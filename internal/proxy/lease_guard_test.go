package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/routing"
	M "github.com/sagernet/sing/common/metadata"
)

func proxyGuardAccount(account string, route routing.RouteResult) string {
	return fmt.Sprintf("%s~r1~%s~%d~%d~%s", account, route.NodeHash.Hex(), route.LeaseCreatedAtNs, time.Now().Add(time.Minute).UnixMilli(), base64.RawURLEncoding.EncodeToString([]byte(route.EgressIP.String())))
}

func TestPrepareConnectTunnel_GuardedFailureRetainsLeaseWithoutRetry(t *testing.T) {
	env := newProxyE2EEnv(t)
	var calls atomic.Int32
	dial := func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("synthetic subresource failure")
	}
	setProxyE2EOutboundDialFunc(t, env, dial)
	addProxyE2ENode(t, env, json.RawMessage(`{"type":"stub","server":"127.0.0.1","server_port":2}`), "203.0.113.11", dial)
	before, err := env.router.RouteRequest("plat", "browser", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	guard := proxyGuardAccount("browser", before)
	result := prepareConnectTunnel(context.Background(), tunnelDeps{router: env.router, pool: env.pool, connectRetries: 2}, "plat", guard, "example.com:443")
	if result.session != nil || result.proxyErr == nil || calls.Load() != 1 || !result.route.LeaseGuarded {
		t.Fatalf("guard retried or accepted a failed dial: calls=%d result=%+v", calls.Load(), result)
	}
	if invalidateTunnelLease(env.router, result.route, guard) {
		t.Fatal("guarded relay failure invalidated the account lease")
	}
	after := env.router.ReadLease(model.LeaseKey{PlatformID: before.PlatformID, Account: "browser"})
	if after == nil || after.NodeHash != before.NodeHash.Hex() || after.CreatedAtNs != before.LeaseCreatedAtNs {
		t.Fatalf("subresource failure changed the account lease: %+v", after)
	}
	if _, err := env.router.RouteRequest("plat", guard, "example.com:443"); err != nil {
		t.Fatalf("next resource cannot reuse the unchanged lease: %v", err)
	}
	// The default path retains its original recovery semantics.
	if !invalidateTunnelLease(env.router, before, "browser") {
		t.Fatal("ordinary recovery was changed")
	}
}

func TestPrepareConnectTunnel_GuardCannotUseDirectBypass(t *testing.T) {
	env := newProxyE2EEnv(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	result := prepareConnectTunnel(context.Background(), tunnelDeps{router: env.router, pool: env.pool, bypass: NewTargetBypassMatcher([]string{"127.0.0.1"})}, "plat", "browser~r1~invalid", ln.Addr().String())
	if result.session != nil || result.proxyErr != ErrLeaseGuard {
		if result.session != nil {
			result.session.upstreamConn.Close()
		}
		t.Fatalf("guard fell through to direct bypass: %+v", result)
	}
}

func TestForwardProxy_GuardRejectionLogsTheOriginalAccount(t *testing.T) {
	env := newProxyE2EEnv(t)
	emitter := newMockEventEmitter()
	var requests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	fp := NewForwardProxy(ForwardProxyConfig{ProxyToken: "tok", Router: env.router, Pool: env.pool, Events: emitter, ProxyBypassRules: []string{"127.*"}})
	req := httptest.NewRequest(http.MethodGet, upstream.URL, nil)
	req.Header.Set("Proxy-Authorization", basicAuth("plat.browser~r1~invalid", "tok"))
	response := httptest.NewRecorder()
	fp.ServeHTTP(response, req)
	if response.Code != http.StatusConflict || response.Header().Get("X-Resin-Error") != "LEASE_GUARD_FAILED" || requests.Load() != 0 {
		t.Fatalf("guard rejection bypassed routing: status=%d requests=%d", response.Code, requests.Load())
	}
	select {
	case event := <-emitter.logCh:
		if event.Account != "browser" {
			t.Fatalf("failed guard logged a transient identity: %q", event.Account)
		}
	case <-time.After(time.Second):
		t.Fatal("missing rejected request log")
	}
}
