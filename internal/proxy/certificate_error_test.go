package proxy

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/model"
	M "github.com/sagernet/sing/common/metadata"
)

func TestCertificateFailurePreservesNodeAndAccount(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, certErr := range []error{
			x509.CertificateInvalidError{Cert: &x509.Certificate{}, Reason: x509.Expired},
			x509.UnknownAuthorityError{Cert: &x509.Certificate{}},
			x509.HostnameError{Certificate: &x509.Certificate{}, Host: "example.com"},
		} {
			t.Run(fmt.Sprintf("reverse=%v/%T", reverse, certErr), func(t *testing.T) {
				env := newProxyE2EEnv(t)
				health := &mockPassiveHealthRecorder{done: make(chan struct{}, 1)}
				before, err := env.router.RouteRequest("plat", "cert-test", "example.com:443")
				if err != nil {
					t.Fatal(err)
				}
				setProxyE2EOutboundDialFunc(t, env, func(context.Context, string, M.Socksaddr) (net.Conn, error) {
					return nil, fmt.Errorf("wrapped upstream: %w", certErr)
				})
				var handler http.Handler
				var req *http.Request
				if reverse {
					handler = NewReverseProxy(ReverseProxyConfig{ProxyToken: "tok", Router: env.router, Pool: env.pool, PlatformLookup: env.pool, Health: health})
					req = httptest.NewRequest(http.MethodGet, "http://resin/tok/plat/https/example.com/", nil)
					req.Header.Set("X-Resin-Account", "cert-test")
				} else {
					handler = NewForwardProxy(ForwardProxyConfig{ProxyToken: "tok", Router: env.router, Pool: env.pool, Health: health})
					req = httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
					req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("plat.cert-test:tok")))
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != 502 || rec.Header().Get("X-Resin-Error") != "UPSTREAM_TLS_CERTIFICATE_ERROR" {
					t.Fatalf("certificate failure lost: %d %s", rec.Code, rec.Body.String())
				}
				select {
				case <-health.done:
					t.Fatal("certificate failure penalized a node")
				case <-time.After(20 * time.Millisecond):
				}
				after := env.router.ReadLease(model.LeaseKey{PlatformID: before.PlatformID, Account: "cert-test"})
				if after == nil || after.CreatedAtNs != before.LeaseCreatedAtNs || env.router.RecoveryStatus().Rotated != 0 {
					t.Fatal("certificate failure changed account lease")
				}
			})
		}
	}
}
