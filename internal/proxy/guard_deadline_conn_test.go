package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

type noDeadlineConn struct {
	net.Conn
	deadlineCalls atomic.Int32
}

func (c *noDeadlineConn) SetDeadline(time.Time) error {
	c.deadlineCalls.Add(1)
	return errors.New("deadlines unsupported by transport")
}

func TestPrepareConnectTunnel_GuardSupportsTransportWithoutDeadlines(t *testing.T) {
	env := newProxyE2EEnv(t)
	base, peer := net.Pipe()
	defer peer.Close()
	conn := &noDeadlineConn{Conn: base}
	var dials atomic.Int32
	setProxyE2EOutboundDialFunc(t, env, func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		dials.Add(1)
		return conn, nil
	})
	route, err := env.router.RouteRequest("plat", "browser", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	result := prepareConnectTunnel(context.Background(), tunnelDeps{router: env.router, pool: env.pool, connectRetries: 2},
		"plat", proxyGuardAccount("browser", route), "example.com:443")
	if result.proxyErr != nil || result.session == nil || result.session.guard == nil || dials.Load() != 1 {
		t.Fatalf("guarded transport rejected: result=%+v dials=%d", result, dials.Load())
	}
	defer result.session.upstreamConn.Close()
	if conn.deadlineCalls.Load() != 0 {
		t.Fatal("lease lifetime still depends on transport SetDeadline")
	}
	_ = peer.SetDeadline(time.Now().Add(time.Second))
	go func() { _, _ = peer.Write([]byte("ok")) }()
	buffer := make([]byte, 2)
	if _, err := io.ReadFull(result.session.upstreamConn, buffer); err != nil || string(buffer) != "ok" {
		t.Fatalf("guarded transport lost data: %q %v", buffer, err)
	}
}

func TestGuardLifetimeClosesIdleTunnelWithoutPenalizingNode(t *testing.T) {
	client, clientPeer := net.Pipe()
	base, upstreamPeer := net.Pipe()
	defer client.Close()
	defer clientPeer.Close()
	defer upstreamPeer.Close()
	guard := newGuardDeadlineConn(&noDeadlineConn{Conn: base}, time.Now().Add(30*time.Millisecond))
	defer guard.Close()
	done := make(chan tunnelRelayResult, 1)
	go func() {
		done <- pumpPreparedTunnelReader(client, client,
			&preparedTunnel{upstreamConn: guard, guard: guard}, tunnelPumpOptions{requireBidirectionalTraffic: true})
	}()
	select {
	case result := <-done:
		if !result.guardExpired || result.proxyErr != ErrLeaseGuard || result.upstreamStage != "connect_lease_guard_expired" {
			t.Fatalf("expiry lost its cause: %+v", result)
		}
		if _, known := result.passiveHealth(); known || shouldInvalidateTunnelLease(result) {
			t.Fatal("planned expiry penalized or invalidated the node")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lease guard failed to close the idle tunnel")
	}
}

func TestGuardCloseStopsExpiryAndPreservesHalfClose(t *testing.T) {
	base := &stubHalfCloseConn{}
	guard := newGuardDeadlineConn(base, time.Now().Add(time.Hour))
	if err := guard.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := guard.CloseRead(); err != nil {
		t.Fatal(err)
	}
	if base.closeWriteCalls.Load() != 1 || base.closeReadCalls.Load() != 1 || base.closed.Load() {
		t.Fatal("half-close was not forwarded")
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
	// Simulate a timer callback racing with an ordinary close.
	_ = guard.close(true)
	if !base.closed.Load() || guard.expired.Load() || guard.timer.Stop() {
		t.Fatal("ordinary close left an active timer or became an expiry")
	}
}
