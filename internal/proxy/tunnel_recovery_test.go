package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/node"
	M "github.com/sagernet/sing/common/metadata"
)

type tunnelFaultConn struct {
	readData []byte
	readErr  error
	writeErr error
	closed   atomic.Bool
}

func (c *tunnelFaultConn) Read(p []byte) (int, error) {
	if len(c.readData) > 0 {
		n := copy(p, c.readData)
		c.readData = c.readData[n:]
		return n, nil
	}
	return 0, c.readErr
}

func (c *tunnelFaultConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(p), nil
}

func (c *tunnelFaultConn) Close() error                     { c.closed.Store(true); return nil }
func (c *tunnelFaultConn) LocalAddr() net.Addr              { return tunnelFaultAddr("local") }
func (c *tunnelFaultConn) RemoteAddr() net.Addr             { return tunnelFaultAddr("remote") }
func (c *tunnelFaultConn) SetDeadline(time.Time) error      { return nil }
func (c *tunnelFaultConn) SetReadDeadline(time.Time) error  { return nil }
func (c *tunnelFaultConn) SetWriteDeadline(time.Time) error { return nil }

type tunnelFaultAddr string

func (a tunnelFaultAddr) Network() string { return string(a) }
func (a tunnelFaultAddr) String() string  { return string(a) }

func TestPrepareConnectTunnel_RetriesWithDifferentNode(t *testing.T) {
	env := newProxyE2EEnv(t)
	firstRaw := json.RawMessage(`{"type":"stub","server":"127.0.0.1","server_port":1}`)
	firstHash := node.HashFromRawOptions(firstRaw)

	var calls atomic.Int32
	failedNodeCh := make(chan node.Hash, 1)
	upstreamConn, upstreamPeer := net.Pipe()
	defer upstreamPeer.Close()

	dialFor := func(hash node.Hash) func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		return func(context.Context, string, M.Socksaddr) (net.Conn, error) {
			if calls.Add(1) == 1 {
				failedNodeCh <- hash
				return nil, errors.New("dial failed")
			}
			return upstreamConn, nil
		}
	}
	setProxyE2EOutboundDialFunc(t, env, dialFor(firstHash))
	addProxyE2ENode(
		t,
		env,
		json.RawMessage(`{"type":"stub","server":"127.0.0.1","server_port":2}`),
		"203.0.113.11",
		dialFor(node.HashFromRawOptions(json.RawMessage(`{"type":"stub","server":"127.0.0.1","server_port":2}`))),
	)

	result := prepareConnectTunnel(context.Background(), tunnelDeps{
		router:         env.router,
		pool:           env.pool,
		health:         env.pool,
		connectRetries: 1,
	}, "plat", "acct-retry", "example.com:443")
	if result.session == nil {
		t.Fatalf("expected retry to succeed, got error=%v stage=%q", result.upstreamErr, result.upstreamStage)
	}
	defer result.session.upstreamConn.Close()
	if got := calls.Load(); got != 2 {
		t.Fatalf("dial calls: got %d, want 2", got)
	}
	failedNode := <-failedNodeCh
	if result.route.NodeHash == failedNode {
		t.Fatalf("retry reused failed node %s", failedNode.Hex())
	}

	sticky, err := env.router.RouteRequest("plat", "acct-retry", "example.com:443")
	if err != nil {
		t.Fatalf("read sticky route: %v", err)
	}
	if sticky.NodeHash != result.route.NodeHash {
		t.Fatalf("sticky route: got %s, want %s", sticky.NodeHash.Hex(), result.route.NodeHash.Hex())
	}
}

func TestPrepareConnectTunnel_TwoFailuresAreBoundedAndDistinct(t *testing.T) {
	env := newProxyE2EEnv(t)
	firstRaw := json.RawMessage(`{"type":"stub","server":"127.0.0.1","server_port":1}`)
	firstHash := node.HashFromRawOptions(firstRaw)

	var calls atomic.Int32
	calledNodes := make(chan node.Hash, 2)
	dialFor := func(hash node.Hash) func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		return func(context.Context, string, M.Socksaddr) (net.Conn, error) {
			calls.Add(1)
			calledNodes <- hash
			return nil, errors.New("dial failed")
		}
	}
	setProxyE2EOutboundDialFunc(t, env, dialFor(firstHash))
	secondRaw := json.RawMessage(`{"type":"stub","server":"127.0.0.1","server_port":2}`)
	secondHash := node.HashFromRawOptions(secondRaw)
	addProxyE2ENode(t, env, secondRaw, "203.0.113.11", dialFor(secondHash))

	result := prepareConnectTunnel(context.Background(), tunnelDeps{
		router:         env.router,
		pool:           env.pool,
		health:         env.pool,
		connectRetries: 1,
	}, "plat", "acct-bounded", "example.com:443")
	if result.session != nil || result.proxyErr == nil {
		t.Fatalf("expected bounded failure, got session=%v proxyErr=%v", result.session, result.proxyErr)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("dial calls: got %d, want 2", got)
	}
	firstCalled := <-calledNodes
	secondCalled := <-calledNodes
	if firstCalled == secondCalled {
		t.Fatalf("retry reused failed node %s", firstCalled.Hex())
	}
}

func TestPrepareConnectTunnel_ThreeAttemptsExcludeEveryFailedNode(t *testing.T) {
	env := newProxyE2EEnv(t)
	firstRaw := json.RawMessage(`{"type":"stub","server":"127.0.0.1","server_port":1}`)
	firstHash := node.HashFromRawOptions(firstRaw)

	var calls atomic.Int32
	calledNodes := make(chan node.Hash, 3)
	upstreamConn, upstreamPeer := net.Pipe()
	defer upstreamPeer.Close()
	dialFor := func(hash node.Hash) func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		return func(context.Context, string, M.Socksaddr) (net.Conn, error) {
			calledNodes <- hash
			if calls.Add(1) < 3 {
				return nil, errors.New("dial failed")
			}
			return upstreamConn, nil
		}
	}
	setProxyE2EOutboundDialFunc(t, env, dialFor(firstHash))
	secondRaw := json.RawMessage(`{"type":"stub","server":"127.0.0.1","server_port":2}`)
	secondHash := node.HashFromRawOptions(secondRaw)
	addProxyE2ENode(t, env, secondRaw, "203.0.113.11", dialFor(secondHash))
	thirdRaw := json.RawMessage(`{"type":"stub","server":"127.0.0.1","server_port":3}`)
	thirdHash := node.HashFromRawOptions(thirdRaw)
	addProxyE2ENode(t, env, thirdRaw, "203.0.113.12", dialFor(thirdHash))

	result := prepareConnectTunnel(context.Background(), tunnelDeps{
		router:         env.router,
		pool:           env.pool,
		health:         env.pool,
		connectRetries: 2,
	}, "plat", "acct-three-attempts", "example.com:443")
	if result.session == nil {
		t.Fatalf("expected third attempt to succeed, got error=%v stage=%q", result.upstreamErr, result.upstreamStage)
	}
	defer result.session.upstreamConn.Close()
	if got := calls.Load(); got != 3 {
		t.Fatalf("dial calls: got %d, want 3", got)
	}

	seen := make(map[node.Hash]struct{}, 3)
	for i := 0; i < 3; i++ {
		seen[<-calledNodes] = struct{}{}
	}
	if len(seen) != 3 {
		t.Fatalf("attempts reused a failed node: distinct=%d, want 3", len(seen))
	}
}

func TestPrepareConnectTunnel_ContextCanceledDoesNotRetry(t *testing.T) {
	env := newProxyE2EEnv(t)
	var calls atomic.Int32
	dial := func(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
		calls.Add(1)
		return nil, ctx.Err()
	}
	setProxyE2EOutboundDialFunc(t, env, dial)
	addProxyE2ENode(
		t,
		env,
		json.RawMessage(`{"type":"stub","server":"127.0.0.1","server_port":2}`),
		"203.0.113.11",
		dial,
	)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := prepareConnectTunnel(ctx, tunnelDeps{
		router:         env.router,
		pool:           env.pool,
		health:         env.pool,
		connectRetries: 1,
	}, "plat", "acct-cancel", "example.com:443")
	if !result.canceled || result.proxyErr != nil {
		t.Fatalf("expected canceled result, got canceled=%v proxyErr=%v", result.canceled, result.proxyErr)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("dial calls after cancel: got %d, want 1", got)
	}
}

func TestDialTunnelWithTimeout_BoundsBlockingDial(t *testing.T) {
	started := time.Now()
	conn, err := dialTunnelWithTimeout(context.Background(), 30*time.Millisecond, func(ctx context.Context) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if conn != nil {
		t.Fatal("timed-out dial returned a connection")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dial error: got %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("dial timeout took too long: %v", elapsed)
	}
}

func TestShouldInvalidateTunnelLease_UpstreamReadFailed(t *testing.T) {
	// Upstream read error should invalidate even if ingress > 0
	res := tunnelRelayResult{
		ingressBytes:       1024,
		upstreamReadFailed: true,
		upstreamStage:      "connect_upstream_to_client_copy",
		netOK:              false,
	}
	if !shouldInvalidateTunnelLease(res) {
		t.Fatal("expected lease invalidation on upstream read failure with ingress bytes")
	}

	// Downstream client write error (upstreamReadFailed is false) must NOT invalidate
	resClientErr := tunnelRelayResult{
		ingressBytes:       1024,
		upstreamReadFailed: false,
		upstreamStage:      "connect_upstream_to_client_copy",
		netOK:              false,
	}
	if shouldInvalidateTunnelLease(resClientErr) {
		t.Fatal("client write error unexpectedly invalidated lease")
	}

	// NetOK = true must NOT invalidate
	resOK := tunnelRelayResult{
		ingressBytes:       1024,
		upstreamReadFailed: false,
		netOK:              true,
	}
	if shouldInvalidateTunnelLease(resOK) {
		t.Fatal("netOK unexpectedly invalidated lease")
	}
}

func TestPumpPreparedTunnelReader_ObserverClassifiesFailureSide(t *testing.T) {
	t.Run("upstream read failure invalidates after ingress", func(t *testing.T) {
		upstreamErr := errors.New("upstream read reset")
		client := &tunnelFaultConn{readErr: io.EOF}
		upstream := &tunnelFaultConn{readData: []byte("partial"), readErr: upstreamErr}
		result := pumpPreparedTunnelReader(client, client, &preparedTunnel{upstreamConn: upstream, recordResult: func(bool) {}}, tunnelPumpOptions{})
		if !result.upstreamReadFailed || result.ingressBytes != int64(len("partial")) {
			t.Fatalf("result did not capture upstream read failure: %+v", result)
		}
		if !shouldInvalidateTunnelLease(result) {
			t.Fatalf("upstream read failure should invalidate: %+v", result)
		}
	})

	t.Run("downstream write failure does not invalidate after ingress", func(t *testing.T) {
		downstreamErr := errors.New("downstream write reset")
		client := &tunnelFaultConn{readErr: io.EOF, writeErr: downstreamErr}
		upstream := &tunnelFaultConn{readData: []byte("partial"), readErr: io.EOF}
		result := pumpPreparedTunnelReader(client, client, &preparedTunnel{upstreamConn: upstream, recordResult: func(bool) {}}, tunnelPumpOptions{})
		if result.upstreamReadFailed {
			t.Fatalf("downstream write failure was misclassified as upstream read failure: %+v", result)
		}
		if shouldInvalidateTunnelLease(result) {
			t.Fatalf("downstream write failure should not invalidate after ingress: %+v", result)
		}
	})

	t.Run("upstream read failure remains visible with production first byte options", func(t *testing.T) {
		upstreamErr := errors.New("upstream read reset after first byte")
		client := &tunnelFaultConn{readErr: io.EOF}
		upstream := &tunnelFaultConn{readData: []byte("partial"), readErr: upstreamErr}
		var firstByteObserved atomic.Bool
		result := pumpPreparedTunnelReader(
			client,
			client,
			&preparedTunnel{upstreamConn: upstream, recordResult: func(bool) {}},
			tunnelPumpOptions{
				firstByteTimeout: time.Second,
				onFirstIngressByte: func() {
					firstByteObserved.Store(true)
				},
			},
		)
		if !firstByteObserved.Load() {
			t.Fatal("production first-byte callback was not invoked")
		}
		if !result.upstreamReadFailed || result.ingressBytes != int64(len("partial")) {
			t.Fatalf("first-byte wrapper hid upstream read failure: %+v", result)
		}
		if !shouldInvalidateTunnelLease(result) {
			t.Fatalf("upstream read failure should invalidate with production options: %+v", result)
		}
	})
}
