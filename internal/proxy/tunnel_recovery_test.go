package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/node"
	M "github.com/sagernet/sing/common/metadata"
)

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
