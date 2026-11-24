package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/testutil"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

func TestHTTPTransports_CanceledRequestCannotLeaveTLSHandshakeForever(t *testing.T) {
	for _, direct := range []bool{false, true} {
		name := "outbound"
		if direct {
			name = "direct"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ob, err := (&testutil.StubOutboundBuilder{}).Build(nil)
			if err != nil {
				t.Fatal(err)
			}
			transport := mustGetTransport(t, newOutboundTransportPool(), node.Hash{1}, ob, nil)
			if direct {
				transport = newDirectHTTPTransport(OutboundTransportConfig{}, nil)
			}
			defer transport.CloseIdleConnections()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+listener.Addr().String(), nil)
				if err == nil {
					var resp *http.Response
					resp, err = (&http.Client{Transport: transport}).Do(req)
					if resp != nil {
						resp.Body.Close()
					}
				}
				done <- err
			}()
			if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			peer, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			if err := peer.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var firstByte [1]byte
			if _, err := io.ReadFull(peer, firstByte[:]); err != nil {
				t.Fatalf("read ClientHello: %v", err)
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("request cancellation: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("request did not return after cancellation")
			}
			// Keep the shared pool alive: only its setup deadline may release the
			// abandoned handshake; idle eviction must not be needed to do so.
			if _, err := io.Copy(io.Discard, peer); err != nil {
				t.Fatalf("detached TLS handshake exceeded its setup budget: %v", err)
			}
		})
	}
}

type noopOutbound struct {
	adapter.Outbound
}

type versionedTestOutbound struct {
	noopOutbound
	version atomic.Uint64
}

func (n *versionedTestOutbound) RoutingVersion() uint64 { return n.version.Load() }

func TestTransportPoolChangesWithOutboundMode(t *testing.T) {
	pool := newOutboundTransportPool()
	ob := new(versionedTestOutbound)
	ob.version.Store(1)
	hash := node.Hash{7}
	first := mustGetTransport(t, pool, hash, ob, nil)
	ob.version.Store(2)
	second := mustGetTransport(t, pool, hash, ob, nil)
	if first == second {
		t.Fatal("new mode reused old HTTP connections")
	}
	if mustGetTransport(t, pool, hash, ob, nil) != second {
		t.Fatal("same mode did not reuse its transport")
	}
	stale := new(versionedTestOutbound)
	stale.version.Store(1)
	if transport, err := pool.Get(hash, stale, nil); transport != nil || err != ErrNoAvailableNodes {
		t.Fatalf("stale version reused another mode: %v %v", transport, err)
	}
	if mustGetTransport(t, pool, hash, ob, nil) != second {
		t.Fatal("stale caller rolled the pool back")
	}

}

func (n *noopOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("not used in transport-pool tests")
}

func (n *noopOutbound) Tag() string  { return "noop" }
func (n *noopOutbound) Type() string { return "noop" }

func TestOutboundDialPreservesContextWithoutOuterHTTPTrace(t *testing.T) {
	type contextKey struct{}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), contextKey{}, "preserved"), time.Second)
	defer cancel()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GetConn: func(string) {}})
	var dialContext context.Context
	ob := &mockOutbound{dialFunc: func(inner context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
		dialContext = inner
		if httptrace.ContextClientTrace(inner) != nil {
			t.Error("outer HTTP trace leaked into protocol dial")
		}
		if inner.Value(contextKey{}) != "preserved" || inner.Done() == nil {
			t.Error("protocol dial lost request context data or cancellation")
		}
		deadline, ok := inner.Deadline()
		want, _ := ctx.Deadline()
		if !ok || !deadline.Equal(want) {
			t.Error("protocol dial lost deadline")
		}
		// The setup timeout creates a child cancellation channel. Check that
		// parent cancellation propagates, rather than requiring channel identity.
		cancel()
		if inner.Err() != context.Canceled {
			t.Error("protocol dial did not follow parent cancellation")
		}
		return nil, errors.New("dial failed")
	}}
	transport := newOutboundTransportPool().newReusableOutboundTransport(ob, nil)
	_, _ = transport.DialContext(ctx, "tcp", "example.com:443")
	cancel()
	if dialContext == nil || dialContext.Err() != context.Canceled {
		t.Fatal("dial context did not follow cancellation")
	}
	if httptrace.ContextClientTrace(ctx) == nil {
		t.Fatal("protocol dial modified the original request trace")
	}
}

func TestOutboundTransportPool_ReusesByNodeHash(t *testing.T) {
	pool := newOutboundTransportPool()
	hash := node.Hash{1}

	t1 := mustGetTransport(t, pool, hash, &noopOutbound{}, nil)
	t2 := mustGetTransport(t, pool, hash, &noopOutbound{}, nil)

	if t1 != t2 {
		t.Fatal("expected same transport instance for identical node hash")
	}
}

func TestOutboundTransportPool_SplitsByNodeHash(t *testing.T) {
	pool := newOutboundTransportPool()
	ob := &noopOutbound{}
	hash1 := node.Hash{1}
	hash2 := node.Hash{2}

	base := mustGetTransport(t, pool, hash1, ob, nil)
	byNodeHash := mustGetTransport(t, pool, hash2, ob, nil)
	if base == byNodeHash {
		t.Fatal("expected different transport for different node hash")
	}
}

func TestOutboundTransportPool_UsesKeepAliveTransport(t *testing.T) {
	pool := newOutboundTransportPool()
	ob := &noopOutbound{}
	hash := node.Hash{1}

	transport := mustGetTransport(t, pool, hash, ob, nil)
	if transport.DisableKeepAlives {
		t.Fatal("expected keep-alive enabled transport")
	}
}

func TestOutboundTransportPool_EvictRemovesNodeTransport(t *testing.T) {
	pool := newOutboundTransportPool()
	hash := node.Hash{1}
	ob := &noopOutbound{}

	t1 := mustGetTransport(t, pool, hash, ob, nil)
	pool.Evict(hash)
	t2 := mustGetTransport(t, pool, hash, ob, nil)

	if t1 == t2 {
		t.Fatal("expected a new transport after evict")
	}
}

func TestOutboundTransportPool_AppliesConfiguredLimits(t *testing.T) {
	pool := newOutboundTransportPoolWithConfig(OutboundTransportConfig{
		MaxIdleConns:        9,
		MaxIdleConnsPerHost: 3,
		IdleConnTimeout:     12 * time.Second,
	})
	ob := &noopOutbound{}
	hash := node.Hash{1}

	transport := mustGetTransport(t, pool, hash, ob, nil)
	if transport.MaxIdleConns != 9 {
		t.Fatalf("MaxIdleConns: got %d, want %d", transport.MaxIdleConns, 9)
	}
	if transport.MaxIdleConnsPerHost != 3 {
		t.Fatalf("MaxIdleConnsPerHost: got %d, want %d", transport.MaxIdleConnsPerHost, 3)
	}
	if transport.IdleConnTimeout != 12*time.Second {
		t.Fatalf("IdleConnTimeout: got %s, want %s", transport.IdleConnTimeout, 12*time.Second)
	}
}

func TestOutboundTransportPool_CloseAllClearsEntries(t *testing.T) {
	pool := newOutboundTransportPool()
	ob := &noopOutbound{}

	hashA := node.Hash{1}
	hashB := node.Hash{2}
	t1 := mustGetTransport(t, pool, hashA, ob, nil)
	_ = mustGetTransport(t, pool, hashB, ob, nil)

	pool.CloseAll()

	t2 := mustGetTransport(t, pool, hashA, ob, nil)
	if t1 == t2 {
		t.Fatal("expected a new transport after CloseAll")
	}
}

func mustGetTransport(t *testing.T, pool *OutboundTransportPool, hash node.Hash, ob adapter.Outbound, sink MetricsEventSink) *http.Transport {
	t.Helper()
	transport, err := pool.Get(hash, ob, sink)
	if err != nil {
		t.Fatal(err)
	}
	return transport
}

// Pause after Get has read the old cache entry but before it enters Compute,
// ensuring that both cache lookup paths reject newer versions for an old call.
func TestTransportPoolRejectsStaleVersionDuringCacheUpdate(t *testing.T) {
	pool := newOutboundTransportPool()
	defer pool.CloseAll()
	hash := node.Hash{8}
	initial := new(versionedTestOutbound)
	initial.version.Store(0)
	mustGetTransport(t, pool, hash, initial, nil)
	stale := &blockedVersionOutbound{entered: make(chan struct{}), release: make(chan struct{})}
	result := make(chan *ProxyError, 1)
	go func() {
		tr, err := pool.Get(hash, stale, nil)
		if tr != nil {
			result <- nil
			return
		}
		result <- err
	}()
	<-stale.entered
	current := new(versionedTestOutbound)
	current.version.Store(2)
	expected := mustGetTransport(t, pool, hash, current, nil)
	close(stale.release)
	if err := <-result; err != ErrNoAvailableNodes {
		t.Fatalf("stale caller accepted current transport: %v", err)
	}
	if mustGetTransport(t, pool, hash, current, nil) != expected {
		t.Fatal("stale caller replaced the new cache entry")
	}
}

type blockedVersionOutbound struct {
	noopOutbound
	entered, release chan struct{}
}

func (n *blockedVersionOutbound) RoutingVersion() uint64 { close(n.entered); <-n.release; return 1 }
