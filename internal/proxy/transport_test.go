package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
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
			transport := newOutboundTransportPool().Get(node.Hash{1}, ob, nil)
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

func (n *noopOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("not used in transport-pool tests")
}

func (n *noopOutbound) Tag() string  { return "noop" }
func (n *noopOutbound) Type() string { return "noop" }

func TestOutboundTransportPool_ReusesByNodeHash(t *testing.T) {
	pool := newOutboundTransportPool()
	hash := node.Hash{1}

	t1 := pool.Get(hash, &noopOutbound{}, nil)
	t2 := pool.Get(hash, &noopOutbound{}, nil)

	if t1 != t2 {
		t.Fatal("expected same transport instance for identical node hash")
	}
}

func TestOutboundTransportPool_SplitsByNodeHash(t *testing.T) {
	pool := newOutboundTransportPool()
	ob := &noopOutbound{}
	hash1 := node.Hash{1}
	hash2 := node.Hash{2}

	base := pool.Get(hash1, ob, nil)
	byNodeHash := pool.Get(hash2, ob, nil)
	if base == byNodeHash {
		t.Fatal("expected different transport for different node hash")
	}
}

func TestOutboundTransportPool_UsesKeepAliveTransport(t *testing.T) {
	pool := newOutboundTransportPool()
	ob := &noopOutbound{}
	hash := node.Hash{1}

	transport := pool.Get(hash, ob, nil)
	if transport.DisableKeepAlives {
		t.Fatal("expected keep-alive enabled transport")
	}
}

func TestOutboundTransportPool_EvictRemovesNodeTransport(t *testing.T) {
	pool := newOutboundTransportPool()
	hash := node.Hash{1}
	ob := &noopOutbound{}

	t1 := pool.Get(hash, ob, nil)
	pool.Evict(hash)
	t2 := pool.Get(hash, ob, nil)

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

	transport := pool.Get(hash, ob, nil)
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
	t1 := pool.Get(hashA, ob, nil)
	_ = pool.Get(hashB, ob, nil)

	pool.CloseAll()

	t2 := pool.Get(hashA, ob, nil)
	if t1 == t2 {
		t.Fatal("expected a new transport after CloseAll")
	}
}
