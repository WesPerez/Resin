package netutil

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/testutil"
	M "github.com/sagernet/sing/common/metadata"
)

type fetchDialOutbound struct {
	testutil.NoopOutbound
	dial func(context.Context) (net.Conn, error)
}

func (o *fetchDialOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	return o.dial(ctx)
}

func TestHTTPGetViaOutbound_CancellationClosesStalledTLSHandshake(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var opened, closed atomic.Int32
	ob := &fetchDialOutbound{dial: func(context.Context) (net.Conn, error) { return client, nil }}
	done := make(chan error, 1)
	go func() {
		_, _, err := HTTPGetViaOutbound(ctx, ob, "https://stall.invalid/", OutboundHTTPOptions{
			OnConnLifecycle: func(op ConnLifecycleOp) {
				if op == ConnLifecycleOpen {
					opened.Add(1)
				} else {
					closed.Add(1)
				}
			},
		})
		done <- err
	}()
	// Accept the ClientHello without responding, reproducing the production
	// sockets that retained a completed SOCKS handshake and no TLS response.
	if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
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
			t.Fatalf("fetch cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fetch did not return after cancellation")
	}
	// The caller returning is insufficient: the detached TLS goroutine and
	// its actual connection must also finish without a peer response.
	if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, peer); err != nil {
		t.Fatalf("abandoned TLS connection was not closed: %v", err)
	}
	if opened.Load() != 1 || closed.Load() != 1 {
		t.Fatalf("connection lifecycle imbalance: open=%d close=%d", opened.Load(), closed.Load())
	}
}

func TestHTTPGetViaOutbound_CancellationStopsPendingDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan context.Context, 1)
	dialDone := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	ob := &fetchDialOutbound{dial: func(dialCtx context.Context) (net.Conn, error) {
		started <- dialCtx
		select {
		case <-dialCtx.Done():
		case <-release:
		}
		close(dialDone)
		return nil, context.Canceled
	}}
	done := make(chan error, 1)
	go func() {
		_, _, err := HTTPGetViaOutbound(ctx, ob, "https://stall.invalid/", OutboundHTTPOptions{})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("dial did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("fetch cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fetch did not return after cancellation")
	}
	select {
	case <-dialDone:
	case <-time.After(3 * time.Second):
		t.Fatal("abandoned outbound dial outlived its fetch")
	}
}

func TestHTTPGetViaOutbound_RequireStatusOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	ob, err := (&testutil.StubOutboundBuilder{}).Build(nil)
	if err != nil {
		t.Fatalf("build outbound: %v", err)
	}
	_, _, err = HTTPGetViaOutbound(context.Background(), ob, srv.URL, OutboundHTTPOptions{
		RequireStatusOK: true,
	})
	if err == nil {
		t.Fatal("expected non-200 status to return error")
	}
	if !strings.Contains(err.Error(), "unexpected status 404") {
		t.Fatalf("expected status error, got: %v", err)
	}
}

func TestHTTPGetViaOutbound_AllowNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("probe-body"))
	}))
	defer srv.Close()

	ob, err := (&testutil.StubOutboundBuilder{}).Build(nil)
	if err != nil {
		t.Fatalf("build outbound: %v", err)
	}
	body, _, err := HTTPGetViaOutbound(context.Background(), ob, srv.URL, OutboundHTTPOptions{
		RequireStatusOK: false,
	})
	if err != nil {
		t.Fatalf("expected non-200 response to pass through, got: %v", err)
	}
	if string(body) != "probe-body" {
		t.Fatalf("unexpected body %q", string(body))
	}
}

func TestConnCloseHook_CloseIsIdempotentAndConcurrentSafe(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	var onCloseCount atomic.Int32
	hook := &connCloseHook{
		Conn: client,
		onClose: func() {
			onCloseCount.Add(1)
		},
	}

	const closers = 32
	var wg sync.WaitGroup
	wg.Add(closers)
	for i := 0; i < closers; i++ {
		go func() {
			defer wg.Done()
			_ = hook.Close()
		}()
	}
	wg.Wait()

	if got := onCloseCount.Load(); got != 1 {
		t.Fatalf("onClose called %d times, want 1", got)
	}
}
