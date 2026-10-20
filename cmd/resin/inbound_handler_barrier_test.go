package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestInboundDemux_ShutdownJoinsHijackedHandlerAfterConnectionClose(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	closeRelease := func() { releaseOnce.Do(func() { close(release) }) }
	errorsCh := make(chan error, 1)
	s := newInboundDemuxServer(&http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			errorsCh <- err
			return
		}
		_ = conn.Close()
		close(entered)
		<-release // Simulate the final lease event after a CONNECT closes.
	})}, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serveDone := make(chan struct{})
	go func() { defer close(serveDone); _ = s.Serve(ln) }()
	t.Cleanup(func() { closeRelease(); _ = s.Shutdown(context.Background(), false); <-serveDone })
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	select {
	case <-entered:
	case err := <-errorsCh:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("handler did not hijack")
	}
	done := make(chan error, 1)
	stopDone := make(chan struct{})
	go func() { defer close(stopDone); done <- s.Shutdown(context.Background(), true) }()
	t.Cleanup(func() { closeRelease(); <-stopDone })
	select {
	case err := <-done:
		t.Fatalf("connection close was mistaken for handler quiescence: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	closeRelease()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("handler was not joined")
	}
}

func TestInboundDemux_HTTPFailureIsArchivedOnceWithoutHidingOuterError(t *testing.T) {
	s := newInboundDemuxServer(nil, nil)
	want := errors.New("inner HTTP serve failed")
	s.mu.Lock()
	s.httpServeErr = want
	s.mu.Unlock()
	if err := s.Shutdown(context.Background(), false); !errors.Is(err, want) {
		t.Fatalf("inner serve error lost: %v", err)
	}
	if err := s.httpServeError(); !errors.Is(err, want) {
		t.Fatalf("shutdown hid error from outer accept owner: %v", err)
	}
	if err := s.Shutdown(context.Background(), false); err != nil {
		t.Fatalf("inner serve failure repeated after archival: %v", err)
	}
}

func TestInboundDemux_ServeCannotReopenAfterShutdown(t *testing.T) {
	s := newInboundDemuxServer(nil, nil)
	if err := s.Shutdown(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := s.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("late Serve reopened the writer: %v", err)
	}
}
