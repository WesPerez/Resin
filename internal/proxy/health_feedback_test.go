package proxy

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/routing"
)

type blockedFeedback struct {
	entered     chan string
	release     chan struct{}
	releaseOnce sync.Once
	mu          sync.Mutex
	results     []string
}

func (f *blockedFeedback) closeRelease() { f.releaseOnce.Do(func() { close(f.release) }) }

func cleanupFeedback(t *testing.T, b *HealthFeedbackBarrier, f *blockedFeedback) {
	t.Helper()
	t.Cleanup(func() {
		f.closeRelease()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = b.StopAndWait(ctx)
	})
}

func (f *blockedFeedback) record(kind string) {
	f.entered <- kind
	<-f.release
	f.mu.Lock()
	f.results = append(f.results, kind)
	f.mu.Unlock()
}
func (f *blockedFeedback) RecordResult(node.Hash, bool) { f.record("result") }
func (f *blockedFeedback) RecordLatency(node.Hash, string, *time.Duration) {
	f.record("latency")
}
func (f *blockedFeedback) RecordPassiveResult(platformID string, _ node.Hash, _ bool) {
	f.record("passive:" + platformID)
}

func TestHealthFeedbackBarrier_JoinsResultAndLatencyBeforeReturn(t *testing.T) {
	f := &blockedFeedback{entered: make(chan string, 2), release: make(chan struct{})}
	b := NewHealthFeedbackBarrier(f)
	cleanupFeedback(t, b, f)
	recordPassiveResultAsync(b, routing.RouteResult{PlatformID: "platform"}, true)
	recordLatencyAsync(b, node.Hash{}, "example.com", nil)
	for i := 0; i < 2; i++ {
		select {
		case <-f.entered:
		case <-time.After(time.Second):
			t.Fatal("accepted callback did not start")
		}
	}
	done := make(chan error, 1)
	go func() { done <- b.StopAndWait(context.Background()) }()
	select {
	case err := <-done:
		t.Fatalf("barrier returned before callback completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	f.closeRelease()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("barrier failed to join callbacks")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.results) != 2 {
		t.Fatalf("lost feedback: %v", f.results)
	}
}

func TestHealthFeedbackBarrier_RejectsLateWritesAndReportsFailure(t *testing.T) {
	f := &blockedFeedback{entered: make(chan string, 4), release: make(chan struct{})}
	b := NewHealthFeedbackBarrier(f)
	cleanupFeedback(t, b, f)
	if err := b.StopAndWait(context.Background()); err != nil {
		t.Fatal(err)
	}
	recordPassiveResultAsync(b, routing.RouteResult{}, false)
	recordLatencyAsync(b, node.Hash{}, "example.com", nil)
	b.RecordResult(node.Hash{}, true)
	b.RecordLatency(node.Hash{}, "example.com", nil)
	if err := b.StopAndWait(context.Background()); err == nil {
		t.Fatal("late writers must invalidate the drain")
	}
	select {
	case <-f.entered:
		t.Fatal("late callback wrote after the barrier closed")
	default:
	}
}

func TestHealthFeedbackBarrier_ConcurrentRegistrationAndStop(t *testing.T) {
	f := &blockedFeedback{entered: make(chan string, 128), release: make(chan struct{})}
	f.closeRelease()
	b := NewHealthFeedbackBarrier(f)
	cleanupFeedback(t, b, f)
	var callers sync.WaitGroup
	for i := 0; i < 100; i++ {
		callers.Add(1)
		go func() {
			defer callers.Done()
			recordPassiveResultAsync(b, routing.RouteResult{}, true)
		}()
	}
	_ = b.StopAndWait(context.Background())
	callers.Wait()
	_ = b.StopAndWait(context.Background())
	// Every accepted call is joined, rejected calls are accounted for. In
	// particular no Add occurs after Wait without holding the registration lock.
	b.mu.Lock()
	late := b.late
	b.mu.Unlock()
	f.mu.Lock()
	accepted := len(f.results)
	f.mu.Unlock()
	if uint64(accepted)+late != 100 {
		t.Fatalf("lost registrations: accepted=%d late=%d", accepted, late)
	}
}

func TestHealthFeedbackBarrier_DeadlineDoesNotForgetPendingWriter(t *testing.T) {
	f := &blockedFeedback{entered: make(chan string, 1), release: make(chan struct{})}
	b := NewHealthFeedbackBarrier(f)
	cleanupFeedback(t, b, f)
	recordPassiveResultAsync(b, routing.RouteResult{}, true)
	select {
	case <-f.entered:
	case <-time.After(time.Second):
		t.Fatal("feedback did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := b.StopAndWait(ctx); err != context.DeadlineExceeded {
		t.Fatalf("blocked feedback did not fail deadline: %v", err)
	}
	f.closeRelease()
	if err := b.StopAndWait(context.Background()); err != nil {
		t.Fatalf("pending writer could not later be joined: %v", err)
	}
}
