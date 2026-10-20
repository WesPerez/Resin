package proxy

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/routing"
)

// HealthFeedbackBarrier owns the asynchronous feedback spawned by the proxy.
// Registration happens on the calling handler before a goroutine is launched,
// so draining the handler cannot race ahead of an unregistered writer.
// Call StopAndWait only AFTER all owning handlers have stopped. It does not
// drain connections or background topology workers on behalf of the caller.
type HealthFeedbackBarrier struct {
	target   HealthRecorder
	mu       sync.Mutex
	wg       sync.WaitGroup
	closed   bool
	late     uint64
	waitOnce sync.Once
	done     chan struct{}
}

func NewHealthFeedbackBarrier(target HealthRecorder) *HealthFeedbackBarrier {
	return &HealthFeedbackBarrier{target: target, done: make(chan struct{})}
}

func (b *HealthFeedbackBarrier) begin() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		b.late++
		return false
	}
	if b.target == nil {
		return false
	}
	b.wg.Add(1)
	return true
}

func (b *HealthFeedbackBarrier) dispatch(fn func()) {
	if !b.begin() {
		return
	}
	go func() {
		defer b.wg.Done()
		fn()
	}()
}

func (b *HealthFeedbackBarrier) RecordResult(hash node.Hash, success bool) {
	if !b.begin() {
		return
	}
	defer b.wg.Done()
	b.target.RecordResult(hash, success)
}

func (b *HealthFeedbackBarrier) RecordLatency(hash node.Hash, rawTarget string, latency *time.Duration) {
	if !b.begin() {
		return
	}
	defer b.wg.Done()
	b.target.RecordLatency(hash, rawTarget, latency)
}

func (b *HealthFeedbackBarrier) passiveResult(route routing.RouteResult, success bool) {
	if recorder, ok := b.target.(passiveHealthRecorder); ok {
		recorder.RecordPassiveResult(route.PlatformID, route.NodeHash, success)
	} else {
		b.target.RecordResult(route.NodeHash, success)
	}
}

func (b *HealthFeedbackBarrier) recordPassiveResultAsync(route routing.RouteResult, success bool) {
	b.dispatch(func() { b.passiveResult(route, success) })
}

func (b *HealthFeedbackBarrier) recordLatencyAsync(hash node.Hash, rawTarget string, latency *time.Duration) {
	// The original pointer may belong to a handler stack. Own its value for
	// the asynchronous callback instead of relying on the caller's lifetime.
	if latency != nil {
		value := *latency
		latency = &value
	}
	b.dispatch(func() { b.target.RecordLatency(hash, rawTarget, latency) })
}

// StopAndWait seals registration and joins every accepted callback. A late
// call is rejected rather than writing after the final state transaction and
// is reported as an error, never evidence of a successful source drain.
func (b *HealthFeedbackBarrier) StopAndWait(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	b.waitOnce.Do(func() {
		go func() { b.wg.Wait(); close(b.done) }()
	})
	select {
	case <-b.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.late != 0 {
		return fmt.Errorf("proxy: %d health feedback calls arrived after the barrier closed", b.late)
	}
	return nil
}
