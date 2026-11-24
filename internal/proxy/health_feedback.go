package proxy

import (
	"context"
	"fmt"
	"sync"

	"github.com/Resinat/Resin/internal/node"
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

func (b *HealthFeedbackBarrier) ApplyFeedback(hash node.Hash, version uint64, feedback node.Feedback) bool {
	if !b.begin() {
		return false
	}
	defer b.wg.Done()
	return b.target.ApplyFeedback(hash, version, feedback)
}

func (b *HealthFeedbackBarrier) applyFeedbackAsync(hash node.Hash, version uint64, feedback node.Feedback) {
	// Own pointer values before the asynchronous callback outlives its caller.
	if feedback.Result != nil {
		value := *feedback.Result
		feedback.Result = &value
	}
	if feedback.Latency != nil {
		value := *feedback.Latency
		feedback.Latency = &value
	}
	b.dispatch(func() { b.target.ApplyFeedback(hash, version, feedback) })
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
