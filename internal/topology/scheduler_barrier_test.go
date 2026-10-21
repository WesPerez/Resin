package topology

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/subscription"
)

func TestSchedulerAsyncUpdateRegistrationPrecedesDispatchAndStopJoins(t *testing.T) {
	mgr := NewSubscriptionManager()
	pool := NewGlobalNodePool(PoolConfig{SubLookup: mgr.Lookup})
	sub := subscription.NewSubscription("sub", "Sub", "http://fixture", true, false)
	mgr.Register(sub)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	var calls atomic.Int32
	s := NewSubscriptionScheduler(SchedulerConfig{SubManager: mgr, Pool: pool,
		Fetcher: func(string) ([]byte, error) {
			calls.Add(1)
			close(entered)
			<-release
			return nil, errors.New("fixture")
		}})
	unlock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(func() { unlock(); s.Stop() })
	if err := s.UpdateSubscriptionAsync(sub); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("admitted update did not start")
	}
	go func() { s.Stop(); close(done) }()
	select {
	case <-done:
		t.Fatal("Stop forgot an admitted API update")
	case <-time.After(20 * time.Millisecond):
	}
	unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop did not join completed update")
	}
	if err := s.BarrierError(); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSubscriptionAsync(sub); err == nil {
		t.Fatal("post-stop async accepted")
	}
	s.SetSubscriptionEnabled(sub, false)
	s.RenameSubscription(sub, "late")
	if !sub.Enabled() || sub.Name() != "Sub" {
		t.Fatal("late scheduler mutation applied")
	}
	if err := s.BarrierError(); err == nil {
		t.Fatal("late scheduler event certified")
	}
	s.UpdateSubscription(sub)
	s.ForceRefreshAllAsync()
	s.Start()
	if calls.Load() != 1 {
		t.Fatal("post-stop update admitted")
	}
	s.Stop() // idempotent; no Add/Wait race or closed-channel panic.
}
