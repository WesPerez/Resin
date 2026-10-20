package main

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/proxy"
	"github.com/Resinat/Resin/internal/state"
)

type shutdownLeaseFeedback struct {
	engine  *state.StateEngine
	entered chan struct{}
	release chan struct{}
	mu      sync.Mutex
	lease   model.Lease
}

func (f *shutdownLeaseFeedback) RecordResult(node.Hash, bool) {}
func (f *shutdownLeaseFeedback) RecordLatency(_ node.Hash, _ string, _ *time.Duration) {
	close(f.entered)
	<-f.release
	f.engine.MarkLease(f.lease.PlatformID, f.lease.Account)
}

func TestShutdownComponents_LastAsyncEventIsPersistedBeforeDatabaseClose(t *testing.T) {
	e, closer, err := state.PersistenceBootstrap(t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	f := &shutdownLeaseFeedback{engine: e, entered: make(chan struct{}), release: make(chan struct{}),
		lease: model.Lease{PlatformID: "platform", Account: "last-handler", NodeHash: "node",
			EgressIP: "203.0.113.9", CreatedAtNs: 1700000000000000001,
			ExpiryNs: 1800000000000000002, LastAccessedNs: 1700000000000000003}}
	readers := state.CacheReaders{
		ReadLease: func(state.LeaseDirtyKey) *model.Lease {
			f.mu.Lock()
			defer f.mu.Unlock()
			copy := f.lease
			return &copy
		},
	}
	w := state.NewCacheFlushWorker(e, readers, func() int { return 1000 },
		func() time.Duration { return time.Hour }, time.Hour)
	w.Start()
	b := proxy.NewHealthFeedbackBarrier(f)
	go b.RecordLatency(node.Zero, "example.com", nil)
	<-f.entered
	done := make(chan error, 1)
	go func() {
		if err := b.StopAndWait(context.Background()); err != nil {
			done <- err
			return
		}
		done <- w.StopAndFlush()
	}()
	select {
	case err := <-done:
		t.Fatalf("final flush raced ahead of the final feedback event: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(f.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("feedback and final flush did not complete")
	}
	got, err := e.LoadAllLeases()
	if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0], f.lease) || e.DirtyCount() != 0 {
		t.Fatalf("last asynchronous lease event was not persisted: got=%v err=%v", got, err)
	}
}
