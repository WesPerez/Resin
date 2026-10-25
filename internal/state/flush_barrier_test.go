package state

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/model"
)

func emptyBarrierReaders() CacheReaders {
	return CacheReaders{
		ReadNodeStatic:       func(string) *model.NodeStatic { return nil },
		ReadNodeDynamic:      func(string) *model.NodeDynamic { return nil },
		ReadNodeLatency:      func(NodeLatencyDirtyKey) *model.NodeLatency { return nil },
		ReadLease:            func(LeaseDirtyKey) *model.Lease { return nil },
		ReadSubscriptionNode: func(SubscriptionNodeDirtyKey) *model.SubscriptionNode { return nil },
	}
}

func TestStopAndFlush_ReportsClosedDatabaseAndRetainsDirtyWork(t *testing.T) {
	e, _, _ := newTestEngine(t)
	w := NewCacheFlushWorker(e, emptyBarrierReaders(), func() int { return 1000 },
		func() time.Duration { return time.Hour }, time.Hour)
	w.Start()
	t.Cleanup(w.Discard)
	e.MarkLease("platform", "account")
	if err := e.CacheRepo.db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.StopAndFlush(); err == nil {
		t.Fatal("failed final transaction was reported as success")
	}
	if e.DirtyCount() != 1 {
		t.Fatal("failed flush lost dirty work")
	}
}

func TestStopAndFlush_DiscardCanNeverBeOverridden(t *testing.T) {
	e, _, _ := newTestEngine(t)
	w := NewCacheFlushWorker(e, emptyBarrierReaders(), func() int { return 1000 },
		func() time.Duration { return time.Hour }, time.Hour)
	w.Start()
	e.MarkLease("platform", "account")
	w.Discard()
	if err := w.StopAndFlush(); !errors.Is(err, ErrFlushDiscarded) {
		t.Fatalf("discard was overridden: %v", err)
	}
	if e.DirtyCount() != 1 {
		t.Fatal("discarded slot consumed dirty work")
	}
}

func TestStopAndFlush_JoinsPeriodicFlushAndPersistsLateMark(t *testing.T) {
	e, _, _ := newTestEngine(t)
	readers := emptyBarrierReaders()
	want := model.Lease{PlatformID: "platform", Account: "last-handler", NodeHash: "late-node",
		EgressIP: "203.0.113.10", CreatedAtNs: 1700000000000000001,
		ExpiryNs: 1800000000000000002, LastAccessedNs: 1700000000000000003}
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	closeRelease := func() { releaseOnce.Do(func() { close(release) }) }
	readers.ReadLease = func(key LeaseDirtyKey) *model.Lease {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		if key.PlatformID == want.PlatformID && key.Account == want.Account {
			copy := want
			return &copy
		}
		if key.PlatformID != "platform" || key.Account != "first" {
			t.Errorf("unexpected lease key: %+v", key)
		}
		return nil
	}
	w := NewCacheFlushWorker(e, readers, func() int { return 1 },
		func() time.Duration { return time.Hour }, time.Millisecond)
	e.MarkLease("platform", "first")
	w.Start()
	t.Cleanup(func() { closeRelease(); w.Discard() })
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("periodic flush did not enter reader")
	}
	e.MarkLease("platform", "last-handler")
	done := make(chan error, 1)
	stopDone := make(chan struct{})
	go func() { defer close(stopDone); done <- w.StopAndFlush() }()
	t.Cleanup(func() { closeRelease(); <-stopDone })
	select {
	case err := <-done:
		t.Fatalf("flush did not join periodic writer: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	closeRelease()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("authoritative flush did not finish")
	}
	got, err := e.LoadAllLeases()
	if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0], want) || e.DirtyCount() != 0 {
		t.Fatalf("last handler lease was not persisted: got=%v err=%v", got, err)
	}
	// Idempotent stop cannot launch another periodic writer.
	w.Start()
	if err := w.StopAndFlush(); err != nil {
		t.Fatal(err)
	}
}

func TestStopAndFlush_PersistsAllSevenLeaseFields(t *testing.T) {
	e, _, _ := newTestEngine(t)
	want := model.Lease{PlatformID: "platform", Account: "account", NodeHash: "node",
		EgressIP: "203.0.113.9", CreatedAtNs: 1700000000000000001,
		ExpiryNs: 1800000000000000002, LastAccessedNs: 1700000000000000003}
	readers := emptyBarrierReaders()
	readers.ReadLease = func(LeaseDirtyKey) *model.Lease { return &want }
	w := NewCacheFlushWorker(e, readers, func() int { return 1000 },
		func() time.Duration { return time.Hour }, time.Hour)
	w.Start()
	e.MarkLease(want.PlatformID, want.Account)
	if err := w.StopAndFlush(); err != nil {
		t.Fatal(err)
	}
	got, err := e.LoadAllLeases()
	if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Fatalf("seven-field lease changed: got=%v err=%v", got, err)
	}
}

func TestStopAndFlush_RejectsDirtyMarkDuringFinalReader(t *testing.T) {
	e, _, _ := newTestEngine(t)
	readers := emptyBarrierReaders()
	readers.ReadLease = func(LeaseDirtyKey) *model.Lease {
		e.MarkLease("platform", "late")
		return nil
	}
	w := NewCacheFlushWorker(e, readers, func() int { return 1000 },
		func() time.Duration { return time.Hour }, time.Hour)
	// No background worker: the mark is injected into the final transaction.
	e.MarkLease("platform", "first")
	if err := w.StopAndFlush(); err == nil {
		t.Fatal("concurrent final-flush mark was incorrectly certified quiescent")
	}
	if e.DirtyCount() != 1 {
		t.Fatal("late mark was lost")
	}
}
