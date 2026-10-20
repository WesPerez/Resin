package state

import (
	"errors"
	"reflect"
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
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	readers.ReadLease = func(LeaseDirtyKey) *model.Lease {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return nil
	}
	w := NewCacheFlushWorker(e, readers, func() int { return 1 },
		func() time.Duration { return time.Hour }, time.Millisecond)
	e.MarkLease("platform", "first")
	w.Start()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("periodic flush did not enter reader")
	}
	e.MarkLease("platform", "last-handler")
	done := make(chan error, 1)
	go func() { done <- w.StopAndFlush() }()
	select {
	case err := <-done:
		t.Fatalf("flush did not join periodic writer: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("authoritative flush did not finish")
	}
	if e.DirtyCount() != 0 {
		t.Fatal("last handler mark was lost")
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
