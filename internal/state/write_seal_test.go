package state

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/config"
	"github.com/Resinat/Resin/internal/model"
)

func TestStrongSealRejectsConfigLabelAndEndpointMutations(t *testing.T) {
	e, _, _ := newTestEngine(t)
	e.SealStrongWrites()
	for name, write := range map[string]func() error{
		"config":   func() error { return e.SaveSystemConfig(config.NewDefaultRuntimeConfig(), 1, 1) },
		"label":    func() error { return e.SetLeaseDisplayName("platform", "account", "name") },
		"endpoint": func() error { return e.DeleteEndpoint("endpoint") },
		"labelCAS": func() error {
			_, err := e.SetLeaseDisplayNameIfEmpty(context.Background(), "platform", "account", "name")
			return err
		},
	} {
		if err := write(); !errors.Is(err, ErrWritesSealed) {
			t.Fatalf("%s sealed write = %v", name, err)
		}
	}
	if err := e.StrongWriteBarrierError(); err == nil {
		t.Fatal("late attempted strong mutation was incorrectly certified")
	}
}

func TestMaintenanceFlushRetainsDirtyOnFailureAndRetry(t *testing.T) {
	e, _, _ := newTestEngine(t)
	want := model.Lease{PlatformID: "platform", Account: "account", NodeHash: "node",
		EgressIP: "203.0.113.9", CreatedAtNs: 1700000000000000001,
		ExpiryNs: 1800000000000000002, LastAccessedNs: 1700000000000000003}
	readers := emptyBarrierReaders()
	readers.ReadLease = func(LeaseDirtyKey) *model.Lease { return &want }
	w := NewCacheFlushWorker(e, readers, func() int { return 1000 }, func() time.Duration { return time.Hour }, time.Hour)
	e.MarkLease(want.PlatformID, want.Account)
	e.SealStrongWrites()
	e.SealWeakWrites()
	if _, err := e.CacheRepo.db.Exec("DROP TABLE leases"); err != nil {
		t.Fatal(err)
	}
	if err := w.StopAndFlush(); err == nil || e.DirtyCount() != 1 {
		t.Fatalf("failed flush certified or lost dirty work: err=%v dirty=%d", err, e.DirtyCount())
	}
	if _, err := e.CacheRepo.db.Exec(`CREATE TABLE leases (
		platform_id TEXT, account TEXT, node_hash TEXT, egress_ip TEXT,
		created_at_ns INTEGER, expiry_ns INTEGER, last_accessed_ns INTEGER,
		PRIMARY KEY(platform_id, account))`); err != nil {
		t.Fatal(err)
	}
	if err := w.StopAndFlush(); err != nil {
		t.Fatal(err)
	}
	if err := e.CheckpointDurable(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := e.LoadAllLeases()
	if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Fatalf("seven-field retry mismatch: %v %v", got, err)
	}
}

func TestLateMarkIsRetainedButCannotCertifyHandoff(t *testing.T) {
	e, _, _ := newTestEngine(t)
	e.SealStrongWrites()
	e.SealWeakWrites()
	e.MarkLease("platform", "late-timer")
	if e.DirtyCount() != 1 || e.WeakWriteBarrierError() == nil {
		t.Fatal("late mark lost or boundary certified")
	}
	if err := e.CheckpointDurable(context.Background()); err == nil {
		t.Fatal("late source obtained durable handoff")
	}
}

func TestCheckpointFailureOrDeadlineNeverCertifies(t *testing.T) {
	for _, closed := range []bool{false, true} {
		e, _, _ := newTestEngine(t)
		e.SealStrongWrites()
		e.SealWeakWrites()
		ctx, cancel := context.WithCancel(context.Background())
		if closed {
			if err := e.StateRepo.db.Close(); err != nil {
				t.Fatal(err)
			}
		} else {
			cancel()
		}
		if err := e.CheckpointDurable(ctx); err == nil {
			t.Fatal("failed/cancelled checkpoint accepted")
		}
		cancel()
	}
}

func TestEveryStrongMutationIsSealed(t *testing.T) {
	r := newTestStateRepo(t)
	p := model.Platform{ID: "p", Name: "Fixture", ReverseProxyMissAction: "TREAT_AS_EMPTY", AllocationPolicy: "BALANCED"}
	sub := model.Subscription{ID: "s", Name: "Sub", URL: "https://fixture.invalid", UpdateIntervalNs: int64(time.Minute)}
	ep := model.Endpoint{ID: "ep", Port: 1234}
	rule := model.AccountHeaderRule{URLPrefix: "https://fixture.invalid", Headers: []string{"X-Account"}}
	r.SealStrongWrites()
	for name, write := range map[string]func() error{
		"config":              func() error { return r.SaveSystemConfig(config.NewDefaultRuntimeConfig(), 1, 1) },
		"platform_upsert":     func() error { return r.UpsertPlatform(p) },
		"platform_delete":     func() error { return r.DeletePlatform("p") },
		"subscription_upsert": func() error { return r.UpsertSubscription(sub) },
		"subscription_delete": func() error { return r.DeleteSubscription("s") },
		"endpoint_insert":     func() error { return r.InsertEndpoint(ep) },
		"endpoint_update":     func() error { return r.UpdateEndpoint(ep) },
		"endpoint_delete":     func() error { return r.DeleteEndpoint("ep") },
		"header_ensure":       func() error { _, err := r.EnsureAccountHeaderRule(rule); return err },
		"header_upsert":       func() error { _, err := r.UpsertAccountHeaderRuleWithCreated(rule); return err },
		"header_delete":       func() error { return r.DeleteAccountHeaderRule(rule.URLPrefix) },
		"label":               func() error { return r.SetLeaseDisplayName("p", "a", "name") },
		"label_delete":        func() error { return r.SetLeaseDisplayName("p", "a", "") },
		"label_cas": func() error {
			_, err := r.SetLeaseDisplayNameIfEmpty(context.Background(), "p", "a", "name")
			return err
		},
	} {
		if err := write(); !errors.Is(err, ErrWritesSealed) {
			t.Fatalf("%s write escaped seal: %v", name, err)
		}
	}
	if err := r.StrongWriteBarrierError(); err == nil {
		t.Fatal("late write attempts certified")
	}
}

func TestBarrierReadsDoNotWaitForOwnedWriter(t *testing.T) {
	e, _, _ := newTestEngine(t)
	e.StateRepo.mu.Lock()
	if err := e.StrongWriteBarrierError(); err == nil {
		t.Fatal("owned strong writer certified")
	}
	e.StateRepo.mu.Unlock()
	e.mutationMu.Lock()
	if err := e.WeakWriteBarrierError(); err == nil {
		t.Fatal("owned weak writer certified")
	}
	e.mutationMu.Unlock()
}

func TestFinalCertificateSerializedAndLateCallsInvalidate(t *testing.T) {
	for _, strong := range []bool{false, true} {
		e, _, _ := newTestEngine(t)
		e.SealStrongWrites()
		e.SealWeakWrites()
		entered, release, writeDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var certified, invalidated atomic.Bool
		result := make(chan error, 1)
		go func() {
			result <- e.FinalizeMaintenance(context.Background(), func() error {
				close(entered)
				<-release
				certified.Store(true)
				return nil
			}, func() { invalidated.Store(true) })
		}()
		<-entered
		go func() {
			if strong {
				_ = e.SetLeaseDisplayName("p", "a", "late")
			} else {
				e.MarkLease("p", "a")
			}
			close(writeDone)
		}()
		deadline := time.Now().Add(time.Second)
		for (strong && e.writeEntries.Load() == 0) || (!strong && e.markEntries.Load() == 0) {
			if time.Now().After(deadline) {
				t.Fatal("late entry did not register")
			}
			time.Sleep(time.Millisecond)
		}
		select {
		case <-writeDone:
			t.Fatal("write passed held final gate")
		default:
		}
		close(release)
		if err := <-result; err == nil {
			t.Fatal("overlapping late entry produced successful finalization")
		}
		<-writeDone
		if !certified.Load() || !invalidated.Load() {
			t.Fatal("late call did not invalidate certificate")
		}
		if !strong && e.DirtyCount() != 1 {
			t.Fatal("late dirty work disappeared")
		}
	}
}

func TestFinalCertificateRejectsLateOrExpiredAck(t *testing.T) {
	e, _, _ := newTestEngine(t)
	e.SealStrongWrites()
	e.SealWeakWrites()
	e.MarkLease("p", "late")
	called := false
	if err := e.FinalizeMaintenance(context.Background(), func() error { called = true; return nil }, func() {}); err == nil || called {
		t.Fatal("late source certified")
	}
	e, _, _ = newTestEngine(t)
	e.SealStrongWrites()
	e.SealWeakWrites()
	ctx, cancel := context.WithCancel(context.Background())
	invalidated := false
	if err := e.FinalizeMaintenance(ctx, func() error { cancel(); return nil }, func() { invalidated = true }); !errors.Is(err, context.Canceled) || !invalidated {
		t.Fatal("expired ack certified")
	}
}
