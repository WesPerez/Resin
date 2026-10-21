package state

import (
	"context"
	"errors"
	"reflect"
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
	sub := model.Subscription{ID: "s", Name: "Sub", URL: "https://fixture.invalid"}
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
