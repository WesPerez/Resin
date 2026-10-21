package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/routing"
	"github.com/Resinat/Resin/internal/state"
)

func maintenanceLeaseFixture(t *testing.T) (*resinApp, model.Lease, []string) {
	t.Helper()
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "state", "state.db"), filepath.Join(dir, "cache", "cache.db")}
	e, closer, err := state.PersistenceBootstrap(filepath.Dir(paths[0]), filepath.Dir(paths[1]))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closer.Close() })
	lease := model.Lease{PlatformID: "11111111-1111-4111-8111-111111111111", Account: "fixture", NodeHash: strings.Repeat("a", 32), EgressIP: "203.0.113.9", CreatedAtNs: 1700000000000000001, ExpiryNs: 1800000000000000002, LastAccessedNs: 1700000000000000003}
	if err := e.UpsertPlatform(model.Platform{ID: lease.PlatformID, Name: "Fixture", StickyTTLNs: int64(time.Hour), ReverseProxyMissAction: "TREAT_AS_EMPTY", AllocationPolicy: "BALANCED"}); err != nil {
		t.Fatal(err)
	}
	if err := e.UpsertSubscription(model.Subscription{ID: "sub", Name: "Sub", URL: "https://fixture.invalid", UpdateIntervalNs: int64(time.Minute), Enabled: true, CreatedAtNs: 1, UpdatedAtNs: 1}); err != nil {
		t.Fatal(err)
	}
	if err := e.BulkUpsertNodesStatic([]model.NodeStatic{{Hash: lease.NodeHash, RawOptions: json.RawMessage(`{"type":"http","server":"127.0.0.1","server_port":1}`), CreatedAtNs: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := e.BulkUpsertSubscriptionNodes([]model.SubscriptionNode{{SubscriptionID: "sub", NodeHash: lease.NodeHash}}); err != nil {
		t.Fatal(err)
	}
	if err := e.BulkUpsertLeases([]model.Lease{lease}); err != nil {
		t.Fatal(err)
	}
	router := routing.NewRouter(routing.RouterConfig{})
	router.RestoreLeases([]model.Lease{lease})
	return &resinApp{engine: e, topoRuntime: &topologyRuntime{router: router}, maintenance: newMaintenanceController(filepath.Dir(paths[0]), "fixture", true)}, lease, paths
}

func TestMaintenanceActualRouterCacheSevenFieldsAndBootstrap(t *testing.T) {
	a, want, paths := maintenanceLeaseFixture(t)
	if err := a.verifyMaintenanceLeases(); err != nil {
		t.Fatal(err)
	}
	if a.maintenance.record.LeaseCount != 1 || len(a.maintenance.record.LeaseDigest) != 64 {
		t.Fatal("missing lease identity")
	}
	changed := want
	changed.LastAccessedNs++
	if err := a.engine.BulkUpsertLeases([]model.Lease{changed}); err != nil {
		t.Fatal(err)
	}
	if err := a.verifyMaintenanceLeases(); err == nil {
		t.Fatal("actual 1ns drift accepted")
	}
	if err := a.engine.BulkUpsertLeases([]model.Lease{want}); err != nil {
		t.Fatal(err)
	}
	e2, c2, err := state.PersistenceBootstrap(filepath.Dir(paths[0]), filepath.Dir(paths[1]))
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	survivors, err := e2.LoadAllLeases()
	if err != nil || !reflect.DeepEqual(survivors, []model.Lease{want}) {
		t.Fatalf("bootstrap pruned valid lease: %v %v", survivors, err)
	}
	a.engine.SealStrongWrites()
	a.engine.SealWeakWrites()
	if err := a.engine.CheckpointDurable(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.engine.MarkLease(want.PlatformID, want.Account)
	if err := a.engine.WeakWriteBarrierError(); err == nil {
		t.Fatal("post-verify late mark certified")
	}
}

func TestMaintenanceReferencesPredictBootstrapPruning(t *testing.T) {
	for _, kind := range []string{"platform", "subscription", "evicted", "static"} {
		t.Run(kind, func(t *testing.T) {
			a, want, paths := maintenanceLeaseFixture(t)
			switch kind {
			case "platform":
				if err := a.engine.DeletePlatform(want.PlatformID); err != nil {
					t.Fatal(err)
				}
			case "subscription":
				if err := a.engine.DeleteSubscription("sub"); err != nil {
					t.Fatal(err)
				}
			case "evicted":
				if err := a.engine.BulkUpsertSubscriptionNodes([]model.SubscriptionNode{{SubscriptionID: "sub", NodeHash: want.NodeHash, Evicted: true}}); err != nil {
					t.Fatal(err)
				}
			case "static":
				if err := a.engine.BulkDeleteNodesStatic([]string{want.NodeHash}); err != nil {
					t.Fatal(err)
				}
			}
			if err := a.verifyMaintenanceLeases(); err == nil {
				t.Fatal("bootstrap-pruned reference accepted")
			}
			before, err := a.engine.LoadAllLeases()
			if err != nil || len(before) != 1 {
				t.Fatal("readonly verifier mutated lease")
			}
			e2, c2, err := state.PersistenceBootstrap(filepath.Dir(paths[0]), filepath.Dir(paths[1]))
			if err != nil {
				t.Fatal(err)
			}
			defer c2.Close()
			survivors, err := e2.LoadAllLeases()
			if err != nil || len(survivors) != 0 {
				t.Fatalf("RepairConsistency disagreement: %v %v", survivors, err)
			}
		})
	}
}
