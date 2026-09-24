package routing_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/routing"
)

func guardAccount(lease model.Lease, until time.Time) string {
	return fmt.Sprintf("%s~r1~%s~%d~%d~%s", lease.Account, lease.NodeHash, lease.CreatedAtNs, until.UnixMilli(), base64.RawURLEncoding.EncodeToString([]byte(lease.EgressIP)))
}

func TestGuardedLease_ReusesOnlyTheExistingGeneration(t *testing.T) {
	pool, subMgr := setupPool(t)
	hash := makeRoutableNode(t, pool, subMgr, `{"guard":"original"}`, "198.51.100.1", "cloudflare.com", time.Millisecond)
	makeRoutableNode(t, pool, subMgr, `{"guard":"alternative"}`, "198.51.100.2", "cloudflare.com", time.Millisecond)
	router := makeRouter(pool, nil)
	now := time.Now().UnixNano()
	before := model.Lease{PlatformID: platID, Account: "browser", NodeHash: hash.Hex(), EgressIP: "198.51.100.1", CreatedAtNs: now, LastAccessedNs: now, ExpiryNs: now + int64(time.Hour)}
	if err := router.UpsertLease(before); err != nil {
		t.Fatal(err)
	}
	guard := guardAccount(before, time.Now().Add(10*time.Minute))
	route, err := router.RouteRequest(platName, guard, "cloudflare.com")
	if err != nil || !route.LeaseGuarded || route.LeaseAccount != before.Account || route.LeaseCreated || route.NodeHash != hash || route.LeaseCreatedAtNs != now {
		t.Fatalf("guard did not retain the original lease: %+v %v", route, err)
	}
	if router.ReadLease(model.LeaseKey{PlatformID: platID, Account: guard}) != nil || router.SnapshotIPLoad(platID)[netip.MustParseAddr(before.EgressIP)] != 1 {
		t.Fatal("guard must not allocate a new identity or change IP load")
	}
	var closed atomic.Bool
	unregister, ok := router.RegisterLeaseConnection(route, guard, func() { closed.Store(true) })
	if !ok {
		t.Fatal("guarded connection must register under the real account")
	}
	defer unregister()
	_, count, err := router.RotateLease(platID, before.Account, hash, now, "cloudflare.com", routing.RotateLeaseOptions{})
	if err != nil || count != 1 || !closed.Load() {
		t.Fatalf("administrative recovery must still close the real account's tunnel: count=%d err=%v", count, err)
	}
	if _, err := router.RouteRequest(platName, guard, "cloudflare.com"); !errors.Is(err, routing.ErrLeaseGuard) {
		t.Fatalf("old guard followed a replacement: %v", err)
	}
	if _, ok := router.RegisterLeaseConnection(route, guard, func() {}); ok {
		t.Fatal("late guarded dial registered after rotation")
	}
}

func TestGuardedLease_RejectsUnavailableOrChangedRoutesWithoutAllocation(t *testing.T) {
	for _, reason := range []string{"missing", "expired_lease", "generation", "node", "ip", "circuit", "outbound", "outside_platform", "excluded", "expired_guard", "long_guard", "invalid_guard"} {
		t.Run(reason, func(t *testing.T) {
			pool, subMgr := setupPool(t)
			hash := makeRoutableNode(t, pool, subMgr, `{"guard":"one"}`, "198.51.100.1", "cloudflare.com", time.Millisecond)
			other := makeRoutableNode(t, pool, subMgr, `{"guard":"two"}`, "198.51.100.2", "cloudflare.com", time.Millisecond)
			router := makeRouter(pool, nil)
			now := time.Now().UnixNano()
			lease := model.Lease{PlatformID: platID, Account: "guarded", NodeHash: hash.Hex(), EgressIP: "198.51.100.1", CreatedAtNs: now, LastAccessedNs: now, ExpiryNs: now + int64(time.Hour)}
			guard := guardAccount(lease, time.Now().Add(time.Minute))
			entry, _ := pool.GetEntry(hash)
			var exclude []node.Hash
			switch reason {
			case "expired_lease":
				lease.ExpiryNs = now - 1
			case "generation":
				lease.CreatedAtNs++
			case "node":
				lease.NodeHash = other.Hex()
			case "ip":
				entry.SetEgressIP(netip.MustParseAddr("198.51.100.3"))
			case "circuit":
				entry.CircuitOpenSince.Store(now)
			case "outbound":
				entry.Outbound.Store(nil)
			case "outside_platform":
				plat, _ := pool.GetPlatform(platID)
				plat.NotifyDirty(hash, func(node.Hash) (*node.NodeEntry, bool) { return nil, false }, nil, nil)
			case "excluded":
				exclude = []node.Hash{hash}
			case "expired_guard":
				guard = guardAccount(lease, time.Now().Add(-time.Second))
			case "long_guard":
				guard = guardAccount(lease, time.Now().Add(time.Hour))
			case "invalid_guard":
				guard = "guarded~r1~malformed"
			}
			if reason != "missing" {
				if err := router.UpsertLease(lease); err != nil {
					t.Fatal(err)
				}
			}
			before := router.ReadLease(model.LeaseKey{PlatformID: platID, Account: lease.Account})
			if _, err := router.RouteRequestExcludingNodes(platName, guard, "cloudflare.com", exclude); !errors.Is(err, routing.ErrLeaseGuard) {
				t.Fatalf("guard silently accepted %s: %v", reason, err)
			}
			after := router.ReadLease(model.LeaseKey{PlatformID: platID, Account: lease.Account})
			if (before == nil) != (after == nil) || before != nil && *before != *after {
				t.Fatalf("guard changed the canonical lease: before=%+v after=%+v", before, after)
			}
			if router.ReadLease(model.LeaseKey{PlatformID: platID, Account: guard}) != nil {
				t.Fatal("guard allocated an account on rejection")
			}
		})
	}
}

func TestGuardedLease_RestartAndLateIPChangeFailClosed(t *testing.T) {
	pool, subMgr := setupPool(t)
	hash := makeRoutableNode(t, pool, subMgr, `{"guard":"restore"}`, "198.51.100.1", "cloudflare.com", time.Millisecond)
	now := time.Now().UnixNano()
	lease := model.Lease{PlatformID: platID, Account: "restored", NodeHash: hash.Hex(), EgressIP: "198.51.100.1", CreatedAtNs: now, LastAccessedNs: now, ExpiryNs: now + int64(time.Hour)}
	guard := guardAccount(lease, time.Now().Add(time.Minute))
	router := makeRouter(pool, nil)
	if _, err := router.RouteRequest(platName, guard, "cloudflare.com"); !errors.Is(err, routing.ErrLeaseGuard) {
		t.Fatal("restart without restored lease must not allocate a route")
	}
	router.RestoreLeases([]model.Lease{lease})
	route, err := router.RouteRequest(platName, guard, "cloudflare.com")
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := pool.GetEntry(hash)
	entry.SetEgressIP(netip.MustParseAddr("198.51.100.9"))
	if _, ok := router.RegisterLeaseConnection(route, guard, func() {}); ok {
		t.Fatal("IP drift during dial must reject the connection")
	}
	entry.SetEgressIP(netip.MustParseAddr(lease.EgressIP))
	route.LeaseGuardUntilMs = time.Now().Add(-time.Second).UnixMilli()
	if _, ok := router.RegisterLeaseConnection(route, guard, func() {}); ok {
		t.Fatal("expired guard must reject a late connection")
	}
}

func TestGuardedLease_MalformedIdentityNeverBecomesOrdinaryAccount(t *testing.T) {
	pool, subMgr := setupPool(t)
	makeRoutableNode(t, pool, subMgr, `{"guard":"parse"}`, "198.51.100.1", "cloudflare.com", time.Millisecond)
	router := makeRouter(pool, nil)
	for _, account := range []string{"~r1~", "bad~r1~", strings.Repeat("a", 65) + "~r1~x", "bad~r1~x~1~1~x", "user~r1~" + strings.Repeat("x", 200)} {
		if _, err := router.RouteRequest(platName, account, "cloudflare.com"); !errors.Is(err, routing.ErrLeaseGuard) {
			t.Fatalf("malformed guard allocated a route: %q %v", account, err)
		}
	}
}
