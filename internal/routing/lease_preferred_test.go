package routing_test

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/routing"
)

func TestRotateLease_PreferredNodeWithoutParent(t *testing.T) {
	for _, preserve := range []bool{false, true} {
		t.Run(map[bool]string{false: "close", true: "preserve"}[preserve], func(t *testing.T) {
			pool, subMgr := setupPool(t)
			old := makeRoutableNode(t, pool, subMgr, `{"preferred":"old"}`, "198.51.100.1", "cloudflare.com", time.Millisecond)
			makeRoutableNode(t, pool, subMgr, `{"preferred":"random"}`, "198.51.100.2", "cloudflare.com", time.Millisecond)
			preferred := makeRoutableNode(t, pool, subMgr, `{"preferred":"audited"}`, "198.51.100.3", "cloudflare.com", time.Second)
			router := makeRouter(pool, nil)
			now := time.Now().UnixNano()
			before := model.Lease{PlatformID: platID, Account: "audited", NodeHash: old.Hex(), EgressIP: "198.51.100.1",
				CreatedAtNs: now, ExpiryNs: now + int64(time.Hour), LastAccessedNs: now}
			if err := router.UpsertLease(before); err != nil {
				t.Fatal(err)
			}
			route, err := router.RouteRequest(platName, "audited", "cloudflare.com")
			if err != nil {
				t.Fatal(err)
			}
			var closed atomic.Int32
			unregister, ok := router.RegisterLeaseConnection(route, "audited", func() { closed.Add(1) })
			if !ok {
				t.Fatal("register original connection")
			}
			defer unregister()
			after, count, err := router.RotateLease(platID, "audited", old, now, "cloudflare.com", routing.RotateLeaseOptions{
				PreferredNode: preferred, ExpectedTargetIP: netip.MustParseAddr("198.51.100.3"),
				ExcludeEgressIP: true, PreserveConnections: preserve,
			})
			if err != nil || after == nil || after.NodeHash != preferred.Hex() || after.EgressIP != "198.51.100.3" {
				t.Fatalf("preferred node was not used: after=%+v err=%v", after, err)
			}
			wantClosed := 1
			if preserve {
				wantClosed = 0
			}
			if count != wantClosed || closed.Load() != int32(wantClosed) {
				t.Fatalf("connection policy changed: count=%d closed=%d want=%d", count, closed.Load(), wantClosed)
			}
			if after.CreatedAtNs <= now || after.LastAccessedNs != after.CreatedAtNs || after.ExpiryNs-after.CreatedAtNs != int64(time.Hour) {
				t.Fatalf("lease generation/TTL changed: %+v", after)
			}
			loads := router.SnapshotIPLoad(platID)
			if loads[netip.MustParseAddr(before.EgressIP)] != 0 || loads[netip.MustParseAddr(after.EgressIP)] != 1 {
				t.Fatalf("incorrect IP load transfer: %v", loads)
			}
		})
	}
}

func TestRotateLease_InvalidPreferredRetainsLeaseAndConnections(t *testing.T) {
	for _, reason := range []string{"circuit", "outbound", "ip_changed", "outside_platform", "disabled", "missing", "same_node", "same_ip", "missing_ip", "missing_hash", "stale_generation"} {
		t.Run(reason, func(t *testing.T) {
			pool, subMgr := setupPool(t)
			old := makeRoutableNode(t, pool, subMgr, `{"candidate":"old"}`, "198.51.100.1", "cloudflare.com", time.Millisecond)
			candidate := makeRoutableNode(t, pool, subMgr, `{"candidate":"target"}`, "198.51.100.2", "cloudflare.com", time.Millisecond)
			// An ordinary random fallback exists, but a failed explicit candidate
			// must not silently allocate it or close the caller's active tunnel.
			makeRoutableNode(t, pool, subMgr, `{"candidate":"fallback"}`, "198.51.100.3", "cloudflare.com", time.Millisecond)
			router := makeRouter(pool, nil)
			now := time.Now().UnixNano()
			before := model.Lease{PlatformID: platID, Account: "strict", NodeHash: old.Hex(), EgressIP: "198.51.100.1",
				CreatedAtNs: now, ExpiryNs: now + int64(time.Hour), LastAccessedNs: now}
			if err := router.UpsertLease(before); err != nil {
				t.Fatal(err)
			}
			var closed atomic.Bool
			unregister, ok := router.RegisterLeaseConnection(routing.RouteResult{PlatformID: platID, NodeHash: old, LeaseCreatedAtNs: now}, "strict", func() { closed.Store(true) })
			if !ok {
				t.Fatal("register original connection")
			}
			defer unregister()
			options := routing.RotateLeaseOptions{PreferredNode: candidate, ExpectedTargetIP: netip.MustParseAddr("198.51.100.2"), ExcludeEgressIP: true}
			entry, _ := pool.GetEntry(candidate)
			generation := now
			wantErr := routing.ErrNoAvailableNodes
			switch reason {
			case "circuit":
				entry.CircuitOpenSince.Store(now)
			case "outbound":
				entry.Outbound.Store(nil)
			case "ip_changed":
				entry.SetEgressIP(netip.MustParseAddr("198.51.100.4"))
			case "outside_platform":
				plat, _ := pool.GetPlatform(platID)
				plat.NotifyDirty(candidate, func(node.Hash) (*node.NodeEntry, bool) { return nil, false }, nil, nil)
			case "disabled":
				sub, _ := subMgr.Get("sub-1")
				sub.SetEnabled(false)
				pool.NotifyNodeDirty(candidate)
			case "missing":
				options.PreferredNode = node.HashFromRawOptions([]byte(`{"candidate":"absent"}`))
			case "same_node":
				options.PreferredNode = old
				options.ExpectedTargetIP = netip.MustParseAddr("198.51.100.1")
			case "same_ip":
				entry.SetEgressIP(netip.MustParseAddr("198.51.100.1"))
				options.ExpectedTargetIP = entry.GetEgressIP()
			case "missing_ip":
				options.ExpectedTargetIP = netip.Addr{}
			case "missing_hash":
				options.PreferredNode = node.Zero
			case "stale_generation":
				generation++
				wantErr = routing.ErrLeaseChanged
			}
			after, count, err := router.RotateLease(platID, "strict", old, generation, "cloudflare.com", options)
			if !errors.Is(err, wantErr) || after != nil || count != 0 || closed.Load() {
				t.Fatalf("failed candidate changed the route: after=%+v count=%d closed=%v err=%v", after, count, closed.Load(), err)
			}
			stored := router.ReadLease(model.LeaseKey{PlatformID: platID, Account: "strict"})
			if stored == nil || *stored != before {
				t.Fatalf("original lease changed: got=%+v want=%+v", stored, before)
			}
			if router.SnapshotIPLoad(platID)[netip.MustParseAddr(before.EgressIP)] != 1 {
				t.Fatal("original IP load changed")
			}
		})
	}
}
