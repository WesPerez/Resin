package service

import (
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/routing"
	"github.com/Resinat/Resin/internal/subscription"
)

func recoveryTestNode(t *testing.T, cp *ControlPlaneService, id, ip string) node.Hash {
	t.Helper()
	sub, ok := cp.SubMgr.Get("recovery-test")
	if !ok {
		sub = subscription.NewSubscription("recovery-test", "Recovery", "https://example.com/nodes", true, false)
		cp.SubMgr.Register(sub)
	}
	return addRoutableNodeForSubscription(t, cp.Pool, sub, []byte(fmt.Sprintf(`{"id":%q}`, id)), ip)
}

func recoveryFailure(lease *LeaseResponse) ReportLeaseFailureRequest {
	return ReportLeaseFailureRequest{TargetHost: "example.com:443", ExpectedNodeHash: lease.NodeHash,
		ExpectedCreatedAtNs: lease.CreatedAtNs, Reason: "empty_stream"}
}

func TestRecoveryLease_NoAlternativeThenNewCandidate(t *testing.T) {
	cp, plat := newLeaseInheritanceTestService()
	plat.StickyTTLNs = int64(time.Hour)
	a := recoveryTestNode(t, cp, "a", "198.51.100.1")
	first, err := cp.AcquireRecoveryLease(plat.Name, "account", AcquireRecoveryLeaseRequest{"example.com:443"})
	if err != nil || first.Status != "available" || first.Lease == nil {
		t.Fatalf("acquire: %+v %v", first, err)
	}
	result, err := cp.ReportLeaseFailure(plat.Name, "account", recoveryFailure(first.Lease))
	if err != nil || result.Status != "no_alternative" || result.Lease == nil {
		t.Fatalf("report: %+v %v", result, err)
	}
	if result.Lease.CreatedAtNs != first.Lease.CreatedAtNs {
		t.Fatal("failed rotation replaced the lease")
	}
	if status := cp.Router.RecoveryStatus(); status.Rotated != 0 {
		t.Fatalf("no-alternative report consumed rotation budget: %+v", status)
	}
	if !cp.Router.TargetCooling(plat.ID, "account", "EXAMPLE.COM.:443", a, netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("no-alternative failure lost its cooldown")
	}
	if cp.Router.TargetCooling(plat.ID, "other", "example.com:443", a, netip.MustParseAddr("198.51.100.1")) ||
		cp.Router.TargetCooling(plat.ID, "account", "other.example:443", a, netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("cooldown escaped its account or target")
	}
	b := recoveryTestNode(t, cp, "b", "198.51.100.2")
	result, err = cp.AcquireRecoveryLease(plat.Name, "account", AcquireRecoveryLeaseRequest{"example.com:443"})
	if err != nil || result.Status != "available" || result.Lease.NodeHash != b.Hex() {
		t.Fatalf("recovery: %+v %v", result, err)
	}
	if status := cp.Router.RecoveryStatus(); status.Rotated != 1 {
		t.Fatalf("acquire bypassed guarded rotation accounting: %+v", status)
	}
	stable, err := cp.AcquireRecoveryLease(plat.Name, "account", AcquireRecoveryLeaseRequest{"example.com:443"})
	if err != nil || stable.Status != "available" || stable.Lease.CreatedAtNs != result.Lease.CreatedAtNs ||
		cp.Router.RecoveryStatus().Rotated != 1 {
		t.Fatalf("ordinary acquire changed the lease or rotation budget: %+v %v", stable, err)
	}
	result, err = cp.ReportLeaseFailure(plat.Name, "account", recoveryFailure(result.Lease))
	if err != nil || result.Status != "recovery_limited" || result.Lease.NodeHash != b.Hex() {
		t.Fatalf("must not bounce to A: %+v %v", result, err)
	}
	recoveryTestNode(t, cp, "same-a-ip", "198.51.100.1")
	result, err = cp.AcquireRecoveryLease(plat.Name, "account", AcquireRecoveryLeaseRequest{"example.com:443"})
	if err != nil || result.Status != "recovery_limited" {
		t.Fatalf("cooled IP reused: %+v %v", result, err)
	}
	c := recoveryTestNode(t, cp, "c", "198.51.100.3")
	result, err = cp.AcquireRecoveryLease(plat.Name, "account", AcquireRecoveryLeaseRequest{"example.com:443"})
	if err != nil || result.Status != "recovery_limited" || result.Lease.NodeHash != b.Hex() {
		t.Fatalf("acquire bypassed recovery limits: %+v %v", result, err)
	}
	// An administrator can still rotate; target cooling survives a limited report.
	created, _ := strconv.ParseInt(result.Lease.CreatedAtNs, 10, 64)
	manual, _, err := cp.Router.RotateLease(plat.ID, "account", b, created, "example.com:443", routing.RotateLeaseOptions{PreserveConnections: true, ApplyTargetCooldown: true})
	if err != nil || manual.NodeHash != c.Hex() {
		t.Fatalf("manual recovery failed to exclude cooled exits: %+v %v", manual, err)
	}
	entry, _ := cp.Pool.GetEntry(a)
	if !entry.IsHealthy() {
		t.Fatal("target failure changed global node health")
	}
}

func TestRecoveryLease_AcquirePreservesInvisibleLease(t *testing.T) {
	cp, plat := newLeaseInheritanceTestService()
	now := time.Now().UnixNano()
	original := model.Lease{PlatformID: plat.ID, Account: "account", NodeHash: node.HashFromRawOptions([]byte("missing")).Hex(),
		EgressIP: "198.51.100.1", CreatedAtNs: now, ExpiryNs: now + int64(time.Hour), LastAccessedNs: now}
	seedLease(t, cp, original)
	result, err := cp.AcquireRecoveryLease(plat.Name, "account", AcquireRecoveryLeaseRequest{"example.com:443"})
	if err != nil || result.Status != "no_alternative" || result.Lease == nil {
		t.Fatalf("acquire: %+v %v", result, err)
	}
	if result.Lease.CreatedAtNs != strconv.FormatInt(now, 10) {
		t.Fatal("response omitted the preserved generation")
	}
	current := cp.Router.ReadLease(model.LeaseKey{PlatformID: plat.ID, Account: "account"})
	if current == nil || *current != original {
		t.Fatalf("acquire mutated fallback lease: %+v", current)
	}
}

func TestRecoveryLease_AcquireDoesNotCommitCooledSameIPReplacement(t *testing.T) {
	cp, plat := newLeaseInheritanceTestService()
	plat.StickyTTLNs = int64(time.Hour)
	a := recoveryTestNode(t, cp, "a", "198.51.100.1")
	first, err := cp.AcquireRecoveryLease(plat.Name, "account", AcquireRecoveryLeaseRequest{"example.com:443"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := cp.ReportLeaseFailure(plat.Name, "account", recoveryFailure(first.Lease))
	if err != nil || result.Status != "no_alternative" {
		t.Fatalf("report: %+v %v", result, err)
	}
	original := cp.Router.ReadLease(model.LeaseKey{PlatformID: plat.ID, Account: "account"})
	recoveryTestNode(t, cp, "same-ip-b", "198.51.100.1")
	entry, _ := cp.Pool.GetEntry(a)
	entry.Outbound.Store(nil)
	cp.Pool.NotifyNodeDirty(a)
	result, err = cp.AcquireRecoveryLease(plat.Name, "account", AcquireRecoveryLeaseRequest{"example.com:443"})
	if err != nil || result.Status != "no_alternative" || result.Lease.NodeHash != a.Hex() {
		t.Fatalf("cooled fallback committed: %+v %v", result, err)
	}
	current := cp.Router.ReadLease(model.LeaseKey{PlatformID: plat.ID, Account: "account"})
	if current == nil || *current != *original {
		t.Fatalf("no-alternative changed lease: %+v", current)
	}
}

func TestRecoveryLease_ConcurrentCASPreservesTunnelsAndRejectsStale(t *testing.T) {
	cp, plat := newLeaseInheritanceTestService()
	plat.StickyTTLNs = int64(time.Hour)
	a := recoveryTestNode(t, cp, "a", "198.51.100.1")
	first, err := cp.AcquireRecoveryLease(plat.Name, "account", AcquireRecoveryLeaseRequest{"example.com:443"})
	if err != nil {
		t.Fatal(err)
	}
	route, err := cp.Router.RouteRequest(plat.Name, "account", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	var closed atomic.Bool
	unregister, ok := cp.Router.RegisterLeaseConnection(route, "account", func() { closed.Store(true) })
	if !ok {
		t.Fatal("register active tunnel")
	}
	defer unregister()
	b := recoveryTestNode(t, cp, "b", "198.51.100.2")
	var wg sync.WaitGroup
	statuses := make(chan string, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := cp.ReportLeaseFailure(plat.Name, "account", recoveryFailure(first.Lease))
			if err != nil {
				t.Errorf("report: %v", err)
				return
			}
			statuses <- result.Status
		}()
	}
	wg.Wait()
	close(statuses)
	counts := map[string]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts["rotated"] != 1 || counts["stale_lease"] != 7 || closed.Load() {
		t.Fatalf("CAS/connection contract: %v closed=%v", counts, closed.Load())
	}
	current := cp.Router.ReadLease(model.LeaseKey{PlatformID: plat.ID, Account: "account"})
	if current.NodeHash != b.Hex() {
		t.Fatalf("wrong replacement: %+v", current)
	}
	if cp.Router.TargetCooling(plat.ID, "account", "other.example:443", a, netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("unexpected cooldown")
	}
	stale := recoveryFailure(first.Lease)
	stale.TargetHost = "other.example:443"
	result, err := cp.ReportLeaseFailure(plat.Name, "account", stale)
	if err != nil || result.Status != "stale_lease" {
		t.Fatalf("stale report: %+v %v", result, err)
	}
	if cp.Router.TargetCooling(plat.ID, "account", stale.TargetHost, a, netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("stale report created cooldown")
	}
}
