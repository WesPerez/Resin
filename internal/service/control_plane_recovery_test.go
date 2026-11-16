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
	first, err := cp.AcquireRecoveryLease(plat.Name, "account", AcquireRecoveryLeaseRequest{TargetHost: "example.com:443"})
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
	result, err = cp.AcquireRecoveryLease(plat.Name, "account", AcquireRecoveryLeaseRequest{TargetHost: "example.com:443"})
	if err != nil || result.Status != "available" || result.Lease.NodeHash != b.Hex() {
		t.Fatalf("recovery: %+v %v", result, err)
	}
	if status := cp.Router.RecoveryStatus(); status.Rotated != 1 {
		t.Fatalf("acquire bypassed guarded rotation accounting: %+v", status)
	}
	stable, err := cp.AcquireRecoveryLease(plat.Name, "account", AcquireRecoveryLeaseRequest{TargetHost: "example.com:443"})
	if err != nil || stable.Status != "available" || stable.Lease.CreatedAtNs != result.Lease.CreatedAtNs ||
		cp.Router.RecoveryStatus().Rotated != 1 {
		t.Fatalf("ordinary acquire changed the lease or rotation budget: %+v %v", stable, err)
	}
	result, err = cp.ReportLeaseFailure(plat.Name, "account", recoveryFailure(result.Lease))
	if err != nil || result.Status != "recovery_limited" || result.Lease.NodeHash != b.Hex() {
		t.Fatalf("must not bounce to A: %+v %v", result, err)
	}
	recoveryTestNode(t, cp, "same-a-ip", "198.51.100.1")
	result, err = cp.AcquireRecoveryLease(plat.Name, "account", AcquireRecoveryLeaseRequest{TargetHost: "example.com:443"})
	if err != nil || result.Status != "recovery_limited" {
		t.Fatalf("cooled IP reused: %+v %v", result, err)
	}
	c := recoveryTestNode(t, cp, "c", "198.51.100.3")
	result, err = cp.AcquireRecoveryLease(plat.Name, "account", AcquireRecoveryLeaseRequest{TargetHost: "example.com:443"})
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
	result, err := cp.AcquireRecoveryLease(plat.Name, "account", AcquireRecoveryLeaseRequest{TargetHost: "example.com:443"})
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
	first, err := cp.AcquireRecoveryLease(plat.Name, "account", AcquireRecoveryLeaseRequest{TargetHost: "example.com:443"})
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
	result, err = cp.AcquireRecoveryLease(plat.Name, "account", AcquireRecoveryLeaseRequest{TargetHost: "example.com:443"})
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
	first, err := cp.AcquireRecoveryLease(plat.Name, "account", AcquireRecoveryLeaseRequest{TargetHost: "example.com:443"})
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
			req := recoveryFailure(first.Lease)
			req.PreferredCandidates = []RecoveryCandidate{{NodeHash: b.Hex(), ExpectedTargetIP: "198.51.100.2"}}
			result, err := cp.ReportLeaseFailure(plat.Name, "account", req)
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

func TestRecoveryLease_PreferredPoolExhaustionAndCoolingAcquire(t *testing.T) {
	cp, plat := newLeaseInheritanceTestService()
	plat.StickyTTLNs = int64(time.Hour)
	recoveryTestNode(t, cp, "original", "198.51.100.1")
	first, err := cp.AcquireRecoveryLease(plat.Name, "pool", AcquireRecoveryLeaseRequest{TargetHost: "example.com:443"})
	if err != nil || first.Lease == nil {
		t.Fatalf("acquire: %+v %v", first, err)
	}
	outside := recoveryTestNode(t, cp, "outside", "198.51.100.2")
	selected := recoveryTestNode(t, cp, "selected", "198.51.100.3")
	req := recoveryFailure(first.Lease)
	// Available nodes outside the supplied pool never become a silent fallback.
	req.PreferredCandidates = []RecoveryCandidate{{NodeHash: outside.Hex(), ExpectedTargetIP: "198.51.100.99"}}
	result, err := cp.ReportLeaseFailure(plat.Name, "pool", req)
	if err != nil || result.Status != "no_alternative" || result.Lease.CreatedAtNs != first.Lease.CreatedAtNs {
		t.Fatalf("exhaustion changed lease: %+v %v", result, err)
	}
	if status := cp.Router.RecoveryStatus(); status.NoAlternative != 1 || status.Rotated != 0 {
		t.Fatalf("failed candidates counted as separate recovery attempts: %+v", status)
	}
	// Explicitly empty is a known exhausted pool, not the legacy random mode.
	result, err = cp.AcquireRecoveryLease(plat.Name, "pool", AcquireRecoveryLeaseRequest{TargetHost: "example.com:443", PreferredCandidates: []RecoveryCandidate{}})
	if err != nil || result.Status != "no_alternative" || result.Lease.CreatedAtNs != first.Lease.CreatedAtNs {
		t.Fatalf("cooling acquire escaped the empty pool: %+v %v", result, err)
	}
	req.PreferredCandidates = append(req.PreferredCandidates, RecoveryCandidate{NodeHash: selected.Hex(), ExpectedTargetIP: "198.51.100.3"})
	result, err = cp.AcquireRecoveryLease(plat.Name, "pool", AcquireRecoveryLeaseRequest{TargetHost: "example.com:443", PreferredCandidates: req.PreferredCandidates})
	if err != nil || result.Status != "available" || result.Lease.NodeHash != selected.Hex() {
		t.Fatalf("cooling acquire ignored ordered pool: %+v %v", result, err)
	}
	if cp.Router.RecoveryStatus().Rotated != 1 {
		t.Fatal("pool bypassed shared rotation budget")
	}
	req = recoveryFailure(result.Lease)
	req.PreferredCandidates = []RecoveryCandidate{{NodeHash: outside.Hex(), ExpectedTargetIP: "198.51.100.2"}}
	result, err = cp.ReportLeaseFailure(plat.Name, "pool", req)
	if err != nil || result.Status != "recovery_limited" || result.Lease.NodeHash != selected.Hex() {
		t.Fatalf("preferred pool bypassed shared limit: %+v %v", result, err)
	}
}

func TestRecoveryCandidatesValidateBeforeAnyMutation(t *testing.T) {
	cp, plat := newLeaseInheritanceTestService()
	hash := recoveryTestNode(t, cp, "original", "198.51.100.1")
	first, err := cp.AcquireRecoveryLease(plat.Name, "validation", AcquireRecoveryLeaseRequest{TargetHost: "example.com:443"})
	if err != nil {
		t.Fatal(err)
	}
	valid := RecoveryCandidate{NodeHash: hash.Hex(), ExpectedTargetIP: "198.51.100.1"}
	for _, values := range [][]RecoveryCandidate{
		{{NodeHash: "bad", ExpectedTargetIP: "198.51.100.1"}},
		{{NodeHash: hash.Hex(), ExpectedTargetIP: "127.0.0.1"}},
		{{NodeHash: hash.Hex(), ExpectedTargetIP: "fe80::1%eth0"}},
		{valid, valid}, make([]RecoveryCandidate, 61),
	} {
		req := recoveryFailure(first.Lease)
		req.PreferredCandidates = values
		if _, err := cp.ReportLeaseFailure(plat.Name, "validation", req); err == nil {
			t.Fatal("accepted invalid list")
		}
		if _, err := cp.AcquireRecoveryLease(plat.Name, "validation", AcquireRecoveryLeaseRequest{TargetHost: "example.com:443", PreferredCandidates: values}); err == nil {
			t.Fatal("acquire accepted invalid list")
		}
	}
	if cp.Router.TargetCooling(plat.ID, "validation", "example.com:443", hash, netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("invalid input wrote cooldown")
	}
	if cp.Router.RecoveryStatus().NoAlternative != 0 {
		t.Fatal("invalid input entered recovery")
	}
}

func TestRecoveryCandidatesAcquireExistingInvalidBinding(t *testing.T) {
	for _, kind := range []string{"healthy", "expired", "missing", "outbound", "circuit", "circuit_dirty", "ip_changed"} {
		for _, useCandidate := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/candidate=%v", kind, useCandidate), func(t *testing.T) {
				cp, plat := newLeaseInheritanceTestService()
				plat.StickyTTLNs = int64(time.Hour)
				a := recoveryTestNode(t, cp, "old", "198.51.100.1")
				first, err := cp.AcquireRecoveryLease(plat.Name, "bound", AcquireRecoveryLeaseRequest{TargetHost: "example.com:443"})
				if err != nil || first.Lease == nil {
					t.Fatalf("initial allocation: %+v %v", first, err)
				}
				b := recoveryTestNode(t, cp, "audited", "198.51.100.2")
				recoveryTestNode(t, cp, "random-outside-list", "198.51.100.3")
				before := *cp.Router.ReadLease(model.LeaseKey{PlatformID: plat.ID, Account: "bound"})
				var closed atomic.Bool
				unregister, ok := cp.Router.RegisterLeaseConnection(routing.RouteResult{PlatformID: plat.ID,
					NodeHash: a, LeaseCreatedAtNs: before.CreatedAtNs}, "bound", func() { closed.Store(true) })
				if !ok {
					t.Fatal("register existing connection")
				}
				defer unregister()
				entry, _ := cp.Pool.GetEntry(a)
				switch kind {
				case "expired":
					before.ExpiryNs = time.Now().Add(-time.Second).UnixNano()
					seedLease(t, cp, before)
				case "missing":
					before.NodeHash = node.HashFromRawOptions([]byte("absent")).Hex()
					seedLease(t, cp, before)
				case "outbound":
					entry.Outbound.Store(nil)
				case "circuit", "circuit_dirty":
					entry.CircuitOpenSince.Store(time.Now().UnixNano())
					if kind == "circuit_dirty" {
						cp.Pool.NotifyNodeDirty(a)
					}
				case "ip_changed":
					entry.SetEgressIP(netip.MustParseAddr("198.51.100.9"))
				}
				loads := cp.Router.SnapshotIPLoad(plat.ID)
				if kind == "expired" {
					result, err := cp.ReportLeaseFailure(plat.Name, "bound", recoveryFailure(first.Lease))
					if err != nil || result.Status != "stale_lease" {
						t.Fatalf("old report accepted expired lease: %+v %v", result, err)
					}
					if _, _, err := cp.Router.RotateLease(plat.ID, "bound", a, before.CreatedAtNs, "example.com:443",
						routing.RotateLeaseOptions{PreserveConnections: true}); err != routing.ErrLeaseChanged {
						t.Fatalf("administrator expiry barrier changed: %v", err)
					}
				}
				pool := []RecoveryCandidate{}
				if useCandidate {
					pool = []RecoveryCandidate{{NodeHash: b.Hex(), ExpectedTargetIP: "198.51.100.2"}}
				}
				result, err := cp.AcquireRecoveryLease(plat.Name, "bound", AcquireRecoveryLeaseRequest{
					TargetHost: "example.com:443", PreferredCandidates: pool})
				if err != nil || result.Lease == nil || closed.Load() {
					t.Fatalf("acquire/connection: %+v %v closed=%v", result, err, closed.Load())
				}
				current := cp.Router.ReadLease(model.LeaseKey{PlatformID: plat.ID, Account: "bound"})
				if kind == "healthy" {
					if result.Status != "available" || current.NodeHash != before.NodeHash || current.CreatedAtNs != before.CreatedAtNs ||
						cp.Router.RecoveryStatus().Rotated != 0 {
						t.Fatalf("healthy binding changed: %+v", result)
					}
				} else if useCandidate {
					if result.Status != "available" || current.NodeHash != b.Hex() || current.CreatedAtNs <= before.CreatedAtNs ||
						cp.Router.RecoveryStatus().Rotated != 1 || current.ExpiryNs <= time.Now().UnixNano() {
						t.Fatalf("candidate recovery bypassed pool/budget: %+v", result)
					}
				} else {
					if result.Status != "no_alternative" || *current != before || cp.Router.RecoveryStatus().Rotated != 0 {
						t.Fatalf("empty pool mutated invalid binding: %+v before=%+v current=%+v", result, before, current)
					}
					for ip, count := range loads {
						if cp.Router.SnapshotIPLoad(plat.ID)[ip] != count {
							t.Fatal("empty pool changed IP loads")
						}
					}
				}
			})
		}
	}
}

func TestRecoveryCandidatesAcquireMissingLeaseUsesNativeInitialAllocation(t *testing.T) {
	cp, plat := newLeaseInheritanceTestService()
	hash := recoveryTestNode(t, cp, "initial", "198.51.100.1")
	result, err := cp.AcquireRecoveryLease(plat.Name, "new", AcquireRecoveryLeaseRequest{
		TargetHost: "example.com:443", PreferredCandidates: []RecoveryCandidate{}})
	if err != nil || result.Status != "available" || result.Lease == nil || result.Lease.NodeHash != hash.Hex() ||
		cp.Router.RecoveryStatus().Rotated != 0 {
		t.Fatalf("native initial allocation changed: %+v %v", result, err)
	}
}

func TestRecoveryCandidatesRetryDoesNotRecreateRemovedLease(t *testing.T) {
	for _, useCandidate := range []bool{false, true} {
		t.Run(fmt.Sprintf("candidate=%v", useCandidate), func(t *testing.T) {
			cp, plat := newLeaseInheritanceTestService()
			old := recoveryTestNode(t, cp, "old", "198.51.100.1")
			first, err := cp.AcquireRecoveryLease(plat.Name, "removed", AcquireRecoveryLeaseRequest{TargetHost: "example.com:443"})
			if err != nil || first.Lease == nil {
				t.Fatalf("initial allocation: %+v %v", first, err)
			}
			audited := recoveryTestNode(t, cp, "audited", "198.51.100.2")
			recoveryTestNode(t, cp, "outside", "198.51.100.3")
			key := model.LeaseKey{PlatformID: plat.ID, Account: "removed"}
			observed := *cp.Router.ReadLease(key)
			observed.ExpiryNs = time.Now().Add(-time.Second).UnixNano()
			seedLease(t, cp, observed)
			// Reproduce the state after the cleaner deletes the observed expired
			// generation between acquisition's read transaction and rotation CAS.
			if !cp.Router.DeleteLeaseIfGeneration(plat.ID, "removed", old, observed.CreatedAtNs) {
				t.Fatal("remove observed generation")
			}
			if _, _, err := cp.Router.RecoverLease(plat.ID, "removed", old, observed.CreatedAtNs, "example.com:443",
				routing.RotateLeaseOptions{}); err != routing.ErrLeaseChanged {
				t.Fatalf("removed generation accepted by CAS: %v", err)
			}
			pool := []RecoveryCandidate{}
			if useCandidate {
				pool = []RecoveryCandidate{{NodeHash: audited.Hex(), ExpectedTargetIP: "198.51.100.2"}}
			}
			result, err := cp.acquireRecoveryLease(plat.Name, "removed", AcquireRecoveryLeaseRequest{
				TargetHost: "example.com:443", PreferredCandidates: pool}, 1, false)
			if err != nil || result.Status != "stale_lease" || result.Lease != nil || cp.Router.ReadLease(key) != nil ||
				cp.Router.RecoveryStatus().Rotated != 0 {
				t.Fatalf("retry recreated a removed binding: %+v %v", result, err)
			}
		})
	}
}

func TestRecoveryCandidatesInitialAllocationPreservesTargetCooldown(t *testing.T) {
	cp, plat := newLeaseInheritanceTestService()
	recoveryTestNode(t, cp, "cooled", "198.51.100.1")
	first, err := cp.AcquireRecoveryLease(plat.Name, "cooling", AcquireRecoveryLeaseRequest{TargetHost: "example.com:443"})
	if err != nil || first.Lease == nil {
		t.Fatalf("initial allocation: %+v %v", first, err)
	}
	failure := recoveryFailure(first.Lease)
	failure.PreferredCandidates = []RecoveryCandidate{}
	result, err := cp.ReportLeaseFailure(plat.Name, "cooling", failure)
	if err != nil || result.Status != "no_alternative" || !cp.Router.DeleteLease(plat.ID, "cooling") {
		t.Fatalf("prepare retained cooldown: %+v %v", result, err)
	}
	recoveryTestNode(t, cp, "same-cooled-ip", "198.51.100.1")
	request := AcquireRecoveryLeaseRequest{TargetHost: "example.com:443", PreferredCandidates: []RecoveryCandidate{}}
	result, err = cp.AcquireRecoveryLease(plat.Name, "cooling", request)
	if err != nil || result.Status != "no_alternative" || result.Lease != nil ||
		cp.Router.ReadLease(model.LeaseKey{PlatformID: plat.ID, Account: "cooling"}) != nil {
		t.Fatalf("initial allocation committed a cooled exit: %+v %v", result, err)
	}
	fresh := recoveryTestNode(t, cp, "fresh", "198.51.100.2")
	result, err = cp.AcquireRecoveryLease(plat.Name, "cooling", request)
	if err != nil || result.Status != "available" || result.Lease == nil || result.Lease.NodeHash != fresh.Hex() ||
		cp.Router.RecoveryStatus().Rotated != 0 {
		t.Fatalf("native initial allocation lost cooldown exclusions: %+v %v", result, err)
	}
}

func TestRecoveryCandidatesAcquireRejectsSameIPAndHonorsSharedLimits(t *testing.T) {
	cp, plat := newLeaseInheritanceTestService()
	old := recoveryTestNode(t, cp, "old", "198.51.100.1")
	first, err := cp.AcquireRecoveryLease(plat.Name, "limited", AcquireRecoveryLeaseRequest{TargetHost: "example.com:443"})
	if err != nil {
		t.Fatal(err)
	}
	same := recoveryTestNode(t, cp, "same-ip", "198.51.100.1")
	audited := recoveryTestNode(t, cp, "audited", "198.51.100.2")
	recoveryTestNode(t, cp, "outside", "198.51.100.3")
	entry, _ := cp.Pool.GetEntry(old)
	entry.CircuitOpenSince.Store(time.Now().UnixNano())
	result, err := cp.AcquireRecoveryLease(plat.Name, "limited", AcquireRecoveryLeaseRequest{
		TargetHost: "example.com:443", PreferredCandidates: []RecoveryCandidate{{NodeHash: same.Hex(), ExpectedTargetIP: "198.51.100.1"}}})
	if err != nil || result.Status != "no_alternative" || result.Lease.CreatedAtNs != first.Lease.CreatedAtNs {
		t.Fatalf("same-IP candidate or random fallback used: %+v %v", result, err)
	}
	request := AcquireRecoveryLeaseRequest{TargetHost: "example.com:443", PreferredCandidates: []RecoveryCandidate{
		{NodeHash: audited.Hex(), ExpectedTargetIP: "198.51.100.2"}}}
	result, err = cp.AcquireRecoveryLease(plat.Name, "limited", request)
	if err != nil || result.Status != "available" || result.Lease.NodeHash != audited.Hex() {
		t.Fatalf("recover audited node: %+v %v", result, err)
	}
	entry, _ = cp.Pool.GetEntry(audited)
	entry.CircuitOpenSince.Store(time.Now().UnixNano())
	request.PreferredCandidates = []RecoveryCandidate{{NodeHash: same.Hex(), ExpectedTargetIP: "198.51.100.1"}}
	limited, err := cp.AcquireRecoveryLease(plat.Name, "limited", request)
	if err != nil || limited.Status != "recovery_limited" || limited.Lease.CreatedAtNs != result.Lease.CreatedAtNs ||
		cp.Router.RecoveryStatus().Rotated != 1 {
		t.Fatalf("acquisition bypassed shared rate limit: %+v %v", limited, err)
	}
}

func TestRecoveryCandidatesAcquireConcurrentInvalidBindingPreservesConnection(t *testing.T) {
	cp, plat := newLeaseInheritanceTestService()
	old := recoveryTestNode(t, cp, "old", "198.51.100.1")
	first, err := cp.AcquireRecoveryLease(plat.Name, "concurrent", AcquireRecoveryLeaseRequest{TargetHost: "example.com:443"})
	if err != nil {
		t.Fatal(err)
	}
	created, _ := strconv.ParseInt(first.Lease.CreatedAtNs, 10, 64)
	var closed atomic.Bool
	unregister, ok := cp.Router.RegisterLeaseConnection(routing.RouteResult{PlatformID: plat.ID,
		NodeHash: old, LeaseCreatedAtNs: created}, "concurrent", func() { closed.Store(true) })
	if !ok {
		t.Fatal("register connection")
	}
	defer unregister()
	audited := recoveryTestNode(t, cp, "audited", "198.51.100.2")
	entry, _ := cp.Pool.GetEntry(old)
	entry.CircuitOpenSince.Store(time.Now().UnixNano())
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := cp.AcquireRecoveryLease(plat.Name, "concurrent", AcquireRecoveryLeaseRequest{
				TargetHost: "example.com:443", PreferredCandidates: []RecoveryCandidate{{NodeHash: audited.Hex(), ExpectedTargetIP: "198.51.100.2"}}})
			if err != nil || result.Lease == nil || result.Status != "available" || result.Lease.NodeHash != audited.Hex() {
				t.Errorf("concurrent acquisition: %+v %v", result, err)
			}
		}()
	}
	wg.Wait()
	if closed.Load() || cp.Router.RecoveryStatus().Rotated != 1 {
		t.Fatalf("concurrent recovery lost connection or consumed duplicate budget: closed=%v status=%+v", closed.Load(), cp.Router.RecoveryStatus())
	}
}
