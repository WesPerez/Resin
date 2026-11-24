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

func TestFailureClassForReason_MapsCooldownClasses(t *testing.T) {
	cases := map[string]routing.FailureClass{
		"transport_error": routing.FailureTransport,
		"empty_stream":    routing.FailureUnclassified,
		"invalid_stream":  routing.FailureUnclassified,
	}
	for reason, want := range cases {
		got, ok := failureClassForReason(reason)
		if !ok || got != want {
			t.Fatalf("failureClassForReason(%q) = (%v, %v), want (%v, true)", reason, got, ok, want)
		}
	}
	for _, rejected := range []string{"challenge", "rate_limited", "429", ""} {
		if _, ok := failureClassForReason(rejected); ok {
			t.Fatalf("reason %q must not be accepted for rotation", rejected)
		}
	}
}

func TestReportLeaseFailure_TransportReasonRotatesAndCoolsObservedNode(t *testing.T) {
	cp, plat := newLeaseInheritanceTestService()
	plat.StickyTTLNs = int64(time.Hour)
	recoveryTestNode(t, cp, "class-a", "198.51.100.1")
	first, err := cp.AcquireRecoveryLease(plat.Name, "account", AcquireRecoveryLeaseRequest{TargetHost: "example.com:443"})
	if err != nil {
		t.Fatal(err)
	}
	recoveryTestNode(t, cp, "class-b", "198.51.100.2")
	req := recoveryFailure(first.Lease)
	req.Reason = "transport_error"
	result, err := cp.ReportLeaseFailure(plat.Name, "account", req)
	if err != nil || result.Status != "rotated" {
		t.Fatalf("transport report: %+v %v", result, err)
	}
	hash, err := node.ParseHex(first.Lease.NodeHash)
	if err != nil {
		t.Fatal(err)
	}
	if !cp.Router.TargetCooling(plat.ID, "account", req.TargetHost, hash, netip.MustParseAddr(first.Lease.EgressIP)) {
		t.Fatal("transport report did not cool the observed node")
	}
}

func TestRecoveryHintsEmptyStaleAndRepeatedDoNotBlockHealthyPool(t *testing.T) {
	cp, plat := newLeaseInheritanceTestService()
	recoveryTestNode(t, cp, "a", "198.51.100.1")
	first, err := cp.AcquireRecoveryLease(plat.Name, "account", AcquireRecoveryLeaseRequest{TargetHost: "example.com:443", PreferredCandidates: []RecoveryCandidate{}})
	if err != nil || first.Status != "available" {
		t.Fatalf("empty hints blocked: %+v %v", first, err)
	}
	recoveryTestNode(t, cp, "b", "198.51.100.2")
	current := first
	for i := 0; i < 5; i++ {
		req := recoveryFailure(current.Lease)
		req.PreferredCandidates = []RecoveryCandidate{{NodeHash: "invalid", ExpectedTargetIP: "invalid"}, {NodeHash: node.HashFromRawOptions([]byte("missing")).Hex(), ExpectedTargetIP: "old-ip"}}
		current, err = cp.ReportLeaseFailure(plat.Name, "account", req)
		if err != nil || current.Status != "rotated" || current.Lease == nil {
			t.Fatalf("hint/quota blocked round %d: %+v %v", i, current, err)
		}
	}
	stale, err := cp.ReportLeaseFailure(plat.Name, "account", recoveryFailure(first.Lease))
	if err != nil || stale.Status != "stale_lease" {
		t.Fatalf("old failure changed current lease: %+v %v", stale, err)
	}
}
func TestRecoveryUnavailableAlternativeStillAllowsCurrentHealthyLease(t *testing.T) {
	cp, plat := newLeaseInheritanceTestService()
	recoveryTestNode(t, cp, "a", "198.51.100.1")
	first, err := cp.AcquireRecoveryLease(plat.Name, "account", AcquireRecoveryLeaseRequest{TargetHost: "example.com:443"})
	if err != nil {
		t.Fatal(err)
	}
	failed, err := cp.ReportLeaseFailure(plat.Name, "account", recoveryFailure(first.Lease))
	if err != nil || failed.Status != "no_alternative" {
		t.Fatalf("unexpected report: %+v %v", failed, err)
	}
	result, err := cp.AcquireRecoveryLease(plat.Name, "account", AcquireRecoveryLeaseRequest{TargetHost: "example.com:443", PreferredCandidates: []RecoveryCandidate{}})
	if err != nil || result.Status != "available" || result.Lease == nil {
		t.Fatalf("healthy lease denied: %+v %v", result, err)
	}
}
