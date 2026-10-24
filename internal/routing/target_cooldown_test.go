package routing

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/platform"
)

func TestTargetCooldown_BoundedExpiryAndIsolation(t *testing.T) {
	now := time.Now()
	r := &Router{targetCooldowns: make(map[targetCooldownKey]targetCooldown)}
	for i := range maxTargetCooldowns {
		key := targetCooldownKey{"platform", fmt.Sprint(i), "example.com", node.HashFromRawOptions([]byte(fmt.Sprint(i)))}
		r.targetCooldowns[key] = targetCooldown{netip.MustParseAddr("198.51.100.1"), now.Add(time.Duration(i+1) * time.Second)}
	}
	hash := node.HashFromRawOptions([]byte("new"))
	lease := Lease{NodeHash: hash, EgressIP: netip.MustParseAddr("198.51.100.2")}
	r.recordTargetCooldownLocked("platform", "new", "EXAMPLE.COM.:443", lease, now, time.Hour)
	if len(r.targetCooldowns) != maxTargetCooldowns {
		t.Fatalf("unbounded cooldowns: %d", len(r.targetCooldowns))
	}
	if r.TargetCooling("platform", "0", "example.com", node.HashFromRawOptions([]byte("0")), netip.Addr{}) {
		t.Fatal("oldest entry not evicted")
	}
	key := targetCooldownKey{"platform", "new", "example.com", hash}
	if got := r.targetCooldowns[key].until; !got.Equal(now.Add(maxTargetCooldownTTL)) {
		t.Fatal("TTL not capped")
	}
	if !r.TargetCooling("platform", "new", "example.com:443", hash, netip.Addr{}) {
		t.Fatal("missing cooldown")
	}
	if r.TargetCooling("other", "new", "example.com:443", hash, netip.Addr{}) {
		t.Fatal("platform leaked")
	}
	r.targetCooldowns[key] = targetCooldown{lease.EgressIP, now.Add(-time.Second)}
	if r.TargetCooling("platform", "new", "example.com", hash, lease.EgressIP) {
		t.Fatal("expired cooldown still active")
	}
}

func TestSameIPRotation_NeverReusesGeneration(t *testing.T) {
	pool := newRouterTestPool()
	plat := platform.NewPlatform("p", "Platform", nil, nil)
	plat.StickyTTLNs = int64(time.Hour)
	pool.addPlatform(plat)
	a, entryA := newRoutableEntry(t, `{"node":"a"}`, "198.51.100.1")
	b, entryB := newRoutableEntry(t, `{"node":"b"}`, "198.51.100.1")
	pool.addEntry(a, entryA)
	pool.rebuildPlatformView(plat)
	router := newTestRouter(pool, nil)
	first, err := router.RouteRequest(plat.Name, "account", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	original := router.ReadLease(model.LeaseKey{PlatformID: plat.ID, Account: "account"})
	pool.removeEntry(a)
	pool.addEntry(b, entryB)
	pool.rebuildPlatformView(plat)
	second, err := router.RouteRequest(plat.Name, "account", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	pool.removeEntry(b)
	pool.addEntry(a, entryA)
	pool.rebuildPlatformView(plat)
	third, err := router.RouteRequest(plat.Name, "account", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	current := router.ReadLease(model.LeaseKey{PlatformID: plat.ID, Account: "account"})
	if second.NodeHash != b || third.NodeHash != a || first.LeaseCreatedAtNs >= second.LeaseCreatedAtNs || second.LeaseCreatedAtNs >= third.LeaseCreatedAtNs {
		t.Fatalf("generation reused: first=%+v second=%+v third=%+v", first, second, third)
	}
	if current.ExpiryNs != original.ExpiryNs {
		t.Fatal("same-IP rotation extended the TTL")
	}
	if router.DeleteLeaseIfGeneration(plat.ID, "account", a, first.LeaseCreatedAtNs) {
		t.Fatal("old A deleted new A")
	}
}

func TestTargetCooldownForClass_UpperBounds(t *testing.T) {
	cases := []struct {
		name      string
		class     FailureClass
		requested time.Duration
		want      time.Duration
	}{
		{"transport caps ten minutes", FailureTransport, 10 * time.Minute, 30 * time.Second},
		{"transport keeps a shorter request", FailureTransport, 10 * time.Second, 10 * time.Second},
		{"unclassified keeps the request", FailureUnclassified, 10 * time.Minute, 10 * time.Minute},
		{"unknown class keeps the request", FailureClass(99), 2 * time.Minute, 2 * time.Minute},
		{"transport ignores a zero request", FailureTransport, 0, 0},
		{"unclassified ignores a negative request", FailureUnclassified, -time.Second, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := targetCooldownForClass(tc.class, tc.requested); got != tc.want {
				t.Fatalf("targetCooldownForClass(%v, %s) = %s, want %s", tc.class, tc.requested, got, tc.want)
			}
		})
	}
}

func TestRotateLease_RecordsClassSpecificTargetCooldown(t *testing.T) {
	cases := []struct {
		name  string
		class FailureClass
		want  time.Duration
	}{
		{"transport", FailureTransport, 30 * time.Second},
		{"unclassified", FailureUnclassified, 10 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool := newRouterTestPool()
			plat := platform.NewPlatform("p-"+tc.name, "Platform "+tc.name, nil, nil)
			plat.StickyTTLNs = int64(time.Hour)
			pool.addPlatform(plat)
			a, entryA := newRoutableEntry(t, `{"class":"a"}`, "198.51.100.1")
			b, entryB := newRoutableEntry(t, `{"class":"b"}`, "198.51.100.2")
			pool.addEntry(a, entryA)
			pool.addEntry(b, entryB)
			pool.rebuildPlatformView(plat)
			router := newTestRouter(pool, nil)
			initial, err := router.RouteRequest(plat.Name, "account", "example.com")
			if err != nil {
				t.Fatal(err)
			}
			before := time.Now()
			next, _, err := router.RecoverLease(plat.ID, "account", initial.NodeHash, initial.LeaseCreatedAtNs, "example.com",
				RotateLeaseOptions{ExcludeEgressIP: true, PreserveConnections: true, FailureCooldown: 10 * time.Minute, FailureClass: tc.class})
			if err != nil {
				t.Fatalf("recover: %v", err)
			}
			if next == nil || next.NodeHash == initial.NodeHash.Hex() {
				t.Fatalf("rotation did not replace the observed node: %+v", next)
			}
			entry, ok := router.targetCooldowns[targetCooldownKey{plat.ID, "account", "example.com", initial.NodeHash}]
			if !ok {
				t.Fatalf("no target cooldown recorded: %v", router.targetCooldowns)
			}
			remaining := entry.until.Sub(before)
			if remaining < tc.want-time.Second || remaining > tc.want+2*time.Second {
				t.Fatalf("target cooldown ~%s, want ~%s", remaining, tc.want)
			}
		})
	}
}
