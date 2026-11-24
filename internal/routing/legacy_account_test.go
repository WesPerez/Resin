package routing

import (
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/platform"
)

func TestLegacyAccountMetadataDoesNotRestrictRouting(t *testing.T) {
	pool := newRouterTestPool()
	plat := platform.NewPlatform("p", "Platform", nil, nil)
	plat.StickyTTLNs = int64(time.Hour)
	pool.addPlatform(plat)
	h, e := newRoutableEntry(t, `{"node":"a"}`, "198.51.100.1")
	pool.addEntry(h, e)
	pool.rebuildPlatformView(plat)
	router := newTestRouter(pool, nil)
	original, err := router.RouteRequest(plat.Name, "alice", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"old~1~0~old-ip", "different~version~1020000~changed-ip", ""} {
		route, err := router.RouteRequest(plat.Name, "alice~r1~"+suffix, "example.com")
		if err != nil || route.NodeHash != original.NodeHash || route.LeaseCreatedAtNs != original.LeaseCreatedAtNs || route.LeaseAccount != "alice" {
			t.Fatalf("legacy alias rejected: %+v %v", route, err)
		}
	}
	if alias := router.ReadLease(model.LeaseKey{PlatformID: plat.ID, Account: "alice~r1~"}); alias == nil || alias.Account != "alice" {
		t.Fatal("legacy read did not use the base account")
	}
	other, err := router.RouteRequest(plat.Name, "bob~r1~old", "example.com")
	if err != nil || other.LeaseAccount != "bob" || other.LeaseCreatedAtNs == original.LeaseCreatedAtNs {
		t.Fatal("account isolation lost")
	}
	pool.removeEntry(h)
	h2, e2 := newRoutableEntry(t, `{"node":"b"}`, "198.51.100.2")
	pool.addEntry(h2, e2)
	pool.rebuildPlatformView(plat)
	next, err := router.RouteRequest(plat.Name, "alice~r1~old-node~1~0~old-ip", "example.com")
	if err != nil || next.NodeHash != h2 || next.LeaseCreatedAtNs <= original.LeaseCreatedAtNs {
		t.Fatalf("normal replacement blocked: %+v %v", next, err)
	}
}
