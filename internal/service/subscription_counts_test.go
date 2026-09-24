package service

import (
	"testing"

	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/subscription"
)

func TestSubscriptionResponseReportsLiveManagedAndEvictedCounts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		active  int
		evicted int
	}{
		{"empty", true, 0, 0},
		{"mixed", true, 2, 1},
		{"all evicted", true, 0, 3},
		{"disabled", false, 2, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sub := subscription.NewSubscription("counts", "counts", "https://example.invalid/sub", tc.enabled, false)
			for i := range tc.active + tc.evicted {
				h := node.HashFromRawOptions([]byte{byte(i)})
				sub.ManagedNodes().StoreNode(h, subscription.ManagedNode{Evicted: i >= tc.active})
			}
			response := (&ControlPlaneService{}).subToResponse(sub)
			if response.NodeCount != tc.active || response.EvictedNodeCount != tc.evicted ||
				response.ManagedNodeCount != tc.active+tc.evicted || response.HealthyNodeCount != 0 {
				t.Fatalf("unexpected counts: %+v", response)
			}
		})
	}
}
