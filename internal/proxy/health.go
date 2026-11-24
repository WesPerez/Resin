package proxy

import (
	"context"
	"errors"
	"time"

	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/routing"
)

// Feedback always identifies the exact outbound mode used by the request.
type HealthRecorder interface {
	ApplyFeedback(node.Hash, uint64, node.Feedback) bool
}

func recordPassiveResultAsync(health HealthRecorder, route routing.RouteResult, success bool, relay node.RelayInfo) {
	if health != nil {
		dispatchHealthFeedback(health, route.NodeHash, route.NodeVersion, node.Feedback{Result: &success, PlatformID: route.PlatformID, Relay: relay})
	}
}
func recordPassiveFailureAsync(health HealthRecorder, route routing.RouteResult, err error, relay node.RelayInfo) {
	if health != nil && !errors.Is(err, routing.ErrNoAvailableRelay) && !errors.Is(err, context.Canceled) {
		failed := false
		dispatchHealthFeedback(health, route.NodeHash, route.NodeVersion, node.Feedback{Result: &failed, Err: err, PlatformID: route.PlatformID, Relay: relay})
	}
}
func recordLatencyForVersion(health HealthRecorder, hash node.Hash, version uint64, domain string, latency *time.Duration) {
	if health != nil {
		dispatchHealthFeedback(health, hash, version, node.Feedback{Target: domain, Latency: latency})
	}
}

// Register with a drain barrier on the handler before launching any writer.
func dispatchHealthFeedback(health HealthRecorder, hash node.Hash, version uint64, feedback node.Feedback) {
	if b, ok := health.(*HealthFeedbackBarrier); ok {
		b.applyFeedbackAsync(hash, version, feedback)
		return
	}
	go health.ApplyFeedback(hash, version, feedback)
}
