package proxy

import (
	"time"

	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/routing"
)

// HealthRecorder abstracts passive health feedback reporting.
// topology.GlobalNodePool satisfies this interface.
type HealthRecorder interface {
	RecordResult(hash node.Hash, success bool)
	RecordLatency(hash node.Hash, rawTarget string, latency *time.Duration)
}

type passiveHealthRecorder interface {
	RecordPassiveResult(platformID string, hash node.Hash, success bool)
}

type asynchronousHealthRecorder interface {
	recordPassiveResultAsync(route routing.RouteResult, success bool)
	recordLatencyAsync(hash node.Hash, rawTarget string, latency *time.Duration)
}

func recordPassiveResultAsync(health HealthRecorder, route routing.RouteResult, success bool) {
	if health == nil {
		return
	}
	if recorder, ok := health.(asynchronousHealthRecorder); ok {
		recorder.recordPassiveResultAsync(route, success)
		return
	}
	if recorder, ok := health.(passiveHealthRecorder); ok {
		recorder.RecordPassiveResult(route.PlatformID, route.NodeHash, success)
		return
	}
	health.RecordResult(route.NodeHash, success)
}

func recordLatencyAsync(health HealthRecorder, hash node.Hash, rawTarget string, latency *time.Duration) {
	if health == nil {
		return
	}
	if recorder, ok := health.(asynchronousHealthRecorder); ok {
		recorder.recordLatencyAsync(hash, rawTarget, latency)
		return
	}
	health.RecordLatency(hash, rawTarget, latency)
}
