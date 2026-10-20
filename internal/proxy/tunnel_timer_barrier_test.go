package proxy

import (
	"testing"
	"time"
)

func TestTunnelFirstByteWatch_StopJoinsInFlightRecovery(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	w := &tunnelFirstByteWatch{timeout: time.Millisecond, onTimeout: func() {
		close(entered)
		<-release
	}}
	w.start()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("timeout callback did not start")
	}
	done := make(chan struct{})
	go func() { w.stop(); close(done) }()
	select {
	case <-done:
		t.Fatal("stop returned while lease recovery was still running")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stop did not join completed lease recovery")
	}
	w.stop() // Repeat stop after an executed callback is safe.
}

func TestTunnelFirstByteWatch_StopBeforeTimeoutNeverRunsRecovery(t *testing.T) {
	w := &tunnelFirstByteWatch{timeout: time.Hour, onTimeout: func() {
		t.Error("stopped timer ran recovery")
	}}
	w.start()
	w.stop()
	w.stop() // A successfully stopped timer must not wait on a nonexistent callback.
	if w.timedOut() {
		t.Fatal("stopped watch reported timeout")
	}
}
