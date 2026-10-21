package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

func TestMaintenanceAdmissionFreezeAndRequestSerialize(t *testing.T) {
	for i := 0; i < 64; i++ {
		m := newMaintenanceController(t.TempDir(), "fixture", true)
		start := make(chan struct{})
		var wg sync.WaitGroup
		var requestErr error
		var frozen bool
		wg.Add(2)
		go func() { defer wg.Done(); <-start; requestErr = m.request() }()
		go func() { defer wg.Done(); <-start; frozen = m.closeAdmission() }()
		close(start)
		wg.Wait()
		if (requestErr == nil) != frozen {
			t.Fatalf("request/frozen disagreement: %v %v", requestErr, frozen)
		}
		if frozen {
			if err := rejectRetainedMaintenance(m.path[:len(m.path)-len("maintenance-handoff.json")]); err == nil {
				t.Fatal("missing restart fence")
			}
		}
	}
}

func TestMaintenancePreAndPostRenameFailures(t *testing.T) {
	for _, installed := range []bool{false, true} {
		m := newMaintenanceController(t.TempDir(), "fixture", true)
		m.install = func(path string, r maintenanceRecord) (bool, error) {
			if installed {
				if err := writeMaintenanceRecord(path, r); err != nil {
					t.Fatal(err)
				}
			}
			return installed, errors.New("fixture fsync failure")
		}
		if err := m.request(); err == nil {
			t.Fatal("failed ack accepted")
		}
		if m.closing != installed || m.isRequested() != installed {
			t.Fatal("rename boundary not respected")
		}
		select {
		case <-m.requested:
			if !installed {
				t.Fatal("unfenced shutdown triggered")
			}
		default:
			if installed {
				t.Fatal("fenced failure not delivered")
			}
		}
		if installed {
			if err := m.phase("complete"); err == nil {
				t.Fatal("failed durability certified")
			}
		} else {
			if _, err := os.Stat(m.path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("pre-rename marker created")
			}
		}
	}
	m := newMaintenanceController(t.TempDir()+"/absent", "fixture", true)
	if err := m.request(); err == nil || m.isRequested() {
		t.Fatal("actual CreateTemp failure triggered shutdown")
	}
}

func TestMaintenanceDeadlineReturnsWithoutClosingOwnedSources(t *testing.T) {
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unlock := func() { once.Do(func() { close(release) }) }
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := waitShutdownDeadline(ctx, func() error { close(entered); <-release; close(done); return nil })
	<-entered
	if !errors.Is(err, errShutdownOwnershipRetained) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline = %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("deadline wait unbounded")
	}
	select {
	case <-done:
		t.Fatal("source incorrectly considered stopped")
	default:
	}
	unlock()
	<-done
}

func TestMaintenanceTimeoutFailedAndEveryRetainedPhaseBlocks(t *testing.T) {
	m := newMaintenanceController(t.TempDir(), "fixture", true)
	if err := m.request(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go m.timeoutFailure(ctx, make(chan struct{}), done)
	<-done
	var r maintenanceRecord
	body, err := os.ReadFile(m.path)
	if err != nil || json.Unmarshal(body, &r) != nil || r.Phase != "failed" {
		t.Fatal("timeout did not persist failure")
	}
	if err := m.phase("complete"); err == nil {
		t.Fatal("timed out source certified")
	}
	for _, phase := range []string{"requested", "draining", "sources_stopped", "persisted", "complete", "failed"} {
		dir := t.TempDir()
		if err := writeMaintenanceRecord(maintenanceMarker(dir), maintenanceRecord{Phase: phase}); err != nil {
			t.Fatal(err)
		}
		if err := rejectRetainedMaintenance(dir); err == nil {
			t.Fatalf("retained %s bootstrapped", phase)
		}
	}
}
