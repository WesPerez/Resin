package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/proxy"
	"github.com/Resinat/Resin/internal/state"
	"github.com/Resinat/Resin/internal/topology"
	"os"
	"os/exec"
	"path/filepath"
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

func TestRunCloseDecisionRetainsDeadlineAndFlushFailureWithoutBarrierOrClose(t *testing.T) {
	for _, maintenance := range []bool{false, true} {
		for _, failure := range []error{errShutdownOwnershipRetained, errShutdownPersistenceRetained} {
			retained := false
			err := closeShutdownDatabases(context.Background(), maintenance, nil, failure,
				func() error { t.Fatal("retained writer barrier evaluated"); return nil },
				func() error { t.Fatal("retained DB closed"); return nil }, func() { retained = true })
			if err == nil || !retained {
				t.Fatal("retained shutdown succeeded")
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := closeShutdownDatabases(ctx, true, nil, nil, func() error { t.Fatal("expired barrier evaluated"); return nil }, func() error { t.Fatal("expired DB closed"); return nil }, func() {}); err == nil {
		t.Fatal("expired close succeeded")
	}
	closed := false
	if err := closeShutdownDatabases(context.Background(), true, nil, nil, func() error { return nil }, func() error { closed = true; return nil }, func() { t.Fatal("healthy source retained") }); err != nil || !closed {
		t.Fatal("healthy close not called")
	}
}

func TestFinalMaintenanceAndTimeoutWriterJoinedBeforeComplete(t *testing.T) {
	for i := 0; i < 32; i++ {
		a, _, paths := maintenanceLeaseFixture(t)
		if err := a.maintenance.request(); err != nil {
			t.Fatal(err)
		}
		if err := a.verifyMaintenanceLeases(); err != nil {
			t.Fatal(err)
		}
		a.engine.SealStrongWrites()
		a.engine.SealWeakWrites()
		a.topoRuntime.scheduler = topology.NewSubscriptionScheduler(topology.SchedulerConfig{})
		a.topoRuntime.scheduler.Stop()
		a.healthFeedback = proxy.NewHealthFeedbackBarrier(nil)
		if err := a.healthFeedback.StopAndWait(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := a.maintenance.phase("persisted"); err != nil {
			t.Fatal(err)
		}
		a.maintenance.record.Databases = []maintenanceDatabase{{Path: paths[0]}, {Path: paths[1]}}
		ctx, cancel := context.WithCancel(context.Background())
		stopped, done := make(chan struct{}), make(chan struct{})
		go a.maintenance.timeoutFailure(ctx, stopped, done)
		if i%2 == 0 {
			cancel()
		}
		close(stopped)
		<-done // actual owner ordering, no post-complete watcher
		err := a.finalizeMaintenance(ctx)
		if i%2 == 0 && err == nil {
			t.Fatal("timeout produced success")
		}
		if i%2 != 0 && err != nil {
			t.Fatal(err)
		}
		cancel()
		if err == nil {
			// Each registration/dirty source has an invalidation latch.
			switch i % 3 {
			case 0:
				a.engine.MarkLease("p", "late")
			case 1:
				_ = a.topoRuntime.scheduler.UpdateSubscriptionAsync(nil)
			case 2:
				a.healthFeedback.RecordResult(node.Hash{}, true)
			}
			var r maintenanceRecord
			body, _ := os.ReadFile(a.maintenance.path)
			if json.Unmarshal(body, &r) != nil || r.Phase != "failed" {
				t.Fatal("late source left complete certificate")
			}
		}
	}
}

func TestMaintenanceInterruptedOwnerNeverCertifiesOrReopens(t *testing.T) {
	if dir := os.Getenv("RESIN_BARRIER_FIXTURE_DIR"); dir != "" {
		e, closer, err := state.PersistenceBootstrap(filepath.Join(dir, "state"), filepath.Join(dir, "cache"))
		if err != nil {
			os.Exit(21)
		}
		m := newMaintenanceController(filepath.Join(dir, "state"), "fixture", true)
		if err := m.request(); err != nil {
			os.Exit(22)
		}
		e.MarkLease("fixture", "pending") // intentionally only in memory, not claimed durable
		_ = closeShutdownDatabases(context.Background(), true, nil, errShutdownPersistenceRetained,
			func() error { os.Exit(23); return nil }, closer.Close, func() {
				if err := m.phase("failed"); err != nil {
					os.Exit(24)
				}
				select {}
			})
		os.Exit(25)
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestMaintenanceInterruptedOwnerNeverCertifiesOrReopens$")
	cmd.Env = append(os.Environ(), "RESIN_BARRIER_FIXTURE_DIR="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	marker := maintenanceMarker(filepath.Join(dir, "state"))
	deadline := time.Now().Add(5 * time.Second)
	for {
		var record maintenanceRecord
		body, err := os.ReadFile(marker)
		if err == nil && json.Unmarshal(body, &record) == nil && record.Phase == "failed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not retain failed owner")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("interrupted owner exited successfully")
	}
	if err := rejectRetainedMaintenance(filepath.Join(dir, "state")); err == nil {
		t.Fatal("interruption reopened fenced source")
	}
	// Both already-committed DBs remain read-only recoverable after interruption;
	// the deliberately unflushed dirty mark is NOT a zero-loss promise.
	for _, path := range []string{filepath.Join(dir, "state", "state.db"), filepath.Join(dir, "cache", "cache.db")} {
		db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
		if err != nil {
			t.Fatal(err)
		}
		var check string
		err = db.QueryRow("PRAGMA quick_check").Scan(&check)
		_ = db.Close()
		if err != nil || check != "ok" {
			t.Fatal("committed SQLite not recoverable")
		}
	}
}
