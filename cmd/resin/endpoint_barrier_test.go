package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/model"
)

func TestEndpointManager_ShutdownJoinsAlreadyRemovedRuntime(t *testing.T) {
	port := reserveTestPorts(t, 1)[0]
	m := newEndpointRuntimeManager("127.0.0.1", "", nil, nil, nil, nil, nil, nil)
	if err := m.ApplyEndpoint(model.Endpoint{ID: "removed", Port: port}); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	runtime := m.runtimes["removed"]
	// A stopped listener does not imply that its last handler/worker ended.
	runtime.server.workerWG.Add(1)
	m.mu.Unlock()
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(runtime.server.workerWG.Done) }
	t.Cleanup(func() { release(); _ = m.Shutdown(context.Background(), false) })
	m.RemoveEndpoint("removed")
	done := make(chan error, 1)
	go func() { done <- m.Shutdown(context.Background(), false) }()
	select {
	case err := <-done:
		t.Fatalf("shutdown ignored retired worker: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("retired runtime was not joined")
	}
}

func TestEndpointManager_ShutdownDoesNotSwallowDrainTimeout(t *testing.T) {
	port := reserveTestPorts(t, 1)[0]
	m := newEndpointRuntimeManager("127.0.0.1", "", nil, nil, nil, nil, nil, nil)
	if err := m.ApplyEndpoint(model.Endpoint{ID: "timeout", Port: port}); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	runtime := m.runtimes["timeout"]
	runtime.server.workerWG.Add(1)
	m.mu.Unlock()
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(runtime.server.workerWG.Done) }
	t.Cleanup(func() { release(); _ = m.Shutdown(context.Background(), false) })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := m.Shutdown(ctx, true)
	release()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline lost: %v", err)
	}
}

func TestEndpointManager_RetiredSourceRespectsDeadlineAndCanLaterQuiesce(t *testing.T) {
	m := newEndpointRuntimeManager("127.0.0.1", "", nil, nil, nil, nil, nil, nil)
	m.retirementWG.Add(1)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(m.retirementWG.Done) }
	t.Cleanup(func() { release(); _ = m.Shutdown(context.Background(), false) })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := m.Shutdown(ctx, false); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pending retired endpoint did not fail the deadline: %v", err)
	}
	release()
	if err := m.Shutdown(context.Background(), false); err != nil {
		t.Fatalf("completed retirement permanently poisoned shutdown: %v", err)
	}
	if err := m.ApplyEndpoint(model.Endpoint{ID: "late", Port: 0}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("endpoint was not rejected after shutdown: %v", err)
	}
}

func TestEndpointManager_SafetyJoinReportsLateServeErrorOnce(t *testing.T) {
	m := newEndpointRuntimeManager("127.0.0.1", "", nil, nil, nil, nil, nil, nil)
	m.retirementWG.Add(1)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(m.retirementWG.Done) }
	t.Cleanup(func() { release(); _ = m.Shutdown(context.Background(), false) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.Shutdown(ctx, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("pending source did not report deadline: %v", err)
	}
	want := errors.New("late retired serve failure")
	runtime := &managedEndpointRuntime{}
	runtime.config.Store(&model.Endpoint{ID: "retired"})
	m.handleRuntimeError(runtime, want)
	release()
	if err := m.WaitQuiescent(); !errors.Is(err, want) {
		t.Fatalf("safety join swallowed late source failure: %v", err)
	}
	if err := m.WaitQuiescent(); err != nil {
		t.Fatalf("source failure reported twice: %v", err)
	}
	if err := m.Shutdown(context.Background(), false); err != nil {
		t.Fatalf("archived error poisoned later shutdown: %v", err)
	}
}

func TestEndpointManager_CanceledContextAndReadySourcesCannotLoseError(t *testing.T) {
	for i := 0; i < 32; i++ {
		m := newEndpointRuntimeManager("127.0.0.1", "", nil, nil, nil, nil, nil, nil)
		want := errors.New("ready source failure")
		m.mu.Lock()
		m.sourceErr = want
		m.mu.Unlock()
		// Freeze both select arms ready without creating an unowned source.
		m.sourcesOnce.Do(func() { close(m.sourcesDone) })
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := errors.Join(m.Shutdown(ctx, false), m.WaitQuiescent())
		if !errors.Is(err, want) {
			t.Fatalf("ready source failure lost to cancellation: %v", err)
		}
		if err := m.WaitQuiescent(); err != nil {
			t.Fatalf("source failure was not consumed: %v", err)
		}
	}
}
