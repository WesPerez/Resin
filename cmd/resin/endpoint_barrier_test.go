package main

import (
	"context"
	"errors"
	"net"
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
	m.RemoveEndpoint("removed")
	done := make(chan error, 1)
	go func() { done <- m.Shutdown(context.Background(), false) }()
	select {
	case err := <-done:
		t.Fatalf("shutdown ignored retired worker: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	runtime.server.workerWG.Done()
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := m.Shutdown(ctx, true)
	runtime.server.workerWG.Done()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline lost: %v", err)
	}
}

func TestEndpointManager_RetiredSourceRespectsDeadlineAndCanLaterQuiesce(t *testing.T) {
	m := newEndpointRuntimeManager("127.0.0.1", "", nil, nil, nil, nil, nil, nil)
	m.retirementWG.Add(1)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := m.Shutdown(ctx, false); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pending retired endpoint did not fail the deadline: %v", err)
	}
	m.retirementWG.Done()
	if err := m.Shutdown(context.Background(), false); err != nil {
		t.Fatalf("completed retirement permanently poisoned shutdown: %v", err)
	}
	if err := m.ApplyEndpoint(model.Endpoint{ID: "late", Port: 0}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("endpoint was not rejected after shutdown: %v", err)
	}
}
