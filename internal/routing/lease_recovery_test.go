package routing_test

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/routing"
)

func TestRotateLease_CASSuccessAndStale(t *testing.T) {
	pool, subMgr := setupPool(t)
	h1 := makeRoutableNode(t, pool, subMgr, `{"rotate":"1"}`, "198.51.100.1", "cloudflare.com", 20*time.Millisecond)
	h2 := makeRoutableNode(t, pool, subMgr, `{"rotate":"2"}`, "198.51.100.2", "cloudflare.com", 30*time.Millisecond)

	var events []routing.LeaseEvent
	router := makeRouter(pool, &events)

	res1, err := router.RouteRequest(platName, "acct-cas", "cloudflare.com")
	if err != nil {
		t.Fatalf("initial route failed: %v", err)
	}
	wrongHash := h1
	if res1.NodeHash == h1 {
		wrongHash = h2
	}
	_, _, err = router.RotateLease(platID, "acct-cas", wrongHash, res1.LeaseCreatedAtNs, "cloudflare.com", routing.RotateLeaseOptions{})
	if !errors.Is(err, routing.ErrLeaseChanged) {
		t.Fatalf("expected ErrLeaseChanged on wrong node hash, got %v", err)
	}

	_, _, err = router.RotateLease(platID, "acct-cas", res1.NodeHash, res1.LeaseCreatedAtNs+100, "cloudflare.com", routing.RotateLeaseOptions{})
	if !errors.Is(err, routing.ErrLeaseChanged) {
		t.Fatalf("expected ErrLeaseChanged on wrong createdAtNs, got %v", err)
	}

	newLease, closedCount, err := router.RotateLease(platID, "acct-cas", res1.NodeHash, res1.LeaseCreatedAtNs, "cloudflare.com", routing.RotateLeaseOptions{})
	if err != nil {
		t.Fatalf("rotate failed: %v", err)
	}
	if newLease.NodeHash == res1.NodeHash.Hex() {
		t.Fatalf("expected rotation away from initial node %s", res1.NodeHash.Hex())
	}
	if closedCount != 0 {
		t.Fatalf("expected 0 active connections closed, got %d", closedCount)
	}
	if newLease.CreatedAtNs <= res1.LeaseCreatedAtNs {
		t.Fatalf("expected new lease createdAtNs (%d) > original (%d)", newLease.CreatedAtNs, res1.LeaseCreatedAtNs)
	}
}

func TestDeleteLeaseIfGeneration_DoesNotDeleteReusedNode(t *testing.T) {
	pool, subMgr := setupPool(t)
	h := makeRoutableNode(t, pool, subMgr, `{"generation-delete":"1"}`, "198.51.100.1", "cloudflare.com", 10*time.Millisecond)
	router := makeRouter(pool, nil)
	first, err := router.RouteRequest(platName, "acct-generation-delete", "cloudflare.com")
	if err != nil {
		t.Fatalf("initial route failed: %v", err)
	}
	now := time.Now().UnixNano()
	newGeneration := model.Lease{
		PlatformID: platID, Account: "acct-generation-delete", NodeHash: h.Hex(), EgressIP: "198.51.100.1",
		CreatedAtNs: max(now, first.LeaseCreatedAtNs+1), ExpiryNs: now + int64(time.Hour), LastAccessedNs: now,
	}
	if err := router.UpsertLease(newGeneration); err != nil {
		t.Fatalf("upsert new generation: %v", err)
	}
	if router.DeleteLeaseIfGeneration(platID, "acct-generation-delete", h, first.LeaseCreatedAtNs) {
		t.Fatal("stale generation deleted a later lease on the same node")
	}
	got := router.ReadLease(model.LeaseKey{PlatformID: platID, Account: "acct-generation-delete"})
	if got == nil || got.CreatedAtNs != newGeneration.CreatedAtNs {
		t.Fatalf("new generation changed: got=%+v want=%+v", got, newGeneration)
	}
}

func TestRotateLease_ExcludesOldNodeAndEgressIP(t *testing.T) {
	pool, subMgr := setupPool(t)
	h1 := makeRoutableNode(t, pool, subMgr, `{"node":"1"}`, "198.51.100.10", "cloudflare.com", 10*time.Millisecond)
	makeRoutableNode(t, pool, subMgr, `{"node":"2"}`, "198.51.100.10", "cloudflare.com", 20*time.Millisecond)
	h3 := makeRoutableNode(t, pool, subMgr, `{"node":"3"}`, "198.51.100.20", "cloudflare.com", 50*time.Millisecond)

	router := makeRouter(pool, nil)
	now := time.Now().UnixNano()
	if err := router.UpsertLease(model.Lease{
		PlatformID: platID, Account: "acct-egress", NodeHash: h1.Hex(), EgressIP: "198.51.100.10",
		CreatedAtNs: now, ExpiryNs: now + int64(time.Hour), LastAccessedNs: now,
	}); err != nil {
		t.Fatalf("seed initial lease: %v", err)
	}
	res, err := router.RouteRequest(platName, "acct-egress", "cloudflare.com")
	if err != nil {
		t.Fatalf("initial route failed: %v", err)
	}
	if res.NodeHash != h1 {
		t.Fatalf("expected initial node with egress IP 198.51.100.10, got %s", res.NodeHash.Hex())
	}

	newLease, _, err := router.RotateLease(platID, "acct-egress", res.NodeHash, res.LeaseCreatedAtNs, "cloudflare.com", routing.RotateLeaseOptions{ExcludeEgressIP: true})
	if err != nil {
		t.Fatalf("rotate failed: %v", err)
	}
	if newLease.NodeHash != h3.Hex() {
		t.Fatalf("expected rotation to pick node 3 (%s) with different egress IP, got %s", h3.Hex(), newLease.NodeHash)
	}
	if newLease.EgressIP != "198.51.100.20" {
		t.Fatalf("expected new egress IP 198.51.100.20, got %s", newLease.EgressIP)
	}
}

func TestRotateLease_NoAlternativeRetainsOriginalLease(t *testing.T) {
	pool, subMgr := setupPool(t)
	h1 := makeRoutableNode(t, pool, subMgr, `{"single":"only"}`, "198.51.100.99", "cloudflare.com", 10*time.Millisecond)

	router := makeRouter(pool, nil)
	res, err := router.RouteRequest(platName, "acct-single", "cloudflare.com")
	if err != nil {
		t.Fatalf("initial route failed: %v", err)
	}

	_, _, err = router.RotateLease(platID, "acct-single", h1, res.LeaseCreatedAtNs, "cloudflare.com", routing.RotateLeaseOptions{})
	if !errors.Is(err, routing.ErrNoAvailableNodes) {
		t.Fatalf("expected ErrNoAvailableNodes, got %v", err)
	}

	read := router.ReadLease(model.LeaseKey{PlatformID: platID, Account: "acct-single"})
	if read == nil {
		t.Fatal("expected original lease to be retained, got nil")
	}
	if read.NodeHash != h1.Hex() || read.CreatedAtNs != res.LeaseCreatedAtNs {
		t.Fatalf("original lease mutated: node=%s createdAtNs=%d", read.NodeHash, read.CreatedAtNs)
	}
	snapshot := router.SnapshotIPLoad(platID)
	if got := snapshot[netip.MustParseAddr("198.51.100.99")]; got != 1 {
		t.Fatalf("original IP load changed after failed rotation: got %d, want 1; snapshot=%v", got, snapshot)
	}
}

func TestRotateLease_IPLoadStatsAndActiveTunnelClosed(t *testing.T) {
	pool, subMgr := setupPool(t)
	_ = makeRoutableNode(t, pool, subMgr, `{"load":"1"}`, "198.51.100.1", "cloudflare.com", 10*time.Millisecond)
	makeRoutableNode(t, pool, subMgr, `{"load":"2"}`, "198.51.100.2", "cloudflare.com", 20*time.Millisecond)

	router := makeRouter(pool, nil)
	res, err := router.RouteRequest(platName, "acct-load", "cloudflare.com")
	if err != nil {
		t.Fatalf("initial route failed: %v", err)
	}

	initialIP := res.EgressIP
	otherIP := netip.MustParseAddr("198.51.100.1")
	if initialIP == otherIP {
		otherIP = netip.MustParseAddr("198.51.100.2")
	}
	snap1 := router.SnapshotIPLoad(platID)
	if snap1[initialIP] != 1 || snap1[otherIP] != 0 {
		t.Fatalf("unexpected initial ip loads: %v", snap1)
	}

	var closed atomic.Bool
	unregister, ok := router.RegisterLeaseConnection(res, "acct-load", func() {
		closed.Store(true)
	})
	if !ok {
		t.Fatal("failed to register lease connection")
	}
	defer unregister()

	_, closedCount, err := router.RotateLease(platID, "acct-load", res.NodeHash, res.LeaseCreatedAtNs, "cloudflare.com", routing.RotateLeaseOptions{})
	if err != nil {
		t.Fatalf("rotate failed: %v", err)
	}
	if closedCount != 1 {
		t.Fatalf("expected 1 closed connection, got %d", closedCount)
	}
	if !closed.Load() {
		t.Fatal("registered connection close callback was not invoked")
	}

	snap2 := router.SnapshotIPLoad(platID)
	if snap2[initialIP] != 0 || snap2[otherIP] != 1 {
		t.Fatalf("unexpected updated ip loads: %v", snap2)
	}
}

func TestRegisterLeaseConnection_RejectsLateRegistration(t *testing.T) {
	pool, subMgr := setupPool(t)
	_ = makeRoutableNode(t, pool, subMgr, `{"late":"1"}`, "198.51.100.1", "cloudflare.com", 10*time.Millisecond)
	_ = makeRoutableNode(t, pool, subMgr, `{"late":"2"}`, "198.51.100.2", "cloudflare.com", 20*time.Millisecond)

	router := makeRouter(pool, nil)
	res, err := router.RouteRequest(platName, "acct-late", "cloudflare.com")
	if err != nil {
		t.Fatalf("initial route failed: %v", err)
	}

	_, _, err = router.RotateLease(platID, "acct-late", res.NodeHash, res.LeaseCreatedAtNs, "cloudflare.com", routing.RotateLeaseOptions{})
	if err != nil {
		t.Fatalf("rotate failed: %v", err)
	}

	var closed atomic.Bool
	_, ok := router.RegisterLeaseConnection(res, "acct-late", func() { closed.Store(true) })
	if ok {
		t.Fatal("expected late connection registration with stale lease to be rejected")
	}
	if closed.Load() {
		t.Fatal("router invoked the rejected registration callback; caller owns late-connection close")
	}
}

func TestRotateLease_PreservesEstablishedConnections(t *testing.T) {
	pool, subMgr := setupPool(t)
	makeRoutableNode(t, pool, subMgr, `{"preserve":"1"}`, "198.51.100.1", "cloudflare.com", 10*time.Millisecond)
	makeRoutableNode(t, pool, subMgr, `{"preserve":"2"}`, "198.51.100.2", "cloudflare.com", 20*time.Millisecond)
	router := makeRouter(pool, nil)
	before, err := router.RouteRequest(platName, "acct-preserve", "cloudflare.com")
	if err != nil {
		t.Fatal(err)
	}
	var closed atomic.Int32
	for range 3 {
		unregister, ok := router.RegisterLeaseConnection(before, "acct-preserve", func() { closed.Add(1) })
		if !ok {
			t.Fatal("register established connection")
		}
		defer unregister()
	}
	lease, count, err := router.RotateLease(platID, "acct-preserve", before.NodeHash, before.LeaseCreatedAtNs,
		"cloudflare.com", routing.RotateLeaseOptions{ExcludeEgressIP: true, PreserveConnections: true})
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 || closed.Load() != 0 {
		t.Fatalf("rotation aborted established connections: count=%d closed=%d", count, closed.Load())
	}
	after, err := router.RouteRequest(platName, "acct-preserve", "cloudflare.com")
	if err != nil || after.NodeHash.Hex() != lease.NodeHash || after.NodeHash == before.NodeHash || after.EgressIP == before.EgressIP {
		t.Fatalf("new route must use replacement node and IP: before=%+v after=%+v err=%v", before, after, err)
	}
	if _, ok := router.RegisterLeaseConnection(before, "acct-preserve", func() { closed.Add(1) }); ok {
		t.Fatal("late dial registered on replaced lease")
	}
	if router.DeleteLeaseIfGeneration(platID, "acct-preserve", before.NodeHash, before.LeaseCreatedAtNs) {
		t.Fatal("old connection failure deleted replacement lease")
	}
	var newClosed atomic.Bool
	unregister, ok := router.RegisterLeaseConnection(after, "acct-preserve", func() { newClosed.Store(true) })
	if !ok {
		t.Fatal("register replacement connection")
	}
	defer unregister()
	_, count, err = router.RotateLease(platID, "acct-preserve", after.NodeHash, after.LeaseCreatedAtNs,
		"cloudflare.com", routing.RotateLeaseOptions{})
	if err != nil || count != 1 || !newClosed.Load() || closed.Load() != 0 {
		t.Fatalf("later forced rotation crossed generations: count=%d oldClosed=%d newClosed=%v err=%v", count, closed.Load(), newClosed.Load(), err)
	}
}

func TestRotateLease_PreservesConcurrentTransfers(t *testing.T) {
	pool, subMgr := setupPool(t)
	makeRoutableNode(t, pool, subMgr, `{"transfer":"1"}`, "198.51.100.1", "cloudflare.com", 10*time.Millisecond)
	makeRoutableNode(t, pool, subMgr, `{"transfer":"2"}`, "198.51.100.2", "cloudflare.com", 20*time.Millisecond)
	router := makeRouter(pool, nil)
	before, err := router.RouteRequest(platName, "acct-transfer", "cloudflare.com")
	if err != nil {
		t.Fatal(err)
	}
	const count = 3
	peers := make([]net.Conn, 0, count)
	ready := make(chan struct{}, count)
	finished := make(chan error, count)
	for range count {
		connection, peer := net.Pipe()
		t.Cleanup(func() { connection.Close(); peer.Close() })
		if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		unregister, ok := router.RegisterLeaseConnection(before, "acct-transfer", func() { connection.Close() })
		if !ok {
			t.Fatal("register transfer connection")
		}
		t.Cleanup(unregister)
		peers = append(peers, peer)
		go func() {
			ready <- struct{}{}
			_, err := connection.Write([]byte("in-flight"))
			finished <- err
		}()
	}
	for range count {
		<-ready
	}
	// Pipe writes remain in flight until their peers read after the rotation.
	_, closed, err := router.RotateLease(platID, "acct-transfer", before.NodeHash, before.LeaseCreatedAtNs,
		"cloudflare.com", routing.RotateLeaseOptions{ExcludeEgressIP: true, PreserveConnections: true})
	if err != nil || closed != 0 {
		t.Fatalf("rotation: closed=%d err=%v", closed, err)
	}
	for _, peer := range peers {
		data := make([]byte, len("in-flight"))
		if _, err := io.ReadFull(peer, data); err != nil || string(data) != "in-flight" {
			t.Fatalf("transfer interrupted: data=%q err=%v", data, err)
		}
	}
	for range count {
		if err := <-finished; err != nil {
			t.Fatalf("in-flight write failed: %v", err)
		}
	}
}

func TestRotateLease_ClosesOnlyExpectedGeneration(t *testing.T) {
	pool, subMgr := setupPool(t)
	_ = makeRoutableNode(t, pool, subMgr, `{"generation":"1"}`, "198.51.100.1", "cloudflare.com", 10*time.Millisecond)
	_ = makeRoutableNode(t, pool, subMgr, `{"generation":"2"}`, "198.51.100.2", "cloudflare.com", 20*time.Millisecond)
	router := makeRouter(pool, nil)
	oldRoute, err := router.RouteRequest(platName, "acct-generation", "cloudflare.com")
	if err != nil {
		t.Fatalf("initial route failed: %v", err)
	}
	var oldClosed atomic.Bool
	oldUnregister, ok := router.RegisterLeaseConnection(oldRoute, "acct-generation", func() { oldClosed.Store(true) })
	if !ok {
		t.Fatal("failed to register old generation")
	}
	defer oldUnregister()
	newLease, _, err := router.RotateLease(platID, "acct-generation", oldRoute.NodeHash, oldRoute.LeaseCreatedAtNs, "cloudflare.com", routing.RotateLeaseOptions{})
	if err != nil {
		t.Fatalf("first rotate failed: %v", err)
	}
	newHash, err := node.ParseHex(newLease.NodeHash)
	if err != nil {
		t.Fatalf("parse new hash: %v", err)
	}
	newRoute := routing.RouteResult{PlatformID: platID, NodeHash: newHash, LeaseCreatedAtNs: newLease.CreatedAtNs}
	var newClosed atomic.Bool
	newUnregister, ok := router.RegisterLeaseConnection(newRoute, "acct-generation", func() { newClosed.Store(true) })
	if !ok {
		t.Fatal("failed to register new generation")
	}
	defer newUnregister()
	if !oldClosed.Load() {
		t.Fatal("old generation was not closed")
	}
	if newClosed.Load() {
		t.Fatal("new generation was closed by old rotation")
	}
}

func TestRotateLease_CloseCallbackRunsOutsideRecoveryLock(t *testing.T) {
	pool, subMgr := setupPool(t)
	_ = makeRoutableNode(t, pool, subMgr, `{"callback":"1"}`, "198.51.100.1", "cloudflare.com", 10*time.Millisecond)
	_ = makeRoutableNode(t, pool, subMgr, `{"callback":"2"}`, "198.51.100.2", "cloudflare.com", 20*time.Millisecond)
	router := makeRouter(pool, nil)
	res, err := router.RouteRequest(platName, "acct-callback", "cloudflare.com")
	if err != nil {
		t.Fatalf("initial route failed: %v", err)
	}
	callbackDone := make(chan struct{})
	unregister, ok := router.RegisterLeaseConnection(res, "acct-callback", func() {
		_, _ = router.RouteRequest(platName, "acct-callback", "cloudflare.com")
		close(callbackDone)
	})
	if !ok {
		t.Fatal("failed to register connection")
	}
	defer unregister()
	rotateDone := make(chan error, 1)
	go func() {
		_, _, rotateErr := router.RotateLease(platID, "acct-callback", res.NodeHash, res.LeaseCreatedAtNs, "cloudflare.com", routing.RotateLeaseOptions{})
		rotateDone <- rotateErr
	}()
	select {
	case err := <-rotateDone:
		if err != nil {
			t.Fatalf("rotate failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("rotate deadlocked while invoking close callback")
	}
	select {
	case <-callbackDone:
	default:
		t.Fatal("close callback did not complete")
	}
}

func TestRotateLease_EventCallbackRunsOutsideRecoveryLock(t *testing.T) {
	pool, subMgr := setupPool(t)
	_ = makeRoutableNode(t, pool, subMgr, `{"event-callback":"1"}`, "198.51.100.1", "cloudflare.com", 10*time.Millisecond)
	_ = makeRoutableNode(t, pool, subMgr, `{"event-callback":"2"}`, "198.51.100.2", "cloudflare.com", 20*time.Millisecond)
	var router *routing.Router
	eventDone := make(chan struct{}, 1)
	router = routing.NewRouter(routing.RouterConfig{
		Pool:        pool,
		Authorities: func() []string { return []string{"cloudflare.com"} },
		P2CWindow:   func() time.Duration { return 10 * time.Minute },
		OnLeaseEvent: func(event routing.LeaseEvent) {
			if event.Type != routing.LeaseReplace {
				return
			}
			_, _ = router.RouteRequest(platName, "acct-event-callback", "cloudflare.com")
			eventDone <- struct{}{}
		},
	})
	res, err := router.RouteRequest(platName, "acct-event-callback", "cloudflare.com")
	if err != nil {
		t.Fatalf("initial route failed: %v", err)
	}
	rotateDone := make(chan error, 1)
	go func() {
		_, _, rotateErr := router.RotateLease(platID, "acct-event-callback", res.NodeHash, res.LeaseCreatedAtNs, "cloudflare.com", routing.RotateLeaseOptions{})
		rotateDone <- rotateErr
	}()
	select {
	case err := <-rotateDone:
		if err != nil {
			t.Fatalf("rotate failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("rotate deadlocked while invoking lease event callback")
	}
	select {
	case <-eventDone:
	default:
		t.Fatal("lease event callback did not complete")
	}
}

func TestRotateLease_ConcurrentReplay(t *testing.T) {
	pool, subMgr := setupPool(t)
	_ = makeRoutableNode(t, pool, subMgr, `{"conc":"1"}`, "198.51.100.1", "cloudflare.com", 10*time.Millisecond)
	_ = makeRoutableNode(t, pool, subMgr, `{"conc":"2"}`, "198.51.100.2", "cloudflare.com", 20*time.Millisecond)

	router := makeRouter(pool, nil)
	res, err := router.RouteRequest(platName, "acct-conc", "cloudflare.com")
	if err != nil {
		t.Fatalf("initial route failed: %v", err)
	}

	const concurrency = 8
	var wg sync.WaitGroup
	wg.Add(concurrency)
	var successes atomic.Int32
	var staleCount atomic.Int32

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			_, _, err := router.RotateLease(platID, "acct-conc", res.NodeHash, res.LeaseCreatedAtNs, "cloudflare.com", routing.RotateLeaseOptions{})
			if err == nil {
				successes.Add(1)
			} else if errors.Is(err, routing.ErrLeaseChanged) {
				staleCount.Add(1)
			} else {
				t.Errorf("unexpected err: %v", err)
			}
		}()
	}
	wg.Wait()

	if successes.Load() != 1 {
		t.Fatalf("expected exactly 1 successful rotation, got %d", successes.Load())
	}
	if staleCount.Load() != concurrency-1 {
		t.Fatalf("expected %d stale rejections, got %d", concurrency-1, staleCount.Load())
	}
}
