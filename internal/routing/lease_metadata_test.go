package routing

import (
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/node"
)

func TestLeaseMetadataGenerationSerializesReplacement(t *testing.T) {
	table := NewLeaseTable(NewIPLoadStats())
	old := Lease{NodeHash: node.HashFromRawOptions([]byte("old")), EgressIP: netip.MustParseAddr("192.0.2.1"), CreatedAtNs: 1, ExpiryNs: 2, LastAccessedNs: 3}
	table.CreateLease("account", old)
	want := LeaseGeneration{NodeHash: old.NodeHash, EgressIP: old.EgressIP, CreatedAtNs: old.CreatedAtNs}
	for _, changed := range []LeaseGeneration{
		{NodeHash: node.HashFromRawOptions([]byte("new")), EgressIP: want.EgressIP, CreatedAtNs: 1},
		{NodeHash: want.NodeHash, EgressIP: netip.MustParseAddr("192.0.2.2"), CreatedAtNs: 1},
		{NodeHash: want.NodeHash, EgressIP: want.EgressIP, CreatedAtNs: 4},
	} {
		if _, matched, err := table.withLeaseGeneration("account", changed, func() error { t.Error("stale metadata written"); return nil }); matched || err != nil {
			t.Fatalf("stale generation: matched=%v err=%v", matched, err)
		}
	}
	entered, release, done, replaced := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		observed, matched, err := table.withLeaseGeneration("account", want, func() error { close(entered); <-release; return nil })
		if !matched || err != nil || observed != old {
			t.Errorf("metadata result: %+v %v %v", observed, matched, err)
		}
	}()
	<-entered
	next := old
	next.CreatedAtNs++
	replacementStarted := make(chan struct{})
	go func() { close(replacementStarted); table.CreateLease("account", next); close(replaced) }()
	<-replacementStarted
	select {
	case <-replaced:
		t.Error("replacement crossed metadata write")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-done
	<-replaced
	if _, matched, _ := table.withLeaseGeneration("account", want, func() error { t.Error("old generation reused"); return nil }); matched {
		t.Fatal("stale generation matched")
	}
	if got, _ := table.GetLease("account"); got != next || table.stats.Get(old.EgressIP) != 1 {
		t.Fatal("metadata altered route or load stats")
	}
}

func TestLeaseMetadataConcurrentDeleteAndResize(t *testing.T) {
	table := NewLeaseTable(NewIPLoadStats())
	lease := Lease{NodeHash: node.HashFromRawOptions([]byte("node")), EgressIP: netip.MustParseAddr("192.0.2.1"), CreatedAtNs: 1}
	expected := LeaseGeneration{NodeHash: lease.NodeHash, EgressIP: lease.EgressIP, CreatedAtNs: 1}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				table.CreateLease("resize-"+strconv.Itoa(worker)+"-"+strconv.Itoa(j), lease)
				table.CreateLease("shared", lease)
				calls := 0
				_, matched, _ := table.withLeaseGeneration("shared", expected, func() error { calls++; return nil })
				if calls > 1 || matched && calls != 1 {
					t.Errorf("callback repeated: %d", calls)
				}
				table.DeleteLease("shared")
			}
		}(i)
	}
	wg.Wait()
}
