package service

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/state"
)

func TestLeaseReadSurvivesUnavailableDisplayMetadata(t *testing.T) {
	cp, plat := newLeaseInheritanceTestService()
	root := t.TempDir()
	engine, closer, err := state.PersistenceBootstrap(filepath.Join(root, "state"), filepath.Join(root, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	cp.Engine = engine
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	hash := node.HashFromRawOptions([]byte(`{"type":"socks","server":"192.0.2.1","server_port":1080}`))
	lease := model.Lease{PlatformID: plat.ID, Account: "legacy-1", NodeHash: hash.Hex(), EgressIP: "192.0.2.2", CreatedAtNs: 1, LastAccessedNs: 2, ExpiryNs: time.Now().Add(time.Hour).UnixNano()}
	seedLease(t, cp, lease)
	got, err := cp.GetLease(plat.ID, lease.Account)
	if err != nil || got == nil || !got.DisplayNameUnavailable || got.NodeHash != lease.NodeHash {
		t.Fatalf("base read lost: %+v %v", got, err)
	}
	rows, err := cp.ListLeases(plat.ID)
	if err != nil || len(rows) != 1 || !rows[0].DisplayNameUnavailable {
		t.Fatalf("base list lost: %+v %v", rows, err)
	}
	name := "wd-1"
	if _, err := cp.SetLeaseDisplayName(plat.ID, lease.Account, SetLeaseDisplayNameRequest{DisplayName: &name}); err == nil {
		t.Fatal("save succeeded with closed metadata store")
	}
}
