package main

import (
	"bytes"
	"encoding/json"
	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/state"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func migrationFixture(t *testing.T) (string, model.Lease) {
	t.Helper()
	dir := t.TempDir()
	e, closer, err := state.PersistenceBootstrap(dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixNano()
	lease := model.Lease{PlatformID: "p", Account: "account", NodeHash: node.HashFromRawOptions([]byte("missing")).Hex(), EgressIP: "198.51.100.1", CreatedAtNs: now, ExpiryNs: now + int64(time.Hour), LastAccessedNs: now}
	if err := e.UpsertPlatform(model.Platform{ID: "p", Name: "Platform", StickyTTLNs: int64(time.Hour), ReverseProxyMissAction: "TREAT_AS_EMPTY", ReverseProxyEmptyAccountBehavior: "RANDOM", AllocationPolicy: "BALANCED"}); err != nil {
		t.Fatal(err)
	}
	if err := e.BulkUpsertLeases([]model.Lease{lease}); err != nil {
		t.Fatal(err)
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, lease
}
func TestStoppedMigrationPreservesDormantLease(t *testing.T) {
	dir, lease := migrationFixture(t)
	var receipt bytes.Buffer
	if err := migrateCLI([]string{"--state-dir", dir, "--cache-dir", dir}, &receipt); err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(receipt.Bytes(), &result); err != nil || result["version"] != "resin-stopped-migration/v1" {
		t.Fatalf("receipt: %v", err)
	}
	e, closer, err := state.PersistenceBootstrapPreservingLeases(dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	rows, err := e.LoadAllLeases()
	if err != nil || !reflect.DeepEqual(rows, []model.Lease{lease}) {
		t.Fatalf("lease changed: %v %v", rows, err)
	}
}
func TestStoppedMigrationRejectsMissingOrLinkedDatabase(t *testing.T) {
	for _, linked := range []bool{false, true} {
		dir, _ := migrationFixture(t)
		path := filepath.Join(dir, "cache.db")
		if err := os.Rename(path, path+".saved"); err != nil {
			t.Fatal(err)
		}
		if linked {
			if err := os.Symlink(path+".saved", path); err != nil {
				t.Fatal(err)
			}
		}
		var out bytes.Buffer
		if err := migrateCLI([]string{"--state-dir", dir, "--cache-dir", dir}, &out); err == nil || out.Len() != 0 {
			t.Fatal("invalid databases accepted")
		}
	}
}
