package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/Resinat/Resin/internal/state"
)

func TestMaintenanceClosedDatabasesIntegrityManifest(t *testing.T) {
	dir := t.TempDir()
	e, closer, err := state.PersistenceBootstrap(filepath.Join(dir, "state"), filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	e.SealStrongWrites()
	e.SealWeakWrites()
	if err := e.CheckpointDurable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	m := newMaintenanceController(filepath.Join(dir, "state"), "fixture", true)
	paths := []string{filepath.Join(dir, "state", "state.db"), filepath.Join(dir, "cache", "cache.db")}
	if err := syncMaintenanceFiles(paths...); err != nil {
		t.Fatal(err)
	}
	if err := m.bindClosedDatabases(context.Background(), paths...); err != nil {
		t.Fatal(err)
	}
	if len(m.record.Databases) != 2 {
		t.Fatal("not a two database group")
	}
	for i, d := range m.record.Databases {
		body, err := os.ReadFile(paths[i])
		digest := sha256.Sum256(body)
		if err != nil || d.Path != paths[i] || d.SHA256 != hex.EncodeToString(digest[:]) || d.Size != int64(len(body)) {
			t.Fatal("file identity does not match independent read")
		}
	}
	for _, suffix := range []string{"-shm", "-journal"} {
		if err := os.WriteFile(paths[0]+suffix, []byte("pending"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := m.bindClosedDatabases(context.Background(), paths...); err == nil {
			t.Fatal("unsafe sidecar certified")
		}
		if err := os.Remove(paths[0] + suffix); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(paths[0]+"-wal", []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.bindClosedDatabases(context.Background(), paths...); err == nil {
		t.Fatal("nonempty WAL certified")
	}
	if err := os.Remove(paths[0] + "-wal"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths[1], []byte("not a database"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.bindClosedDatabases(context.Background(), paths...); err == nil {
		t.Fatal("corrupt closed DB certified")
	}
	if err := os.WriteFile(paths[1], nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.bindClosedDatabases(context.Background(), paths...); err == nil {
		t.Fatal("empty closed DB certified")
	}
	if err := os.Remove(paths[1]); err != nil {
		t.Fatal(err)
	}
	if err := m.bindClosedDatabases(context.Background(), paths...); err == nil {
		t.Fatal("missing closed DB certified")
	}
}
