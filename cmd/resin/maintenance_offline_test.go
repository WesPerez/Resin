package main

import (
	"context"
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
	if err := m.bindClosedDatabases(paths...); err != nil {
		t.Fatal(err)
	}
	if len(m.record.Databases) != 2 {
		t.Fatal("not a two database group")
	}
	for _, d := range m.record.Databases {
		if len(d.SHA256) != 64 || d.Size == 0 {
			t.Fatal("file identity missing")
		}
	}
	if err := os.WriteFile(paths[0]+"-wal", []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.bindClosedDatabases(paths...); err == nil {
		t.Fatal("nonempty WAL certified")
	}
	if err := os.Remove(paths[0] + "-wal"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths[1], []byte("not a database"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.bindClosedDatabases(paths...); err == nil {
		t.Fatal("corrupt closed DB certified")
	}
	if err := os.WriteFile(paths[1], nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.bindClosedDatabases(paths...); err == nil {
		t.Fatal("empty closed DB certified")
	}
	if err := os.Remove(paths[1]); err != nil {
		t.Fatal(err)
	}
	if err := m.bindClosedDatabases(paths...); err == nil {
		t.Fatal("missing closed DB certified")
	}
}
