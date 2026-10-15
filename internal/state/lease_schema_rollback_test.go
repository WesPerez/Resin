package state

import (
	"path/filepath"
	"testing"
)

// This rollback build retains production behavior while accepting schema 10.
// It must preserve labels and post-upgrade state instead of restoring a stale DB.
func TestRollbackPreservesVersionTenState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := MigrateStateDB(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO platforms(id,name,sticky_ttl_ns,updated_at_ns) VALUES ('after-upgrade','New platform',123,456)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO lease_display_names(platform_id,account,display_name) VALUES ('after-upgrade','old-wire-key','grok-42')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := MigrateStateDB(db); err != nil {
		t.Fatal(err)
	}
	var name string
	if err := db.QueryRow(`SELECT display_name FROM lease_display_names WHERE platform_id='after-upgrade' AND account='old-wire-key'`).Scan(&name); err != nil || name != "grok-42" {
		t.Fatalf("rollback lost display metadata: %q %v", name, err)
	}
	var ttl, updated int64
	if err := db.QueryRow(`SELECT sticky_ttl_ns,updated_at_ns FROM platforms WHERE id='after-upgrade'`).Scan(&ttl, &updated); err != nil || ttl != 123 || updated != 456 {
		t.Fatalf("rollback lost post-upgrade state: %d %d %v", ttl, updated, err)
	}
}
