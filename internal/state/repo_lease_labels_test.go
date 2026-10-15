package state

import (
	"path/filepath"
	"testing"
)

func TestLeaseDisplayNamesMigratePersistAndCascade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if err := MigrateStateDB(db); err != nil {
		t.Fatal(err)
	}
	// Simulate the previous version without modifying any platform contents.
	if _, err := db.Exec("DROP TABLE lease_display_names"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE schema_migrations SET version = 9"); err != nil {
		t.Fatal(err)
	}
	if err := MigrateStateDB(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO platforms(id,name,sticky_ttl_ns,updated_at_ns) VALUES ('p','P',123,456)`); err != nil {
		t.Fatal(err)
	}
	r := newStateRepo(db)
	if err := r.SetLeaseDisplayName("p", "legacy-key", "wd-42"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := MigrateStateDB(db); err != nil {
		t.Fatal(err)
	}
	r = newStateRepo(db)
	names, err := r.LeaseDisplayNames("p")
	if err != nil || names["legacy-key"] != "wd-42" {
		t.Fatalf("label not durable: %v %v", names, err)
	}
	var ttl, updated int64
	if err := db.QueryRow("SELECT sticky_ttl_ns,updated_at_ns FROM platforms WHERE id='p'").Scan(&ttl, &updated); err != nil || ttl != 123 || updated != 456 {
		t.Fatal("platform modified", err)
	}
	if _, err := db.Exec("DELETE FROM platforms WHERE id='p'"); err != nil {
		t.Fatal(err)
	}
	names, err = r.LeaseDisplayNames("p")
	if err != nil || len(names) != 0 {
		t.Fatalf("orphan labels: %v %v", names, err)
	}
}
