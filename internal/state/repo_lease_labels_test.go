package state

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
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

func TestLeaseDisplayNameIfEmptyPreservesManualNamesAndDefersBusy(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := MigrateStateDB(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO platforms(id,name,sticky_ttl_ns,updated_at_ns) VALUES ('p','P',123,456)`); err != nil {
		t.Fatal(err)
	}
	r := newStateRepo(db)
	r.mu.Lock()
	_, err = r.SetLeaseDisplayNameIfEmpty(context.Background(), "p", "a", "auto")
	r.mu.Unlock()
	if !errors.Is(err, ErrLeaseDisplayNameBusy) {
		t.Fatalf("busy result: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.SetLeaseDisplayNameIfEmpty(ctx, "p", "a", "auto"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	var wg sync.WaitGroup
	for _, name := range []string{"first", "second"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			_, err := r.SetLeaseDisplayNameIfEmpty(context.Background(), "p", "a", name)
			if err != nil && !errors.Is(err, ErrLeaseDisplayNameBusy) {
				t.Error(err)
			}
		}(name)
	}
	wg.Wait()
	names, err := r.LeaseDisplayNames("p")
	if err != nil || (names["a"] != "first" && names["a"] != "second") {
		t.Fatalf("concurrent insert: %v %v", names, err)
	}
	if err := r.SetLeaseDisplayName("p", "a", "manual"); err != nil {
		t.Fatal(err)
	}
	if name, err := r.SetLeaseDisplayNameIfEmpty(context.Background(), "p", "a", "auto"); err != nil || name != "manual" {
		t.Fatalf("manual replaced: %s %v", name, err)
	}
	// Waiting for the single DB connection must respect cancellation too.
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = r.SetLeaseDisplayNameIfEmpty(ctx, "p", "blocked", "auto")
	conn.Close()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DB wait ignored context: %v", err)
	}
	if _, err := r.SetLeaseDisplayNameIfEmpty(context.Background(), "missing", "a", "auto"); err == nil {
		t.Fatal("missing platform accepted")
	}
}
