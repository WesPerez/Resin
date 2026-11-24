package state

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Fixtures replay committed SQL up to the historical version. They never
// downgrade metadata on a current schema, which would hide lineage errors.
func historicalStateFixture(t *testing.T, version int, forkLabels bool) *sql.DB {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	entries, err := migrationsFS.ReadDir(stateMigrationsPath)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0)
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".up.sql") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		var current int
		if _, err := fmt.Sscanf(name, "%d_", &current); err != nil {
			t.Fatal(err)
		}
		if current > version || (forkLabels && current == 10) {
			continue
		}
		ddl, err := migrationsFS.ReadFile(stateMigrationsPath + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(ddl)); err != nil {
			t.Fatalf("fixture %s: %v", name, err)
		}
	}
	if forkLabels {
		ddl, err := migrationsFS.ReadFile(stateMigrationsPath + "/000011_lease_display_names.up.sql")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(ddl)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`CREATE TABLE schema_migrations(version INTEGER NOT NULL PRIMARY KEY, dirty BOOLEAN NOT NULL); INSERT INTO schema_migrations VALUES (?, false)`, version); err != nil {
		t.Fatal(err)
	}
	return db
}

func seedUpgradeRows(t *testing.T, db *sql.DB, labels bool) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO platforms(id,name,sticky_ttl_ns,updated_at_ns) VALUES ('p','P',123,456);
		INSERT INTO subscriptions(id,name,url,update_interval_ns,ephemeral_node_evict_delay_ns,created_at_ns,updated_at_ns) VALUES ('s','S','https://example.com',30000000000,789,111,222)`); err != nil {
		t.Fatal(err)
	}
	if labels {
		if _, err := db.Exec(`INSERT INTO lease_display_names VALUES ('p','account','manual')`); err != nil {
			t.Fatal(err)
		}
	}
}

func assertUpgradeRows(t *testing.T, db *sql.DB, labels bool) {
	t.Helper()
	var version, dirty int
	if err := db.QueryRow(`SELECT version,dirty FROM schema_migrations`).Scan(&version, &dirty); err != nil || version != 11 || dirty != 0 {
		t.Fatalf("migration metadata %d/%d: %v", version, dirty, err)
	}
	var ttl, updated, created, delay int64
	if err := db.QueryRow(`SELECT sticky_ttl_ns,updated_at_ns FROM platforms WHERE id='p'`).Scan(&ttl, &updated); err != nil || ttl != 123 || updated != 456 {
		t.Fatalf("platform lost: %v", err)
	}
	if err := db.QueryRow(`SELECT created_at_ns,ephemeral_node_evict_delay_ns FROM subscriptions WHERE id='s'`).Scan(&created, &delay); err != nil || created != 111 || delay != 789 {
		t.Fatalf("subscription lost: %v", err)
	}
	if err := validateChainSchema(db); err != nil {
		t.Fatal(err)
	}
	if err := validateLeaseLabelSchema(db); err != nil {
		t.Fatal(err)
	}
	if labels {
		var label string
		if err := db.QueryRow(`SELECT display_name FROM lease_display_names WHERE platform_id='p' AND account='account'`).Scan(&label); err != nil || label != "manual" {
			t.Fatalf("label lost: %q %v", label, err)
		}
	}
}

func TestForkStateMigrationHistoricalLineages(t *testing.T) {
	for _, fixture := range []struct {
		name    string
		version int
		labels  bool
	}{{"schema9", 9, false}, {"production10", 10, true}, {"upstream10", 10, false}, {"repaired10", 10, true}} {
		t.Run(fixture.name, func(t *testing.T) {
			db := historicalStateFixture(t, fixture.version, fixture.labels)
			seedUpgradeRows(t, db, fixture.labels)
			if fixture.name == "repaired10" {
				ddl, _ := migrationsFS.ReadFile(stateMigrationsPath + "/000010_subscription_chain_proxy.up.sql")
				if _, err := db.Exec(string(ddl)); err != nil {
					t.Fatal(err)
				}
			}
			for range 2 {
				if err := MigrateStateDB(db); err != nil {
					t.Fatal(err)
				}
				assertUpgradeRows(t, db, fixture.labels)
			}
		})
	}
}

func TestForkStateMigrationRepairRollbackAndResume(t *testing.T) {
	db := historicalStateFixture(t, 10, true)
	seedUpgradeRows(t, db, true)
	// This pre-existing wrong second column makes the original upstream DDL
	// fail after its first ALTER; the transaction must roll that ALTER back.
	if _, err := db.Exec(`ALTER TABLE subscriptions ADD COLUMN chain_relay TEXT`); err != nil {
		t.Fatal(err)
	}
	if err := MigrateStateDB(db); err == nil {
		t.Fatal("partial schema accepted")
	}
	if exists, _ := hasTableColumn(db, "subscriptions", "chain_proxy"); exists {
		t.Fatal("failed repair altered schema")
	}
	if _, err := db.Exec(`ALTER TABLE subscriptions DROP COLUMN chain_relay`); err != nil {
		t.Fatal(err)
	}
	// Exercise a commit of only the lineage repair, as a process exit before 11.
	ddl, _ := migrationsFS.ReadFile(stateMigrationsPath + "/000010_subscription_chain_proxy.up.sql")
	if _, err := db.Exec(string(ddl)); err != nil {
		t.Fatal(err)
	}
	if err := MigrateStateDB(db); err != nil {
		t.Fatal(err)
	}
	assertUpgradeRows(t, db, true)
}

func TestForkStateMigrationRejectsUnknownAndDirtySchemas(t *testing.T) {
	for _, kind := range []string{"unknown", "dirty", "bad_label", "bad_chain"} {
		t.Run(kind, func(t *testing.T) {
			db := historicalStateFixture(t, 10, true)
			seedUpgradeRows(t, db, true)
			switch kind {
			case "unknown":
				_, _ = db.Exec(`DROP TABLE lease_display_names`)
			case "dirty":
				_, _ = db.Exec(`UPDATE schema_migrations SET dirty=true`)
			case "bad_label":
				_, _ = db.Exec(`ALTER TABLE lease_display_names ADD COLUMN unexpected TEXT`)
			case "bad_chain":
				_, _ = db.Exec(`ALTER TABLE subscriptions ADD COLUMN chain_proxy TEXT; ALTER TABLE subscriptions ADD COLUMN chain_relay TEXT`)
			}
			if err := MigrateStateDB(db); err == nil {
				t.Fatal("unsafe lineage accepted")
			}
			var version int
			if err := db.QueryRow(`SELECT version FROM schema_migrations`).Scan(&version); err != nil || version != 10 {
				t.Fatalf("metadata changed: %d %v", version, err)
			}
		})
	}
}

func TestForkUpgradePreservesRegexMigration(t *testing.T) {
	db := historicalStateFixture(t, 8, false)
	if _, err := db.Exec(`INSERT INTO platforms(id,name,sticky_ttl_ns,updated_at_ns,regex_filters_json) VALUES ('p','P',123,456,'["a","b"]')`); err != nil {
		t.Fatal(err)
	}
	if err := MigrateStateDB(db); err != nil {
		t.Fatal(err)
	}
	var filters string
	if err := db.QueryRow(`SELECT regex_filters_json FROM platforms WHERE id='p'`).Scan(&filters); err != nil || filters != `["*a","*b"]` {
		t.Fatalf("regex conversion lost: %q %v", filters, err)
	}
	if err := MigrateStateDB(db); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT regex_filters_json FROM platforms WHERE id='p'`).Scan(&filters); err != nil || filters != `["*a","*b"]` {
		t.Fatal("regex converted twice")
	}
}
