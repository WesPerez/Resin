package state

import (
	"context"
	"database/sql"
	"testing"
)

func preflightHistoricalState(t *testing.T, version int, labels bool) *sql.DB {
	t.Helper()
	db := historicalStateFixture(t, version, labels && version == 10)
	// Historical fixture uses its own metadata DDL. Match the actual deployed
	// golang-migrate driver so the strict proof exercises real schema identity.
	if _, err := db.Exec(`DROP TABLE schema_migrations; CREATE TABLE schema_migrations (version uint64,dirty bool); CREATE UNIQUE INDEX version_unique ON schema_migrations (version); INSERT INTO schema_migrations VALUES (?,false)`, version); err != nil {
		t.Fatal(err)
	}
	seedUpgradeRows(t, db, labels)
	return db
}

func TestPreflightMigrationProvesKnownHistoricalLineages(t *testing.T) {
	for _, fixture := range []struct {
		name    string
		version int
		labels  bool
	}{{"schema9", 9, false}, {"production10", 10, true}, {"upstream10", 10, false}, {"repaired10", 10, true}, {"current11", 11, true}} {
		t.Run(fixture.name, func(t *testing.T) {
			db := preflightHistoricalState(t, fixture.version, fixture.labels)
			if fixture.name == "repaired10" {
				ddl, _ := migrationsFS.ReadFile(stateMigrationsPath + "/000010_subscription_chain_proxy.up.sql")
				if _, err := db.Exec(string(ddl)); err != nil {
					t.Fatal(err)
				}
			}
			if fixture.name == "upstream10" || fixture.name == "repaired10" || fixture.name == "current11" {
				if _, err := db.Exec(`UPDATE subscriptions SET chain_relay=1`); err != nil {
					t.Fatal(err)
				}
			}
			proof, err := MigrateStateDBForPreflight(context.Background(), db)
			if err != nil {
				t.Fatal(err)
			}
			if proof.FromVersion != fixture.version || proof.ToVersion != 11 || len(proof.BusinessDigest) != 64 {
				t.Fatalf("missing migration bindings: %+v", proof)
			}
			assertUpgradeRows(t, db, fixture.labels)
			if fixture.name == "upstream10" || fixture.name == "repaired10" || fixture.name == "current11" {
				var relay int
				if err := db.QueryRow(`SELECT chain_relay FROM subscriptions WHERE id='s'`).Scan(&relay); err != nil || relay != 1 {
					t.Fatal("existing chain setting lost")
				}
			}
			if again, err := MigrateStateDBForPreflight(context.Background(), db); err != nil || again.Lineage != "current-11" {
				t.Fatalf("current reentry: %v", err)
			}
		})
	}
}

func TestPreflightMigrationRejectsUnknownSourceBeforeWriting(t *testing.T) {
	for _, statement := range []string{
		`UPDATE schema_migrations SET dirty=1`,
		`UPDATE schema_migrations SET version=8`,
		`INSERT INTO schema_migrations VALUES (9,0)`,
		`ALTER TABLE subscriptions ADD COLUMN chain_proxy INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE platforms ADD COLUMN unknown TEXT`,
		`CREATE INDEX unknown_idx ON platforms(name)`,
		`CREATE TRIGGER unknown_trigger AFTER UPDATE ON platforms BEGIN DELETE FROM account_header_rules; END`,
		`CREATE VIEW unknown_view AS SELECT name FROM platforms`,
		`CREATE TABLE sqliteXpayload (value TEXT)`,
		`CREATE VIEW sqliteXview AS SELECT name FROM platforms`,
		`CREATE INDEX sqliteXindex ON platforms(name)`,
		`CREATE TRIGGER sqliteXtrigger AFTER UPDATE ON platforms BEGIN DELETE FROM account_header_rules; END`,
		`ALTER TABLE lease_display_names ADD COLUMN unknown TEXT`,
		`DROP TABLE lease_display_names`,
		`UPDATE lease_display_names SET display_name=CAST(x'80' AS TEXT)`,
		`PRAGMA writable_schema=ON; UPDATE sqlite_master SET sql=replace(sql,'DEFAULT ''[]''','DEFAULT ''[ ]''') WHERE name='platforms'; PRAGMA writable_schema=OFF`,
	} {
		t.Run(statement, func(t *testing.T) {
			db := preflightHistoricalState(t, 10, true)
			if _, err := db.Exec(statement); err != nil {
				t.Fatal(err)
			}
			before, err := preflightSchemaDigest(context.Background(), db)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := MigrateStateDBForPreflight(context.Background(), db); err == nil {
				t.Fatal("unreviewed source certified")
			}
			after, err := preflightSchemaDigest(context.Background(), db)
			if err != nil || after != before {
				t.Fatal("refused source schema modified")
			}
		})
	}
}

func TestPreflightMigrationRejectsAnyUnapprovedTransition(t *testing.T) {
	for _, statement := range []string{
		`UPDATE platforms SET updated_at_ns=updated_at_ns+1`,
		`DELETE FROM subscriptions`,
		`INSERT INTO account_header_rules VALUES ('extra','[]',99)`,
		`UPDATE lease_display_names SET display_name='changed'`,
		`DELETE FROM lease_display_names`,
		`INSERT INTO lease_display_names VALUES ('p','extra','extra')`,
		`UPDATE subscriptions SET chain_proxy=1`,
		`CREATE INDEX unexpected_idx ON platforms(name)`,
		`UPDATE schema_migrations SET dirty=1`,
		`PRAGMA writable_schema=ON; UPDATE sqlite_master SET sql=replace(sql,'chain_proxy INTEGER NOT NULL DEFAULT 0','chain_proxy INTEGER NOT NULL DEFAULT 1') WHERE name='subscriptions'; PRAGMA writable_schema=OFF`,
	} {
		t.Run(statement, func(t *testing.T) {
			db := preflightHistoricalState(t, 10, true)
			before, err := inspectPreflightState(context.Background(), db)
			if err != nil {
				t.Fatal(err)
			}
			if err := MigrateStateDB(db); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(statement); err != nil {
				t.Fatal(err)
			}
			if err := verifyPreflightStateMigration(context.Background(), db, before); err == nil {
				t.Fatal("unapproved migration change certified")
			}
		})
	}
	// A lineage without labels may create the table, never populate it.
	db := preflightHistoricalState(t, 9, false)
	before, err := inspectPreflightState(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if err := MigrateStateDB(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO lease_display_names VALUES ('p','extra','extra')`); err != nil {
		t.Fatal(err)
	}
	if err := verifyPreflightStateMigration(context.Background(), db, before); err == nil {
		t.Fatal("populated new label table certified")
	}
}
