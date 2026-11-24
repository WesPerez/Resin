package state

import (
	"database/sql"
	"fmt"
	"strings"

	migratedb "github.com/golang-migrate/migrate/v4/database"
)

// The production fork used version 10 for labels before upstream assigned that
// version to chaining. Repair only the identifiable, clean fork schema; keep
// migration metadata intact so an interrupted repair is safe to resume.
func repairForkStateVersion10(db *sql.DB, driver migratedb.Driver) error {
	version, dirty, err := driver.Version()
	if err != nil {
		return err
	}
	if dirty {
		return fmt.Errorf("state migration version %d is dirty", version)
	}
	if version != stateVersionSubscriptionChainProxy {
		return nil
	}
	proxy, err := hasTableColumn(db, "subscriptions", "chain_proxy")
	if err != nil {
		return err
	}
	relay, err := hasTableColumn(db, "subscriptions", "chain_relay")
	if err != nil {
		return err
	}
	labels, err := hasTable(db, "lease_display_names")
	if err != nil {
		return err
	}
	if proxy != relay {
		return fmt.Errorf("state version 10 has a partial chain schema")
	}
	if labels {
		if err := validateLeaseLabelSchema(db); err != nil {
			return err
		}
	}
	if proxy {
		return validateChainSchema(db)
	}
	if !labels {
		return fmt.Errorf("state version 10 matches neither upstream nor production fork schema")
	}
	schema, err := migrationsFS.ReadFile(stateMigrationsPath + "/000010_subscription_chain_proxy.up.sql")
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(string(schema)); err != nil {
		return fmt.Errorf("repair fork version 10: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit fork version 10 repair: %w", err)
	}
	return validateChainSchema(db)
}

type migrationColumn struct {
	kind             string
	notNull, primary int
	defaultValue     sql.NullString
}

func migrationColumns(db *sql.DB, table string) (map[string]migrationColumn, error) {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns := make(map[string]migrationColumn)
	for rows.Next() {
		var id int
		var name string
		var c migrationColumn
		if err := rows.Scan(&id, &name, &c.kind, &c.notNull, &c.defaultValue, &c.primary); err != nil {
			return nil, err
		}
		columns[name] = c
	}
	return columns, rows.Err()
}

func validateLeaseLabelSchema(db *sql.DB) error {
	columns, err := migrationColumns(db, "lease_display_names")
	if err != nil {
		return err
	}
	if len(columns) != 3 {
		return fmt.Errorf("invalid lease display name schema")
	}
	for i, name := range []string{"platform_id", "account", "display_name"} {
		c, ok := columns[name]
		primary := 0
		if i < 2 {
			primary = i + 1
		}
		if !ok || strings.ToUpper(c.kind) != "TEXT" || c.notNull != 1 || c.primary != primary || c.defaultValue.Valid {
			return fmt.Errorf("invalid lease display name column %s", name)
		}
	}
	rows, err := db.Query("PRAGMA foreign_key_list(lease_display_names)")
	if err != nil {
		return err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id, seq int
		var table, from, to, update, remove, match string
		if err := rows.Scan(&id, &seq, &table, &from, &to, &update, &remove, &match); err != nil {
			return err
		}
		if table != "platforms" || from != "platform_id" || to != "id" || remove != "CASCADE" {
			return fmt.Errorf("invalid lease display name foreign key")
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("missing lease display name foreign key")
	}
	return nil
}

func validateChainSchema(db *sql.DB) error {
	columns, err := migrationColumns(db, "subscriptions")
	if err != nil {
		return err
	}
	for _, name := range []string{"chain_proxy", "chain_relay"} {
		c, ok := columns[name]
		if !ok || strings.ToUpper(c.kind) != "INTEGER" || c.notNull != 1 || c.primary != 0 || !c.defaultValue.Valid || c.defaultValue.String != "0" {
			return fmt.Errorf("invalid chain column %s", name)
		}
	}
	var ddl string
	if err := db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='subscriptions'").Scan(&ddl); err != nil {
		return err
	}
	compact := strings.Join(strings.Fields(strings.ToLower(ddl)), "")
	for _, constraint := range []string{"check(chain_proxyin(0,1))", "check(chain_relayin(0,1)andnot(chain_proxy=1andchain_relay=1))"} {
		if !strings.Contains(compact, constraint) {
			return fmt.Errorf("invalid chain constraint %s", constraint)
		}
	}
	return nil
}
