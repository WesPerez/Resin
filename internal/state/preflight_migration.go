package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// StateMigrationProof approves only the additive 9/10 -> 11 lineages. It is
// evidence about a private candidate copy, never a live writer certificate.
type StateMigrationProof struct {
	FromVersion    int    `json:"from_version"`
	ToVersion      int    `json:"to_version"`
	Lineage        string `json:"lineage"`
	BusinessDigest string `json:"preserved_business_digest"`
}

type preflightStateSchema struct {
	proof         StateMigrationProof
	chain, labels bool
	columns       map[string][]string
}

// MigrateStateDBForPreflight freezes original typed business rows before the
// migration. Both schemas must exactly match committed, known DDL; migration
// metadata, new false chain flags and an empty new labels table are the only
// approved changes. Normal bootstrap/repair must run AFTER this proof.
func MigrateStateDBForPreflight(ctx context.Context, db *sql.DB) (*StateMigrationProof, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	before, err := inspectPreflightState(ctx, db)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := MigrateStateDB(db); err != nil {
		return nil, err
	}
	if err := verifyPreflightStateMigration(ctx, db, before); err != nil {
		return nil, err
	}
	return &before.proof, nil
}

func preflightMigrationVersion(ctx context.Context, db *sql.DB) (int, error) {
	rows, err := db.QueryContext(ctx, `SELECT version,dirty,typeof(version),typeof(dirty) FROM schema_migrations`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var version, count int
	for rows.Next() {
		var dirty int
		var versionType, dirtyType string
		if err := rows.Scan(&version, &dirty, &versionType, &dirtyType); err != nil {
			return 0, err
		}
		if dirty != 0 || versionType != "integer" || dirtyType != "integer" {
			return 0, errors.New("preflight migration metadata is not clean typed state")
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if count != 1 || version < 9 || version > stateLatestVersion {
		return 0, errors.New("preflight requires one known migration version 9 through 11")
	}
	return version, nil
}

// Replay the actual committed SQL into a schema-only in-memory reference.
// Exact sqlite_master text deliberately rejects unreviewed DDL, including
// triggers, indexes and defaults. No whitespace rewriting touches literals.
func preflightReferenceSchema(ctx context.Context, chain, labels bool) (_ *sql.DB, resultErr error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, db.Close())
		}
	}()
	entries, err := migrationsFS.ReadDir(stateMigrationsPath)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries { // embed.FS returns names in sorted order.
		name := entry.Name()
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		var version int
		if _, err := fmt.Sscanf(name, "%d_", &version); err != nil {
			return nil, err
		}
		if version > 11 || (version == 10 && !chain) || (version == 11 && !labels) {
			continue
		}
		ddl, err := migrationsFS.ReadFile(stateMigrationsPath + "/" + name)
		if err != nil {
			return nil, err
		}
		if _, err := db.ExecContext(ctx, string(ddl)); err != nil {
			return nil, err
		}
	}
	// This is the golang-migrate SQLite driver's persisted metadata schema.
	_, err = db.ExecContext(ctx, `CREATE TABLE schema_migrations (version uint64,dirty bool); CREATE UNIQUE INDEX version_unique ON schema_migrations (version)`)
	return db, err
}

func preflightSchemaDigest(ctx context.Context, db *sql.DB) (string, error) {
	rows, err := db.QueryContext(ctx, `SELECT type,name,tbl_name,sql FROM sqlite_master WHERE substr(lower(name),1,7) != 'sqlite_' ORDER BY type,name`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	h := sha256.New()
	enc := json.NewEncoder(h)
	for rows.Next() {
		var kind, name, table, ddl string
		if err := rows.Scan(&kind, &name, &table, &ddl); err != nil {
			return "", err
		}
		for _, value := range []string{kind, name, table, ddl} {
			if !utf8.ValidString(value) {
				return "", errors.New("preflight schema text is not valid UTF-8")
			}
		}
		if err := enc.Encode([]string{kind, name, table, ddl}); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), rows.Err()
}

func requirePreflightSchema(ctx context.Context, db *sql.DB, chain, labels bool) error {
	ref, err := preflightReferenceSchema(ctx, chain, labels)
	if err != nil {
		return err
	}
	defer ref.Close()
	expected, err := preflightSchemaDigest(ctx, ref)
	if err != nil {
		return err
	}
	actual, err := preflightSchemaDigest(ctx, db)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("preflight state schema differs from committed lineage")
	}
	return nil
}

func quotePreflightIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func inspectPreflightState(ctx context.Context, db *sql.DB) (*preflightStateSchema, error) {
	version, err := preflightMigrationVersion(ctx, db)
	if err != nil {
		return nil, err
	}
	chain, err := hasTableColumn(db, "subscriptions", "chain_proxy")
	if err != nil {
		return nil, err
	}
	labels, err := hasTable(db, "lease_display_names")
	if err != nil {
		return nil, err
	}
	lineage := "upstream-9"
	switch {
	case version == 9 && !chain && !labels:
	case version == 10 && !chain && labels:
		lineage = "fork-labels-10"
	case version == 10 && chain && !labels:
		lineage = "upstream-chain-10"
	case version == 10 && chain && labels:
		lineage = "fork-repaired-10"
	case version == 11 && chain && labels:
		lineage = "current-11"
	default:
		return nil, errors.New("preflight migration version and schema lineage disagree")
	}
	if err := requirePreflightSchema(ctx, db, chain, labels); err != nil {
		return nil, err
	}
	before := &preflightStateSchema{proof: StateMigrationProof{FromVersion: version, ToVersion: stateLatestVersion, Lineage: lineage}, chain: chain, labels: labels, columns: make(map[string][]string)}
	for _, table := range []string{"system_config", "platforms", "subscriptions", "account_header_rules", "endpoints", "lease_display_names"} {
		if table == "lease_display_names" && !labels {
			continue
		}
		rows, err := db.QueryContext(ctx, "SELECT * FROM "+quotePreflightIdentifier(table)+" LIMIT 0")
		if err != nil {
			return nil, err
		}
		columns, err := rows.Columns()
		err = errors.Join(err, rows.Close())
		if err != nil {
			return nil, err
		}
		before.columns[table] = columns
	}
	before.proof.BusinessDigest, err = preflightBusinessDigest(ctx, db, before.columns)
	return before, err
}

func preflightBusinessDigest(ctx context.Context, db *sql.DB, columns map[string][]string) (string, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	names := make([]string, 0, len(columns))
	for name := range columns {
		names = append(names, name)
	}
	sort.Strings(names)
	h := sha256.New()
	enc := json.NewEncoder(h)
	for _, name := range names {
		quoted := make([]string, len(columns[name]))
		for i, column := range columns[name] {
			quoted[i] = quotePreflightIdentifier(column)
		}
		rows, err := tx.QueryContext(ctx, "SELECT "+strings.Join(quoted, ",")+" FROM "+quotePreflightIdentifier(name))
		if err != nil {
			return "", err
		}
		var records []string
		for rows.Next() {
			values, dest := make([]any, len(quoted)), make([]any, len(quoted))
			for i := range values {
				dest[i] = &values[i]
			}
			if err := rows.Scan(dest...); err != nil {
				rows.Close()
				return "", err
			}
			for i, value := range values {
				if text, ok := value.(string); ok && !utf8.ValidString(text) {
					rows.Close()
					return "", errors.New("preflight business text is not valid UTF-8")
				}
				values[i] = []any{fmt.Sprintf("%T", value), value}
			}
			raw, err := json.Marshal(values)
			if err != nil {
				rows.Close()
				return "", err
			}
			records = append(records, string(raw))
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return "", err
		}
		sort.Strings(records)
		if err := enc.Encode([]any{name, columns[name], records}); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), ctx.Err()
}

func verifyPreflightStateMigration(ctx context.Context, db *sql.DB, before *preflightStateSchema) error {
	version, err := preflightMigrationVersion(ctx, db)
	if err != nil || version != stateLatestVersion {
		return errors.New("preflight migration did not produce clean current metadata")
	}
	if err := requirePreflightSchema(ctx, db, true, true); err != nil {
		return err
	}
	digest, err := preflightBusinessDigest(ctx, db, before.columns)
	if err != nil || digest != before.proof.BusinessDigest {
		return errors.New("preflight migration changed existing typed business rows")
	}
	if !before.chain {
		var invalid int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM subscriptions WHERE typeof(chain_proxy)!='integer' OR chain_proxy!=0 OR typeof(chain_relay)!='integer' OR chain_relay!=0`).Scan(&invalid); err != nil || invalid != 0 {
			return errors.New("preflight migration changed new chain defaults")
		}
	}
	if !before.labels {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM lease_display_names`).Scan(&count); err != nil || count != 0 {
			return errors.New("preflight migration populated new display names")
		}
	}
	return ctx.Err()
}
