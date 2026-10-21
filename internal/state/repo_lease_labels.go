package state

import (
	"context"
	"errors"

	"modernc.org/sqlite"
)

var ErrLeaseDisplayNameBusy = errors.New("lease display name storage busy")

// SetLeaseDisplayNameIfEmpty is a single SQLite autocommit statement. It uses
// the caller's context, including while waiting for the DB connection; there
// is no sql.Tx.Commit with a detached background context. An interrupted
// commit is an unknown result, never permission to overwrite an existing name.
// Names describe a stable application key and retain the existing lifetime
// contract across expiry/renewal. This operation cannot replace a manual name.
func (r *StateRepo) SetLeaseDisplayNameIfEmpty(ctx context.Context, platformID, account, name string) (string, error) {
	if !r.mu.TryLock() {
		return "", ErrLeaseDisplayNameBusy
	}
	defer r.mu.Unlock()
	if err := r.checkWriteAllowed(); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	result, err := r.db.ExecContext(ctx, `INSERT INTO lease_display_names(platform_id, account, display_name)
		VALUES (?, ?, ?) ON CONFLICT(platform_id, account) DO NOTHING`, platformID, account, name)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		var sqliteErr *sqlite.Error
		if errors.As(err, &sqliteErr) {
			// Primary SQLite codes: BUSY=5, LOCKED=6, INTERRUPT=9.
			// The result may be unknown; never claim the write rolled back.
			switch sqliteErr.Code() & 0xff {
			case 5, 6, 9:
				return "", ErrLeaseDisplayNameBusy
			}
		}
		return "", err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return "", err
	}
	if count == 1 {
		return name, nil
	}
	var existing string
	err = r.db.QueryRowContext(ctx, "SELECT display_name FROM lease_display_names WHERE platform_id = ? AND account = ?", platformID, account).Scan(&existing)
	return existing, err
}

// LeaseDisplayNames reads the persisted labels for one platform. Labels survive
// lease renewal/expiry because they describe the same stable application key.
func (r *StateRepo) LeaseDisplayNames(platformID string) (map[string]string, error) {
	rows, err := r.db.Query("SELECT account, display_name FROM lease_display_names WHERE platform_id = ?", platformID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]string)
	for rows.Next() {
		var account, name string
		if err := rows.Scan(&account, &name); err != nil {
			return nil, err
		}
		result[account] = name
	}
	return result, rows.Err()
}

// SetLeaseDisplayName only updates strong-persist display metadata, never the
// router or its weak-persist lease cache. Empty names remove the override.
func (r *StateRepo) SetLeaseDisplayName(platformID, account, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkWriteAllowed(); err != nil {
		return err
	}
	if name == "" {
		_, err := r.db.Exec("DELETE FROM lease_display_names WHERE platform_id = ? AND account = ?", platformID, account)
		return err
	}
	_, err := r.db.Exec(`INSERT INTO lease_display_names(platform_id, account, display_name)
		VALUES (?, ?, ?) ON CONFLICT(platform_id, account) DO UPDATE SET display_name = excluded.display_name`, platformID, account, name)
	return err
}
