package state

import (
	"context"
	"errors"

	"github.com/Resinat/Resin/internal/model"
)

// ReplaceHandoffLeases is only for an unserved standby whose background flush
// has not started. The caller validates every row and owns the routing gate.
// A transaction failure leaves the old table intact, including on cancellation.
func (r *CacheRepo) ReplaceHandoffLeases(ctx context.Context, leases []model.Lease) error {
	if r.fenced {
		return errors.New("handoff cannot write fenced persistence")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "DELETE FROM leases"); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, upsertLeasesSQL)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, l := range leases {
		if _, err = stmt.ExecContext(ctx, l.PlatformID, l.Account, l.NodeHash, l.EgressIP, l.CreatedAtNs, l.ExpiryNs, l.LastAccessedNs); err != nil {
			return err
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return tx.Commit()
}
