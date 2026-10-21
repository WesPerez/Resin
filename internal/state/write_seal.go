package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var ErrWritesSealed = errors.New("state: authoritative writes are sealed")

// checkWriteAllowed runs under StateRepo.mu, held through SQL commit. A
// rejected late writer invalidates handoff even though it cannot change SQL.
func (r *StateRepo) checkWriteAllowed() error {
	if r.sealed {
		r.lateWrites = true
		return ErrWritesSealed
	}
	return nil
}

// SealStrongWrites joins synchronous SQL writers, then rejects all subsequent
// writes. There is no strong-state asynchronous queue in this implementation.
// Owners must also join the enclosing service operation's memory side effects.
func (r *StateRepo) SealStrongWrites() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sealed = true
}

func (r *StateRepo) StrongWriteBarrierError() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.sealed || r.lateWrites {
		return errors.New("state: strong write boundary is not certified")
	}
	return nil
}

// CheckpointDurable is only a component boundary: callers must first seal all
// mutation sources and the cache worker. A busy/partial checkpoint is failure,
// never a durable acknowledgement. It does not certify a cross-process cutover.
func (e *StateEngine) CheckpointDurable(ctx context.Context) error {
	if err := e.StrongWriteBarrierError(); err != nil {
		return err
	}
	if err := e.WeakWriteBarrierError(); err != nil {
		return err
	}
	var busy, logFrames, checkpointed int
	if err := e.StateRepo.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(FULL)").Scan(&busy, &logFrames, &checkpointed); err != nil {
		return fmt.Errorf("state checkpoint: %w", err)
	}
	if busy != 0 || logFrames != checkpointed {
		return errors.New("state: incomplete strong-state checkpoint")
	}
	if err := e.CacheRepo.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(FULL)").Scan(&busy, &logFrames, &checkpointed); err != nil {
		return fmt.Errorf("cache checkpoint: %w", err)
	}
	if busy != 0 || logFrames != checkpointed {
		return errors.New("state: incomplete cache checkpoint")
	}
	for _, db := range []*sql.DB{e.StateRepo.db, e.CacheRepo.db} {
		var check string
		if err := db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check); err != nil {
			return fmt.Errorf("database integrity confirmation: %w", err)
		}
		if check != "ok" {
			return errors.New("database integrity confirmation failed")
		}
	}
	return errors.Join(ctx.Err(), e.StrongWriteBarrierError(), e.WeakWriteBarrierError())
}

// admitWeakMark retains mutationMu until the dirty set is updated. Rejected
// marks never disappear silently: retain dirty work for a failed flush/retry,
// but their existence invalidates handoff. No disk write is admitted here.
func (e *StateEngine) admitWeakMark() bool {
	e.mutationMu.Lock()
	if e.weakSealed {
		e.lateMarks = true
	}
	return true
}

func (e *StateEngine) SealWeakWrites() {
	e.mutationMu.Lock()
	defer e.mutationMu.Unlock()
	e.weakSealed = true
}

func (e *StateEngine) WeakWriteBarrierError() error {
	e.mutationMu.Lock()
	defer e.mutationMu.Unlock()
	if !e.weakSealed || e.lateMarks {
		return errors.New("state: weak mutation boundary is not certified")
	}
	return nil
}
