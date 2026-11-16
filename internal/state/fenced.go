package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
)

// OpenFencedPersistence opens already verified, stopped candidate files only.
// No mkdir, migration, consistency repair, WAL setup, or schema/default writes.
// The caller owns the generation exclusively and must bind both file digests
// and the preflight marker before calling this. SQLite read-only is defense in
// depth, not proof that another process has stopped writing the files.
func OpenFencedPersistence(ctx context.Context, stateDir, cacheDir string) (*StateEngine, io.Closer, error) {
	open := func(path string) (*sql.DB, error) {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return nil, errors.New("state: fenced database is not an existing regular file")
		}
		u := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&immutable=1"}
		db, err := sql.Open("sqlite", u.String())
		if err != nil {
			return nil, err
		}
		db.SetMaxOpenConns(1)
		if err := db.PingContext(ctx); err != nil {
			_ = db.Close()
			return nil, err
		}
		return db, nil
	}
	s, err := open(filepath.Join(stateDir, "state.db"))
	if err != nil {
		return nil, nil, err
	}
	c, err := open(filepath.Join(cacheDir, "cache.db"))
	if err != nil {
		_ = s.Close()
		return nil, nil, err
	}
	e := newStateEngine(newStateRepo(s), newCacheRepo(c))
	e.fenced = true
	e.CacheRepo.fenced = true
	e.SealStrongWrites()
	e.SealWeakWrites()
	return e, &persistenceCloser{stateDB: s, cacheDB: c}, nil
}

// FencedPersistenceError detects ANY mutation attempt, not just DirtyCount=0.
// Constructors must use read operations; even a denied write invalidates ready.
func (e *StateEngine) FencedPersistenceError() error {
	if !e.fenced {
		return errors.New("state: not a fenced engine")
	}
	if err := errors.Join(e.StrongWriteBarrierError(), e.WeakWriteBarrierError()); err != nil {
		return err
	}
	if e.DirtyCount() != 0 || e.markEpoch.Load() != 0 || e.writeEpoch.Load() != 0 || e.CacheRepo.fencedWriteAttempt.Load() {
		return errors.New("state: mutation attempted during fenced bootstrap")
	}
	return nil
}

// ActivateFencedPersistence is EXCLUSIVE startup-only: caller must hold its
// authority gate, with no data-plane listener, background source, DB reader or
// other engine user. The durable activation intent must precede this call.
// Existing engine/repo pointers remain stable for callbacks already wired to
// this graph. No migration or repair runs. Any failure makes this generation
// non-retryable; the owner retains its authority marker for explicit recovery.
func (e *StateEngine) ActivateFencedPersistence(ctx context.Context, stateDir, cacheDir string, readonly io.Closer) (io.Closer, error) {
	if err := errors.Join(ctx.Err(), e.FencedPersistenceError()); err != nil {
		return nil, err
	}
	paths := []string{filepath.Join(stateDir, "state.db"), filepath.Join(cacheDir, "cache.db")}
	var identities []os.FileInfo
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return nil, errors.New("state: fenced database identity invalid")
		}
		identities = append(identities, info)
	}
	if err := readonly.Close(); err != nil {
		return nil, err
	}
	// immutable handles must be gone before opening a writable connection.
	s, err := OpenDB(filepath.Join(stateDir, "state.db"))
	if err != nil {
		return nil, err
	}
	c, err := OpenDB(filepath.Join(cacheDir, "cache.db"))
	if err != nil {
		return nil, errors.Join(err, s.Close())
	}
	closer := &persistenceCloser{stateDB: s, cacheDB: c}
	for i, path := range paths {
		info, err := os.Lstat(path)
		if err != nil || !os.SameFile(identities[i], info) || info.Size() != identities[i].Size() {
			return nil, errors.Join(errors.New("state: activation file identity changed"), closer.Close())
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, closer.Close())
	}
	// This does not purport to synchronize arbitrary runtime readers. It is a
	// lifecycle boundary with NO such users, enforced by the authority owner.
	e.StateRepo.mu.Lock()
	defer e.StateRepo.mu.Unlock()
	e.mutationMu.Lock()
	defer e.mutationMu.Unlock()
	if ctx.Err() != nil || !e.fenced || e.lateWrites || e.lateMarks || e.writeEntries.Load() != 0 || e.markEntries.Load() != 0 || e.DirtyCount() != 0 || e.CacheRepo.fencedWriteAttempt.Load() {
		return nil, errors.Join(fmt.Errorf("state: fenced activation boundary changed"), closer.Close())
	}
	e.StateRepo.db, e.CacheRepo.db = s, c
	e.sealed, e.weakSealed, e.fenced = false, false, false
	e.CacheRepo.fenced = false
	return closer, nil
}
