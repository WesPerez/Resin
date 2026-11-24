package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Resinat/Resin/internal/buildinfo"
	"github.com/Resinat/Resin/internal/state"
)

// migrateCLI uses the same embedded migrations as startup on the deployer's
// private stopped-source copy. It does not start a proxy, write a handoff
// certificate, or require an old process to implement the new protocol.
func migrateCLI(args []string, output io.Writer) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var stateDir, cacheDir string
	fs.StringVar(&stateDir, "state-dir", "", "")
	fs.StringVar(&cacheDir, "cache-dir", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || stateDir == "" || cacheDir == "" {
		return errors.New("migrate requires private state-dir and cache-dir")
	}
	for _, path := range []string{filepath.Join(stateDir, "state.db"), filepath.Join(cacheDir, "cache.db")} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("migration requires two existing regular databases")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	leasesBefore, err := offlineLeases(ctx, filepath.Join(cacheDir, "cache.db"))
	if err != nil {
		return err
	}
	leaseDigest, err := canonicalLeaseDigest(leasesBefore)
	if err != nil {
		return err
	}
	db, err := state.OpenDB(stateDir + "/state.db")
	if err != nil {
		return err
	}
	proof, err := state.MigrateStateDBForPreflight(ctx, db)
	if closeErr := db.Close(); err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	cache, err := state.OpenDB(cacheDir + "/cache.db")
	if err != nil {
		return err
	}
	err = state.MigrateCacheDB(cache)
	if closeErr := cache.Close(); err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	leasesAfter, err := offlineLeases(ctx, filepath.Join(cacheDir, "cache.db"))
	if err != nil {
		return err
	}
	afterDigest, err := canonicalLeaseDigest(leasesAfter)
	if err != nil || afterDigest != leaseDigest || len(leasesAfter) != len(leasesBefore) {
		return errors.New("cache migration changed persisted lease identities")
	}
	if err := json.NewEncoder(output).Encode(map[string]any{"version": "resin-stopped-migration/v1", "revision": buildinfo.GitCommit, "state_migration": proof, "lease_digest": leaseDigest, "lease_count": len(leasesBefore)}); err != nil {
		return fmt.Errorf("migration receipt: %w", err)
	}
	return nil
}
