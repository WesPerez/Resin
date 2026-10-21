package main

// Preflight exercises candidate persistence/bootstrap on a new private copy.
// It never calls run/newResinApp: these start writers and bind endpoints before
// health becomes ready. A preflight receipt is NOT authority activation.
import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Resinat/Resin/internal/buildinfo"
	"github.com/Resinat/Resin/internal/config"
	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/routing"
	"github.com/Resinat/Resin/internal/state"
	"github.com/Resinat/Resin/internal/topology"
)

type preflightOptions struct {
	snapshot, output, stateSHA, cacheSHA, leaseSHA string
	leaseCount                                     int
}

type preflightReceipt struct {
	Version            string                `json:"version"`
	Phase              string                `json:"phase"`
	CandidateSHA       string                `json:"candidate_sha"`
	LeaseFormat        string                `json:"lease_format"`
	LeaseDigest        string                `json:"lease_digest"`
	LeaseCount         int                   `json:"lease_count"`
	Leases             []model.Lease         `json:"leases"`
	Source             []maintenanceDatabase `json:"source_databases"`
	Candidate          []maintenanceDatabase `json:"candidate_databases"`
	StrongDigest       string                `json:"strong_logical_digest"`
	OutboundValidated  bool                  `json:"outbound_validated"`
	AuthorityActivated bool                  `json:"authority_activated"`
}

func preflightCLI(args []string, output io.Writer) error {
	fs := flag.NewFlagSet("preflight", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var o preflightOptions
	fs.StringVar(&o.snapshot, "snapshot-dir", "", "")
	fs.StringVar(&o.output, "output-dir", "", "")
	fs.StringVar(&o.stateSHA, "state-sha256", "", "")
	fs.StringVar(&o.cacheSHA, "cache-sha256", "", "")
	fs.StringVar(&o.leaseSHA, "lease-sha256", "", "")
	fs.IntVar(&o.leaseCount, "lease-count", -1, "")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return errors.New("invalid preflight arguments")
	}
	if err := loadDotenvFile(".env"); err != nil {
		return errors.New("preflight environment invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	r, err := candidatePreflight(ctx, o)
	if err != nil {
		return errors.New("candidate preflight refused; no activation; candidate copy retained if created")
	}
	if err := json.NewEncoder(output).Encode(r); err != nil {
		marker := newMaintenanceController(filepath.Join(o.output, "state"), "", false)
		marker.path = filepath.Join(o.output, "state", "candidate-preflight.json")
		_ = marker.phase("failed")
		return errors.New("preflight receipt output failed; no activation")
	}
	return nil
}

func readonlyDB(path string) (*sql.DB, error) {
	u := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&immutable=1"}
	return sql.Open("sqlite", u.String())
}

func offlineLeases(ctx context.Context, path string) ([]model.Lease, error) {
	db, err := readonlyDB(path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, `SELECT platform_id,account,node_hash,egress_ip,created_at_ns,expiry_ns,last_accessed_ns FROM leases ORDER BY platform_id,account`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []model.Lease{}
	for rows.Next() {
		var l model.Lease
		if err := rows.Scan(&l.PlatformID, &l.Account, &l.NodeHash, &l.EgressIP, &l.CreatedAtNs, &l.ExpiryNs, &l.LastAccessedNs); err != nil {
			return nil, err
		}
		result = append(result, l)
	}
	return result, rows.Err()
}

// Full typed strong-store fingerprint: includes config, labels, endpoints,
// subscriptions and schema, not only the seven fields in the weak lease DB.
// Only digests are emitted, never settings, rules or subscription credentials.
func strongLogicalDigest(ctx context.Context, path string) (string, error) {
	db, err := readonlyDB(path)
	if err != nil {
		return "", err
	}
	defer db.Close()
	schema, err := db.QueryContext(ctx, `SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name`)
	if err != nil {
		return "", err
	}
	type table struct{ kind, name, ddl string }
	var tables []table
	for schema.Next() {
		var t table
		if err := schema.Scan(&t.kind, &t.name, &t.ddl); err != nil {
			schema.Close()
			return "", err
		}
		tables = append(tables, t)
	}
	err = errors.Join(schema.Err(), schema.Close())
	if err != nil {
		return "", err
	}
	h := sha256.New()
	enc := json.NewEncoder(h)
	for _, t := range tables {
		if err := enc.Encode([]string{t.kind, t.name, t.ddl}); err != nil {
			return "", err
		}
		if t.kind != "table" {
			continue
		}
		quoted := `"` + strings.ReplaceAll(t.name, `"`, `""`) + `"`
		r, err := db.QueryContext(ctx, "SELECT * FROM "+quoted)
		if err != nil {
			return "", err
		}
		columns, err := r.Columns()
		if err != nil {
			r.Close()
			return "", err
		}
		var records []string
		for r.Next() {
			values := make([]any, len(columns))
			dest := make([]any, len(columns))
			for i := range values {
				dest[i] = &values[i]
			}
			if err := r.Scan(dest...); err != nil {
				r.Close()
				return "", err
			}
			typed := make([]any, len(values))
			for i, v := range values {
				typed[i] = []any{fmt.Sprintf("%T", v), v}
			}
			b, err := json.Marshal(typed)
			if err != nil {
				r.Close()
				return "", err
			}
			records = append(records, string(b))
		}
		if err := errors.Join(r.Err(), r.Close()); err != nil {
			return "", err
		}
		sort.Strings(records)
		if err := enc.Encode(columns); err != nil {
			return "", err
		}
		if err := enc.Encode(records); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), ctx.Err()
}

func copyPreflightFile(ctx context.Context, source, target string) error {
	before, err := os.Lstat(source)
	if err != nil || !before.Mode().IsRegular() {
		return errors.New("unsafe preflight source")
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	opened, err := in.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return errors.New("preflight source changed")
	}
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	return errors.Join(copyErr, out.Sync(), out.Close(), ctx.Err())
}

func candidatePreflight(ctx context.Context, o preflightOptions) (_ *preflightReceipt, resultErr error) {
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	if o.snapshot == "" || o.output == "" || o.leaseCount < 0 || !hex64.MatchString(o.stateSHA) || !hex64.MatchString(o.cacheSHA) || !hex64.MatchString(o.leaseSHA) {
		return nil, errors.New("missing fixed snapshot identity")
	}
	env, err := config.LoadEnvConfig()
	if err != nil {
		return nil, errors.New("invalid preflight environment")
	}
	source, err := filepath.Abs(o.snapshot)
	if err != nil {
		return nil, err
	}
	target, err := filepath.Abs(o.output)
	if err != nil {
		return nil, err
	}
	if source == target || strings.HasPrefix(target, source+string(os.PathSeparator)) || strings.HasPrefix(source, target+string(os.PathSeparator)) {
		return nil, errors.New("preflight source/output overlap")
	}
	resolvedSource, err := filepath.EvalSymlinks(source)
	if err != nil || resolvedSource != source {
		return nil, errors.New("snapshot path contains symlink")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(target))
	if err != nil || parent != filepath.Dir(target) {
		return nil, errors.New("candidate parent contains symlink")
	}
	si, err := os.Lstat(source)
	if err != nil || !si.IsDir() || si.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("unsafe snapshot directory")
	}
	paths := []string{filepath.Join(source, "state.db"), filepath.Join(source, "cache.db")}
	bind := newMaintenanceController("", "", false)
	if err := bind.bindClosedDatabases(ctx, paths...); err != nil {
		return nil, err
	}
	before := append([]maintenanceDatabase(nil), bind.record.Databases...)
	if before[0].SHA256 != o.stateSHA || before[1].SHA256 != o.cacheSHA {
		return nil, errors.New("fixed database digest mismatch")
	}
	leases, err := offlineLeases(ctx, paths[1])
	if err != nil {
		return nil, err
	}
	digest, err := canonicalLeaseDigest(leases)
	if err != nil || digest != o.leaseSHA || len(leases) != o.leaseCount {
		return nil, errors.New("fixed lease identity mismatch")
	}
	strongBefore, err := strongLogicalDigest(ctx, paths[0])
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		return nil, err
	}
	stateDir, cacheDir := filepath.Join(target, "state"), filepath.Join(target, "cache")
	for _, dir := range []string{stateDir, cacheDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return nil, err
		}
	}
	marker := newMaintenanceController(stateDir, "", false)
	marker.path = filepath.Join(stateDir, "candidate-preflight.json")
	if err := marker.phase("preparing"); err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, marker.phase("failed"))
		}
	}()
	candidatePaths := []string{filepath.Join(stateDir, "state.db"), filepath.Join(cacheDir, "cache.db")}
	for i, path := range paths {
		if err := copyPreflightFile(ctx, path, candidatePaths[i]); err != nil {
			return nil, err
		}
	}
	if err := bind.bindClosedDatabases(ctx, candidatePaths...); err != nil {
		return nil, err
	}
	for i, row := range bind.record.Databases {
		if row.SHA256 != before[i].SHA256 {
			return nil, errors.New("copied source differs")
		}
	}
	engine, closer, err := state.PersistenceBootstrap(stateDir, cacheDir)
	if err != nil {
		return nil, err
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, closer.Close())
		}
	}()
	cfg, _, err := engine.GetSystemConfig()
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = config.NewDefaultRuntimeConfig()
	}
	// Match normal startup's default-writing prelude, but only on the candidate
	// copy. Any resulting logical strong-state change is conservatively refused.
	if err := ensureDefaultAccountHeaderRule(engine); err != nil {
		return nil, err
	}
	env.StateDir = stateDir
	env.CacheDir = cacheDir
	subs := topology.NewSubscriptionManager()
	pool := topology.NewGlobalNodePool(topology.PoolConfig{SubLookup: subs.Lookup, MaxLatencyTableEntries: env.MaxLatencyTableEntries, MaxConsecutiveFailures: func() int { return cfg.MaxConsecutiveFailures }, LatencyDecayWindow: func() time.Duration { return time.Duration(cfg.LatencyDecayWindow) }, LatencyAuthorities: func() []string { return cfg.LatencyAuthorities }})
	if err := bootstrapTopology(engine, subs, pool, env); err != nil {
		return nil, err
	}
	// Actual topology restore functions, without outbound construction/probes.
	// This proves persistence/router survival, not outbound or network readiness.
	if _, err := loadBootstrapNodeStatics(engine, pool, env); err != nil {
		return nil, err
	}
	if err := restoreBootstrapSubscriptionBindings(engine, pool, subs); err != nil {
		return nil, err
	}
	if err := restoreBootstrapNodeDynamics(engine, pool); err != nil {
		return nil, err
	}
	if err := restoreBootstrapNodeLatencies(engine, pool, env.MaxLatencyTableEntries, cfg.LatencyAuthorities); err != nil {
		return nil, err
	}
	pool.RebuildAllPlatforms()
	stored, err := engine.LoadAllLeases()
	if err != nil {
		return nil, err
	}
	afterDigest, err := canonicalLeaseDigest(stored)
	if err != nil || afterDigest != digest || len(stored) != len(leases) {
		return nil, errors.New("bootstrap changed lease set")
	}
	router := routing.NewRouter(routing.RouterConfig{Pool: pool})
	router.RestoreLeases(stored)
	app := &resinApp{engine: engine, topoRuntime: &topologyRuntime{pool: pool, subManager: subs, router: router}, maintenance: marker}
	if err := app.verifyMaintenanceLeases(); err != nil {
		return nil, err
	}
	endpoints, err := engine.ListEndpoints()
	if err != nil {
		return nil, err
	}
	for _, ep := range endpoints {
		if ep.Enabled {
			return nil, errors.New("custom endpoint preflight unsupported")
		}
	}
	// Exercise the real final persistence path for every restored lease, even
	// when bootstrap itself had nothing to mark. Values come from the restored
	// router; the before/after seven-field comparison must remain exact.
	for _, lease := range stored {
		engine.MarkLease(lease.PlatformID, lease.Account)
	}
	engine.SealStrongWrites()
	engine.SealWeakWrites()
	worker := state.NewCacheFlushWorker(engine, newFlushReaders(pool, subs, router), func() int { return 1000 }, func() time.Duration { return time.Hour }, time.Hour)
	if err := worker.StopAndFlush(); err != nil {
		return nil, err
	}
	if err := app.verifyMaintenanceLeases(); err != nil {
		return nil, err
	}
	if err := engine.CheckpointDurable(ctx); err != nil {
		return nil, err
	}
	closed = true
	if err := closer.Close(); err != nil {
		return nil, err
	}
	if err := syncMaintenanceFiles(candidatePaths...); err != nil {
		return nil, err
	}
	if err := bind.bindClosedDatabases(ctx, candidatePaths...); err != nil {
		return nil, err
	}
	candidate := append([]maintenanceDatabase(nil), bind.record.Databases...)
	strongAfter, err := strongLogicalDigest(ctx, candidatePaths[0])
	if err != nil || strongAfter != strongBefore {
		return nil, errors.New("bootstrap changed authoritative strong state")
	}
	if err := bind.bindClosedDatabases(ctx, paths...); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(before, bind.record.Databases) {
		return nil, errors.New("source changed during candidate preflight")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := marker.phase("validated"); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &preflightReceipt{Version: "resin-candidate-preflight/v1", Phase: "validated", CandidateSHA: buildinfo.GitCommit, LeaseFormat: "resin-lease-seven/v1", LeaseDigest: digest, LeaseCount: len(leases), Leases: leases, Source: before, Candidate: candidate, StrongDigest: strongBefore}, nil
}
