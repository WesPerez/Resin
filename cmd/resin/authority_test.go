package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/config"
	"github.com/Resinat/Resin/internal/geoip"
	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/service"
	"github.com/Resinat/Resin/internal/state"
)

func authorityFixture(t *testing.T) (*config.EnvConfig, authorityOptions, preflightOptions) {
	t.Helper()
	p := preflightFixture(t, nil)
	if _, err := candidatePreflight(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	env, err := config.LoadEnvConfig()
	if err != nil {
		t.Fatal(err)
	}
	env.StateDir = filepath.Join(p.output, "state")
	env.CacheDir = filepath.Join(p.output, "cache")
	env.LogDir = filepath.Join(p.output, "log")
	raw, err := os.ReadFile(filepath.Join(env.StateDir, "candidate-preflight.json"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	return env, authorityOptions{transferID: p.transferID, markerSHA: hex.EncodeToString(digest[:])}, p
}
func candidateBytes(t *testing.T, env *config.EnvConfig) [][]byte {
	t.Helper()
	var b [][]byte
	for _, p := range []string{filepath.Join(env.StateDir, "state.db"), filepath.Join(env.CacheDir, "cache.db"), filepath.Join(env.StateDir, "candidate-preflight.json")} {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, raw)
	}
	return b
}
func openFixtureAuthority(t *testing.T, env *config.EnvConfig, o authorityOptions) (*resinApp, io.Closer, *authorityController, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	app, c, a, err := openFencedAuthority(ctx, env, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return app, c, a, ctx
}
func requestActivation(a *authorityController, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, authorityPath+"/activate", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	a.handler(w, r)
	return w
}
func activationBody(a *authorityController) string {
	raw, _ := json.Marshal(map[string]string{"transfer_id": a.record.TransferID, "instance_id": a.record.InstanceID, "nonce": strings.Repeat("e", 32)})
	return string(raw)
}
func TestFencedRealRuntimeHasNoPersistenceNetworkOrBackgroundStart(t *testing.T) {
	env, o, p := authorityFixture(t)
	// A port already occupied by a fixture is fine: fenced startup must not bind it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	env.ListenAddress = "127.0.0.1"
	env.ResinPort = ln.Addr().(*net.TCPAddr).Port
	source := sourceBytes(t, p)
	before := candidateBytes(t, env)
	app, _, a, _ := openFixtureAuthority(t, env, o)
	if a.record.Phase != "fenced_ready" || a.record.Nonce != "" || !app.fenced || !app.maintenance.closing {
		t.Fatal("false readiness")
	}
	if app.endpointManager != nil || app.metricsManager != nil || app.requestlogRepo != nil || app.healthFeedback != nil || app.topoRuntime.singboxBuilder.Started() {
		t.Fatal("runtime source started during construction")
	}
	app.topoRuntime.pool.Range(func(_ node.Hash, e *node.NodeEntry) bool {
		if e.Outbound.Load() != nil {
			t.Error("outbound constructed")
		}
		return true
	})
	if err := app.engine.FencedPersistenceError(); err != nil {
		t.Fatal(err)
	}
	if err := app.verifyMaintenanceLeases(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, candidateBytes(t, env)) || !reflect.DeepEqual(source, sourceBytes(t, p)) {
		t.Fatal("candidate/source bytes changed")
	}
	for _, dir := range []string{env.StateDir, env.CacheDir} {
		for _, name := range []string{"state.db-wal", "state.db-shm", "cache.db-wal", "cache.db-shm"} {
			if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
				t.Fatal("sqlite sidecar created")
			}
		}
	}
	if _, err := os.Stat(env.LogDir); !os.IsNotExist(err) {
		t.Fatal("observability initialized")
	}
	if err := rejectRetainedMaintenance(env.StateDir); err == nil {
		t.Fatal("ordinary startup accepted fenced generation")
	}
	if _, _, _, err := openFencedAuthority(context.Background(), env, o); err == nil {
		t.Fatal("duplicate owner accepted")
	}
	// SQL failures and dirty marks do not magically become a valid readiness proof.
	if err := app.engine.SetLeaseDisplayName("fixture-platform", "fixture\u2028😀", "changed"); !errors.Is(err, state.ErrWritesSealed) {
		t.Fatal("strong mutation admitted", err)
	}
	if err := app.engine.BulkDeleteLeases([]model.LeaseKey{{PlatformID: "fixture-platform", Account: "fixture\u2028😀"}}); err == nil {
		t.Fatal("cache write admitted")
	}
	app.engine.MarkLease("fixture-platform", "fixture\u2028😀")
	if err := app.engine.FencedPersistenceError(); err == nil {
		t.Fatal("late mutation not detected")
	}
	if !reflect.DeepEqual(before, candidateBytes(t, env)) {
		t.Fatal("denied write changed DB")
	}
}
func TestFencedIdentityMismatchFailsBeforeOwnershipOrDatabaseOpen(t *testing.T) {
	for _, kind := range []string{"marker", "config", "database", "transfer", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			env, o, _ := authorityFixture(t)
			switch kind {
			case "marker":
				o.markerSHA = strings.Repeat("0", 64)
			case "config":
				env.AdminToken = "different-secret"
			case "database":
				if err := os.WriteFile(filepath.Join(env.CacheDir, "cache.db"), []byte("bad"), 0600); err != nil {
					t.Fatal(err)
				}
			case "transfer":
				o.transferID = strings.Repeat("0", 32)
			case "symlink":
				alias := filepath.Join(t.TempDir(), "state")
				if err := os.Symlink(env.StateDir, alias); err != nil {
					t.Fatal(err)
				}
				env.StateDir = alias
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if _, _, _, err := openFencedAuthority(ctx, env, o); err == nil {
				t.Fatal("identity mismatch accepted")
			}
			if _, err := os.Stat(filepath.Join(env.StateDir, ".candidate-authority-owner")); !os.IsNotExist(err) {
				t.Fatal("bad identity acquired ownership")
			}
		})
	}
}
func TestAuthorityDurableNonceBeforeSingleActivationAndReadOnlyStatus(t *testing.T) {
	env, o, _ := authorityFixture(t)
	_, _, a, _ := openFixtureAuthority(t, env, o)
	body := activationBody(a)
	for _, input := range []string{`null`, `[]`, `{"nonce":42}`, body + `{}`, `{"nonce":"` + strings.Repeat("e", 32) + `","nonce":"` + strings.Repeat("e", 32) + `"}`, strings.Repeat("x", 1025)} {
		if w := requestActivation(a, input, a.token); w.Code != 400 {
			t.Fatalf("invalid body accepted: %d", w.Code)
		}
	}
	if w := requestActivation(a, body, "wrong"); w.Code != 401 {
		t.Fatal("unauthenticated activation")
	}
	var wg sync.WaitGroup
	results := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- requestActivation(a, body, a.token).Code }()
	}
	wg.Wait()
	close(results)
	counts := map[int]int{}
	for code := range results {
		counts[code]++
	}
	if counts[202] != 1 || counts[409] != 1 {
		t.Fatal(counts)
	}
	raw, err := os.ReadFile(a.path)
	if err != nil {
		t.Fatal(err)
	}
	var stored authorityRecord
	if strictAuthorityJSON(raw, &stored) != nil || stored.Phase != "activation_pending" || stored.Nonce != strings.Repeat("e", 32) {
		t.Fatal("no durable single-use intent")
	}
	select {
	case <-a.requested:
	default:
		t.Fatal("not signaled")
	}
	r := httptest.NewRequest(http.MethodGet, authorityPath, nil)
	r.Header.Set("Authorization", "Bearer "+a.token)
	w := httptest.NewRecorder()
	a.handler(w, r)
	after, _ := os.ReadFile(a.path)
	if w.Code != 200 || !bytes.Equal(raw, after) || strings.Contains(w.Body.String(), a.token) {
		t.Fatal("status side effect/secret")
	}
	// Irreversible pending/unknown; a lost reply cannot be replayed as a new activation.
	a.fail()
	if w := requestActivation(a, body, a.token); w.Code != 409 {
		t.Fatal("unknown replayed")
	}
	if err := a.phase("active"); err == nil {
		t.Fatal("unknown became active")
	}
}
func TestAuthorityPersistFailureNeverSignalsActivation(t *testing.T) {
	for _, installed := range []bool{false, true} {
		t.Run(map[bool]string{false: "before_rename", true: "after_rename"}[installed], func(t *testing.T) {
			env, o, _ := authorityFixture(t)
			app, readonly, a, ctx := openFixtureAuthority(t, env, o)
			before := candidateBytes(t, env)
			a.persist = func(path string, v any) (bool, error) {
				if installed {
					_, _ = installDurableRecord(path, v)
				}
				return installed, errors.New("fixture fsync failure")
			}
			if w := requestActivation(a, activationBody(a), a.token); w.Code != 503 {
				t.Fatal("failed fsync accepted")
			}
			select {
			case <-a.requested:
				t.Fatal("failed intent signaled")
			default:
			}
			if _, _, err := activateFencedRuntime(ctx, app, readonly, a, o); err == nil {
				t.Fatal("failed intent activated")
			}
			if app.topoRuntime.singboxBuilder.Started() || !reflect.DeepEqual(before, candidateBytes(t, env)) {
				t.Fatal("failed intent mutated")
			}
		})
	}
}
func TestAuthorityDeadlineAndInterruptedOwnershipRemainFenced(t *testing.T) {
	env, o, _ := authorityFixture(t)
	app, c, a, _ := openFixtureAuthority(t, env, o)
	a.deadline = time.Now().Add(-time.Second)
	// Wall clock display is NOT authority to extend the monotonic deadline.
	a.record.DeadlineNs = time.Now().Add(time.Hour).UnixNano()
	if w := requestActivation(a, activationBody(a), a.token); w.Code != 409 {
		t.Fatal("expired request accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := activateFencedRuntime(ctx, app, c, a, o); err == nil {
		t.Fatal("expired activation accepted")
	}
	// Simulate process departure: close readonly handles, retain its exact claim.
	c.Close()
	retryCtx, retryCancel := context.WithTimeout(context.Background(), time.Minute)
	defer retryCancel()
	if _, _, _, err := openFencedAuthority(retryCtx, env, o); err == nil {
		t.Fatal("interrupted generation reopened")
	}
	if err := rejectRetainedMaintenance(env.StateDir); err == nil {
		t.Fatal("ordinary restart bypass")
	}
}
func TestFencedEngineExclusiveActivationPreservesPointersAndDirtyTracking(t *testing.T) {
	env, o, _ := authorityFixture(t)
	app, c, a, ctx := openFixtureAuthority(t, env, o)
	engine := app.engine
	strong, weak := engine.StateRepo, engine.CacheRepo
	// Readonly persistence may be rebound only as an exclusive lifecycle step.
	if w := requestActivation(a, activationBody(a), a.token); w.Code != 202 {
		t.Fatal(w.Code)
	}
	closer, err := engine.ActivateFencedPersistence(ctx, env.StateDir, env.CacheDir, c)
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	if app.engine != engine || engine.StateRepo != strong || engine.CacheRepo != weak {
		t.Fatal("captured graph pointers invalidated")
	}
	if err := engine.SetLeaseDisplayName("fixture-platform", "fixture\u2028😀", "authorized-label"); err != nil {
		t.Fatal(err)
	}
	engine.MarkLease("fixture-platform", "fixture\u2028😀")
	if engine.DirtyCount() != 1 {
		t.Fatal("dirty tracking lost")
	}
	if err := engine.FlushDirtySets(newFlushReaders(app.topoRuntime.pool, app.topoRuntime.subManager, app.topoRuntime.router)); err != nil {
		t.Fatal(err)
	}
	if err := app.verifyMaintenanceLeases(); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.ActivateFencedPersistence(ctx, env.StateDir, env.CacheDir, c); err == nil {
		t.Fatal("activation repeated")
	}
}

// No account, DNS or upstream traffic: only the local fixture endpoint is used.
type authorityNoNetwork struct{}

func (authorityNoNetwork) Download(context.Context, string) ([]byte, error) {
	return nil, errors.New("fixture forbids network")
}

func TestAuthorityActualActivationAndFinalCommitFailureKeepAdmissionClosed(t *testing.T) {
	for _, failure := range []string{"none", "fsync", "deadline"} {
		t.Run(failure, func(t *testing.T) {
			env, o, p := authorityFixture(t)
			env.ListenAddress = "127.0.0.1"
			portListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			env.ResinPort = portListener.Addr().(*net.TCPAddr).Port
			portListener.Close()
			app, c, a, ctx := openFixtureAuthority(t, env, o)
			// Inject only the external download boundary. Runtime Start/Stop, SQLite,
			// outbounds, endpoint demux and HTTP admission are the actual implementation.
			app.topoRuntime.scheduler.Fetcher = func(string) ([]byte, error) { return nil, errors.New("fixture forbids network") }
			app.geoSvc = geoip.NewService(geoip.ServiceConfig{CacheDir: env.CacheDir, OpenDB: geoip.NoOpOpen, Downloader: authorityNoNetwork{}})
			before := sourceBytes(t, p)
			if w := requestActivation(a, activationBody(a), a.token); w.Code != 202 {
				t.Fatal(w.Code)
			}
			closer, _, err := activateFencedRuntime(ctx, app, c, a, o)
			if err != nil {
				t.Fatal(err)
			}
			defer closer.Close()
			defer func() {
				stop, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := app.shutdown(stop, false); err != nil {
					t.Error(err)
				}
			}()
			if !app.topoRuntime.singboxBuilder.Started() || a.record.Phase != "activating" || !a.record.WritesMayHaveStarted {
				t.Fatal("actual runtime never acquired ownership")
			}
			app.endpointManager.mu.Lock()
			address := app.endpointManager.runtimes[service.DefaultEndpointID].listener.Addr().String()
			app.endpointManager.mu.Unlock()
			client := &http.Client{Timeout: time.Second}
			response, err := client.Get("http://" + address + "/api/v1/system/info")
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 503 {
				t.Fatal("data admission opened before durable active", response.StatusCode)
			}
			commitCtx := ctx
			if failure == "fsync" {
				a.persist = func(path string, record any) (bool, error) {
					installed, err := installDurableRecord(path, record)
					if err != nil {
						return installed, err
					}
					return installed, errors.New("fixture fsync failure after actual rename")
				}
			}
			if failure == "deadline" {
				expired, cancel := context.WithCancel(ctx)
				cancel()
				commitCtx = expired
			}
			err = commitAuthorityActive(commitCtx, app, a)
			if (failure == "none") != (err == nil) {
				t.Fatal("incorrect commit result", err)
			}
			if failure != "none" {
				a.fail()
			}
			response, err = client.Get("http://" + address + "/api/v1/system/info")
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if failure != "none" && (response.StatusCode != 503 || !app.maintenance.closing) {
				t.Fatal("failed authority admitted request")
			}
			if failure == "none" && (response.StatusCode == 503 || a.record.Phase != "active") {
				t.Fatal("committed authority never admitted request")
			}
			if !reflect.DeepEqual(before, sourceBytes(t, p)) {
				t.Fatal("activation touched source snapshot")
			}
			if err := app.verifyMaintenanceLeases(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFencedLatencyOverflowRefusesWithoutDirtyMutation(t *testing.T) {
	env, o, _ := authorityFixture(t)
	app, _, _, _ := openFixtureAuthority(t, env, o)
	// Directly use a separate stopped fixture pair to exercise a stale/invalid
	// preflight input. No silent trim, no weak mark, no repaired readiness.
	dir := t.TempDir()
	e, c, err := state.PersistenceBootstrap(dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	h := strings.Repeat("a", 32)
	if err := e.BulkUpsertNodeLatency([]model.NodeLatency{{NodeHash: h, Domain: "one.invalid", EwmaNs: 1, LastUpdatedNs: 2}, {NodeHash: h, Domain: "two.invalid", EwmaNs: 1, LastUpdatedNs: 3}}); err != nil {
		t.Fatal(err)
	}
	c.Close()
	ro, rc, err := state.OpenFencedPersistence(context.Background(), dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if err := restoreBootstrapNodeLatenciesMode(ro, app.topoRuntime.pool, 1, nil, true); err == nil {
		t.Fatal("unpreflighted trim accepted")
	}
	if err := ro.FencedPersistenceError(); err != nil {
		t.Fatal("rejected trim marked dirty", err)
	}
}

func TestAuthorityPrivatePathsAndOrphanClaimAreFences(t *testing.T) {
	for _, kind := range []string{"world_writable", "public_read", "hardlink", "claim_only"} {
		t.Run(kind, func(t *testing.T) {
			env, o, _ := authorityFixture(t)
			switch kind {
			case "world_writable":
				if err := os.Chmod(env.StateDir, 0777); err != nil {
					t.Fatal(err)
				}
			case "public_read":
				if err := os.Chmod(filepath.Join(env.CacheDir, "cache.db"), 0644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(filepath.Join(env.CacheDir, "cache.db"), filepath.Join(t.TempDir(), "alias.db")); err != nil {
					t.Fatal(err)
				}
			case "claim_only":
				if err := os.Mkdir(filepath.Join(env.StateDir, ".candidate-authority-owner"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(env.StateDir, "candidate-preflight.json")); err != nil {
					t.Fatal(err)
				}
				if err := rejectRetainedMaintenance(env.StateDir); err == nil {
					t.Fatal("orphan ownership claim bypassed")
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if _, _, _, err := openFencedAuthority(ctx, env, o); err == nil {
				t.Fatal("unsafe generation accepted")
			}
		})
	}
}

func TestAuthorityQueuedTerminalBeforeOrDuringActiveFsyncNeverOpensAdmission(t *testing.T) {
	for _, during := range []bool{false, true} {
		t.Run(map[bool]string{false: "before_commit", true: "during_fsync"}[during], func(t *testing.T) {
			env, o, _ := authorityFixture(t)
			app, _, a, ctx := openFixtureAuthority(t, env, o)
			if w := requestActivation(a, activationBody(a), a.token); w.Code != 202 {
				t.Fatal(w.Code)
			}
			if err := a.phase("activating"); err != nil {
				t.Fatal(err)
			}
			terminal := !during
			a.terminalCheck = func() bool { return terminal }
			a.persist = func(path string, r any) (bool, error) {
				installed, err := installDurableRecord(path, r)
				terminal = true
				return installed, err
			}
			if err := commitAuthorityActive(ctx, app, a); err == nil {
				t.Fatal("queued terminal event ignored")
			}
			if !app.maintenance.closing {
				t.Fatal("terminal event opened admission")
			}
			if during {
				raw, err := os.ReadFile(a.path)
				var record authorityRecord
				if err != nil || strictAuthorityJSON(raw, &record) != nil || record.Phase != "activation_unknown" {
					t.Fatal("overlapped terminal event not latched")
				}
			}
		})
	}
}
