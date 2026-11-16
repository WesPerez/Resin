package main

// Candidate authority is a separate, fail-closed lifetime. Ordinary startup
// NEVER removes or ignores its markers. A stopped/failed/unknown candidate is
// not restartable by replaying this command, and activation never authorizes
// routing or rollback from an older database generation.
import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Resinat/Resin/internal/buildinfo"
	"github.com/Resinat/Resin/internal/config"
	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/state"
)

const authorityFile = "candidate-authority.json"
const authorityPath = "/authority"

var authorityHex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)
var authorityHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

type authorityOptions struct {
	transferID, markerSHA, listen string
	wait                          time.Duration
}
type authorityRecord struct {
	Version              string                `json:"version"`
	Phase                string                `json:"phase"`
	TransferID           string                `json:"transfer_id"`
	InstanceID           string                `json:"instance_id"`
	Nonce                string                `json:"activation_nonce,omitempty"`
	CandidateSHA         string                `json:"candidate_sha"`
	MarkerSHA            string                `json:"preflight_marker_sha256"`
	ConfigDigest         string                `json:"effective_config_digest"`
	RuntimeDigest        string                `json:"effective_runtime_digest"`
	StrongDigest         string                `json:"strong_logical_digest"`
	LeaseDigest          string                `json:"lease_digest"`
	LeaseCount           int                   `json:"lease_count"`
	Databases            []maintenanceDatabase `json:"initial_databases"`
	DeadlineNs           int64                 `json:"deadline_ns"`
	WritesMayHaveStarted bool                  `json:"writes_may_have_started"`
}

type authorityController struct {
	mu            sync.Mutex
	path, token   string
	record        authorityRecord
	persist       func(string, any) (bool, error)
	requested     chan struct{}
	deadline      time.Time   // retains monotonic time; DeadlineNs is display only
	terminalCheck func() bool // exclusive startup owner; drains already queued terminal events
}

func (a *authorityController) phase(phase string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.record.Phase == "failed" || a.record.Phase == "activation_unknown" {
		return errors.New("authority failure latched")
	}
	a.record.Phase = phase
	if phase == "activating" {
		a.record.WritesMayHaveStarted = true
	}
	if installed, err := a.persist(a.path, a.record); err != nil {
		a.record.Phase = "activation_unknown"
		if installed {
			_, _ = a.persist(a.path, a.record)
		}
		return err
	}
	return nil
}
func (a *authorityController) fail() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.record.Nonce != "" {
		a.record.Phase = "activation_unknown"
	} else {
		a.record.Phase = "failed"
	}
	_, _ = a.persist(a.path, a.record) // existing durable intent remains the restart fence on I/O failure
}
func (a *authorityController) handler(w http.ResponseWriter, r *http.Request) {
	if a.token == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+a.token)) != 1 {
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.URL.Path != authorityPath && r.URL.Path != authorityPath+"/activate" {
		http.NotFound(w, r)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "invalid request", 400)
		return
	}
	if r.URL.Path == authorityPath+"/activate" {
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1025))
		var req struct {
			TransferID string `json:"transfer_id"`
			InstanceID string `json:"instance_id"`
			Nonce      string `json:"nonce"`
		}
		if err != nil || len(raw) > 1024 || strictAuthorityJSON(raw, &req) != nil || !authorityHex32.MatchString(req.Nonce) {
			http.Error(w, "invalid request", 400)
			return
		}
		a.mu.Lock()
		if a.record.Phase != "fenced_ready" || a.record.TransferID != req.TransferID || a.record.InstanceID != req.InstanceID || !time.Now().Before(a.deadline) {
			a.mu.Unlock()
			http.Error(w, "activation refused; query status", 409)
			return
		}
		// Never send a success before the nonce and owning process are durable.
		// Same-nonce retry is also refused: recovery is GET, not replay POST.
		a.record.Nonce = req.Nonce
		a.record.Phase = "activation_pending"
		if installed, err := a.persist(a.path, a.record); err != nil {
			a.record.Phase = "activation_unknown"
			if installed {
				_, _ = a.persist(a.path, a.record)
			}
			a.mu.Unlock()
			http.Error(w, "authority persistence failed", 503)
			return
		}
		close(a.requested)
		a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"accepted":true,"authority_active":false}`)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	a.mu.Lock()
	record := a.record
	// This derived status is read-only, even if the expiry writer is delayed.
	if record.Phase == "fenced_ready" && !time.Now().Before(a.deadline) {
		record.Phase = "expired"
	}
	a.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(record)
}

// Reject duplicate keys as well as unknown fields/trailing JSON. Marker and
// request decoding must not depend on last-key-wins interpretation.
func strictAuthorityJSON(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return errors.New("duplicate JSON key")
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		_, err = dec.Token()
		return err
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func readAuthorityMarker(env *config.EnvConfig, o authorityOptions) (maintenanceRecord, error) {
	var m maintenanceRecord
	if !authorityHex32.MatchString(o.transferID) || !authorityHex64.MatchString(o.markerSHA) {
		return m, errors.New("authority identity missing")
	}
	for _, dir := range []string{env.StateDir, env.CacheDir} {
		abs, err := filepath.Abs(dir)
		if err != nil || abs != dir {
			return m, errors.New("authority requires absolute directories")
		}
		resolved, err := filepath.EvalSymlinks(dir)
		if err != nil || resolved != dir {
			return m, errors.New("authority directory symlink refused")
		}
	}
	if env.StateDir == env.CacheDir || strings.HasPrefix(env.StateDir, env.CacheDir+string(os.PathSeparator)) || strings.HasPrefix(env.CacheDir, env.StateDir+string(os.PathSeparator)) {
		return m, errors.New("authority directories overlap")
	}
	si, se := os.Lstat(env.StateDir)
	ci, ce := os.Lstat(env.CacheDir)
	if se != nil || ce != nil || os.SameFile(si, ci) {
		return m, errors.New("authority directory identity invalid")
	}
	for _, p := range []string{env.StateDir, env.CacheDir, filepath.Join(env.StateDir, "state.db"), filepath.Join(env.CacheDir, "cache.db"), filepath.Join(env.StateDir, "candidate-preflight.json")} {
		if err := verifyPrivateAuthorityPath(p); err != nil {
			return m, err
		}
	}
	if _, err := os.Lstat(maintenanceMarker(env.StateDir)); !errors.Is(err, os.ErrNotExist) {
		return m, errors.New("source handoff marker cannot become candidate authority")
	}
	path := filepath.Join(env.StateDir, "candidate-preflight.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 65536 {
		return m, errors.New("invalid preflight marker")
	}
	f, err := os.Open(path)
	if err != nil {
		return m, err
	}
	opened, statErr := f.Stat()
	raw, readErr := io.ReadAll(io.LimitReader(f, 65537))
	closeErr := f.Close()
	if statErr != nil || !os.SameFile(info, opened) || readErr != nil || closeErr != nil || int64(len(raw)) != info.Size() {
		return m, errors.New("preflight marker changed")
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != o.markerSHA || strictAuthorityJSON(raw, &m) != nil {
		return m, errors.New("preflight marker digest/schema mismatch")
	}
	if m.Version != 1 || m.Phase != "validated" || m.TransferID != o.transferID || m.SourceSHA != buildinfo.GitCommit || m.LeaseFormat != "resin-lease-seven/v1" || m.LeaseCount < 0 || len(m.Databases) != 2 {
		return m, errors.New("preflight marker identity mismatch")
	}
	// Preflight can run in a container or a hosted process; its PID is not the
	// future authority PID. Bind ordered roles, not relocated sandbox prefixes.
	if m.PID <= 0 || m.StartedAtNs <= 0 || filepath.Base(m.Databases[0].Path) != "state.db" || filepath.Base(m.Databases[1].Path) != "cache.db" {
		return m, errors.New("preflight role or process binding invalid")
	}
	for _, d := range []string{m.ConfigDigest, m.RuntimeDigest, m.StrongDigest, m.LeaseDigest} {
		if !authorityHex64.MatchString(d) {
			return m, errors.New("preflight marker incomplete")
		}
	}
	return m, nil
}

func verifyAuthorityFiles(ctx context.Context, env *config.EnvConfig, o authorityOptions, m maintenanceRecord) error {
	fresh, err := readAuthorityMarker(env, o)
	if err != nil || !reflect.DeepEqual(fresh, m) {
		return errors.New("preflight identity changed")
	}
	got, err := effectiveConfigDigest(env)
	if err != nil || got != m.ConfigDigest {
		return errors.New("authority configuration mismatch")
	}
	bind := newMaintenanceController("", "", false)
	if err := bind.bindClosedDatabases(ctx, filepath.Join(env.StateDir, "state.db"), filepath.Join(env.CacheDir, "cache.db")); err != nil {
		return err
	}
	for i, db := range bind.record.Databases {
		if db.Size != m.Databases[i].Size || db.SHA256 != m.Databases[i].SHA256 {
			return errors.New("candidate database identity mismatch")
		}
	}
	strong, err := strongLogicalDigest(ctx, filepath.Join(env.StateDir, "state.db"))
	if err != nil || strong != m.StrongDigest {
		return errors.New("authority strong state mismatch")
	}
	leases, err := offlineLeases(ctx, filepath.Join(env.CacheDir, "cache.db"))
	if err != nil {
		return err
	}
	digest, err := canonicalLeaseDigest(leases)
	if err != nil || digest != m.LeaseDigest || len(leases) != m.LeaseCount {
		return errors.New("authority lease identity mismatch")
	}
	return ctx.Err()
}

// Ownership directory is an O_EXCL-style interprocess claim and is NEVER
// removed automatically, even on clean exit. Thus process interruption cannot
// reopen this generation through ordinary startup or replay fenced startup.
func openFencedAuthority(ctx context.Context, env *config.EnvConfig, o authorityOptions) (*resinApp, io.Closer, *authorityController, error) {
	m, err := readAuthorityMarker(env, o)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := verifyAuthorityFiles(ctx, env, o, m); err != nil {
		return nil, nil, nil, err
	}
	if _, err := os.Lstat(filepath.Join(env.StateDir, authorityFile)); !errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil, errors.New("authority record already exists")
	}
	claim := filepath.Join(env.StateDir, ".candidate-authority-owner")
	if err := os.Mkdir(claim, 0700); err != nil {
		return nil, nil, nil, errors.New("authority ownership already claimed or unavailable")
	}
	if err := syncAuthorityDirectory(env.StateDir); err != nil {
		return nil, nil, nil, err
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, nil, nil, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, nil, nil, errors.New("authority deadline required")
	}
	a := &authorityController{path: filepath.Join(env.StateDir, authorityFile), token: env.AdminToken, persist: installDurableRecord, requested: make(chan struct{}), deadline: deadline, record: authorityRecord{
		Version: "resin-candidate-authority/v1", Phase: "opening", TransferID: m.TransferID, InstanceID: hex.EncodeToString(id), CandidateSHA: buildinfo.GitCommit, MarkerSHA: o.markerSHA,
		ConfigDigest: m.ConfigDigest, RuntimeDigest: m.RuntimeDigest, StrongDigest: m.StrongDigest, LeaseDigest: m.LeaseDigest, LeaseCount: m.LeaseCount, Databases: m.Databases, DeadlineNs: deadline.UnixNano(),
	}}
	if err := a.phase("opening"); err != nil {
		return nil, nil, a, err
	}
	engine, closer, err := state.OpenFencedPersistence(ctx, env.StateDir, env.CacheDir)
	if err != nil {
		a.fail()
		return nil, nil, a, err
	}
	app, err := constructResinApp(env, engine, true)
	if err == nil {
		err = app.verifyMaintenanceLeases()
	}
	if err == nil {
		err = app.bindMaintenanceRuntime()
	}
	if err == nil && (app.maintenance.record.RuntimeDigest != m.RuntimeDigest || app.maintenance.record.LeaseDigest != m.LeaseDigest || app.maintenance.record.LeaseCount != m.LeaseCount) {
		err = errors.New("fenced runtime identity differs")
	}
	if err == nil {
		err = engine.FencedPersistenceError()
	}
	if err == nil {
		err = verifyAuthorityFiles(ctx, env, o, m)
	}
	if err == nil {
		err = a.phase("fenced_ready")
	}
	if err != nil {
		a.fail()
		_ = closer.Close()
		return nil, nil, a, err
	}
	app.maintenance.closing = true
	app.authority = a
	return app, closer, a, nil
}

func syncAuthorityDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

// This can start network services ONLY after durable single-use intent. A
// timeout/error afterwards is unknown ownership, not permission to close an
// active writer or restore the old DB. The caller parks the process instead.
func activateFencedRuntime(ctx context.Context, app *resinApp, readonly io.Closer, a *authorityController, o authorityOptions) (io.Closer, <-chan error, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	a.mu.Lock()
	allowed := a.record.Phase == "activation_pending" && a.record.Nonce != ""
	a.mu.Unlock()
	if !allowed {
		return nil, nil, errors.New("activation intent absent")
	}
	if err := a.phase("activating"); err != nil {
		return nil, nil, err
	}
	m, err := readAuthorityMarker(app.envCfg, o)
	if err != nil {
		return nil, nil, err
	}
	if err := verifyAuthorityFiles(ctx, app.envCfg, o, m); err != nil {
		return nil, nil, err
	}
	closer, err := app.engine.ActivateFencedPersistence(ctx, app.envCfg.StateDir, app.envCfg.CacheDir, readonly)
	if err != nil {
		return nil, nil, err
	}
	if err := app.topoRuntime.singboxBuilder.Start(); err != nil {
		return closer, nil, err
	}
	var hashes []node.Hash
	app.topoRuntime.pool.Range(func(hash node.Hash, _ *node.NodeEntry) bool { hashes = append(hashes, hash); return true })
	warmupBootstrapOutbounds(hashes, app.topoRuntime.outboundMgr)
	for _, lease := range app.topoRuntime.router.MaintenanceLeases() {
		hash, err := node.ParseHex(lease.NodeHash)
		entry, exists := app.topoRuntime.pool.GetEntry(hash)
		if err != nil || !exists || entry.Outbound.Load() == nil {
			return closer, nil, errors.New("authority lease outbound initialization failed")
		}
	}
	if err := ctx.Err(); err != nil {
		return closer, nil, err
	}
	if err := app.verifyMaintenanceLeases(); err != nil {
		return closer, nil, err
	}
	if err := app.initObservability(); err != nil {
		return closer, nil, err
	}
	if err := app.buildNetworkServers(app.engine); err != nil {
		return closer, nil, err
	}
	if err := ctx.Err(); err != nil {
		return closer, nil, err
	}
	app.startBackgroundServices()
	serverErr := app.startServers() // ordinary HTTP/SOCKS admission is still closed
	return closer, serverErr, nil
}

// The expiry/listener watcher has been joined BEFORE this final transition.
// A failed fsync or expired deadline retains closed data-plane admission. The
// durable activating intent already owns any started background writers.
func commitAuthorityActive(ctx context.Context, app *resinApp, a *authorityController) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	terminal := func() bool { return a.terminalCheck != nil && a.terminalCheck() }
	if ctx.Err() != nil || terminal() || a.record.Phase != "activating" {
		return errors.New("activation expired or invalidated")
	}
	a.record.Phase = "active"
	if installed, err := a.persist(a.path, a.record); err != nil {
		a.record.Phase = "activation_unknown"
		if installed {
			_, _ = a.persist(a.path, a.record)
		}
		return err
	}
	if ctx.Err() != nil || terminal() {
		a.record.Phase = "activation_unknown"
		_, _ = a.persist(a.path, a.record)
		return errors.New("activation terminal event overlapped durability acknowledgement")
	}
	app.maintenance.mu.Lock()
	app.maintenance.closing = false
	app.maintenance.mu.Unlock()
	app.fenced = false
	return nil
}

func fencedCLI(args []string) error {
	fs := flag.NewFlagSet("fenced", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var o authorityOptions
	fs.StringVar(&o.transferID, "transfer-id", "", "")
	fs.StringVar(&o.markerSHA, "marker-sha256", "", "")
	fs.StringVar(&o.listen, "authority-listen", "", "")
	fs.DurationVar(&o.wait, "deadline", 2*time.Minute, "")
	if fs.Parse(args) != nil || fs.NArg() != 0 || o.wait < time.Second || o.wait > 10*time.Minute {
		return errors.New("invalid fenced arguments")
	}
	host, port, err := net.SplitHostPort(o.listen)
	ip, ipErr := netip.ParseAddr(host)
	if err != nil || ipErr != nil || !ip.IsLoopback() || port == "0" || port == "" {
		return errors.New("authority must use an explicit loopback endpoint")
	}
	if err := loadDotenvFile(".env"); err != nil {
		return errors.New("invalid environment")
	}
	env, err := config.LoadEnvConfig()
	if err != nil || env.AdminToken == "" {
		return errors.New("authority authentication required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.wait)
	defer cancel()
	app, readonly, a, err := openFencedAuthority(ctx, env, o)
	if err != nil {
		return errors.New("fenced startup refused; generation retained")
	}
	ln, err := net.Listen("tcp", o.listen)
	if err != nil {
		a.fail()
		_ = readonly.Close()
		return errors.New("authority listener unavailable")
	}
	srv := &http.Server{Handler: http.HandlerFunc(a.handler), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
	serverErr := make(chan error, 1)
	go func() { serverErr <- srv.Serve(ln) }()
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(quit)
	select {
	case <-a.requested:
	case <-ctx.Done():
		a.fail()
		_ = srv.Close()
		_ = readonly.Close()
		return errors.New("fenced readiness expired; generation retained")
	case <-quit:
		a.fail()
		_ = srv.Close()
		_ = readonly.Close()
		return errors.New("fenced startup interrupted; generation retained")
	case <-serverErr:
		a.fail()
		_ = readonly.Close()
		return errors.New("authority listener failed")
	}
	// Once activation is requested the process may acquire writable ownership.
	// A deadline watcher latches failure even if startup blocks in an OS call;
	// it never closes DBs or kills a still-owned callback to force a clean exit.
	watcherStop, watcherDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			a.fail()
		case <-quit:
			cancel()
			a.fail()
		case <-serverErr:
			cancel()
			a.fail()
		case <-watcherStop:
		}
	}()
	closer, dataErr, err := activateFencedRuntime(ctx, app, readonly, a, o)
	close(watcherStop)
	<-watcherDone
	// No watcher may consume these events now. Explicitly sample both sides
	// of the fsync; queued signal/listener failure cannot disappear between
	// watcher join and admission commit. A later event belongs to active stop.
	a.terminalCheck = func() bool {
		select {
		case <-quit:
			return true
		case <-serverErr:
			return true
		default:
			return false
		}
	}
	if err == nil {
		err = commitAuthorityActive(ctx, app, a)
	}
	if err != nil {
		a.fail()
		select {}
	} // explicit recovery/force-stop, NEVER a successful handoff
	cancel() // deadline covered ownership acquisition, not the active lifetime
	// Keep the read-only authority endpoint available for an unknown POST result.
	// An old snapshot is not a valid rollback source after this point.
	defer srv.Close()
	combined := make(chan error, 1)
	monitorDone := make(chan struct{})
	defer close(monitorDone)
	go func() {
		select {
		case e := <-dataErr:
			combined <- e
		case <-serverErr:
			combined <- errors.New("authority status listener failed")
		case <-monitorDone:
		}
	}()
	result := serveResinAppUsingSignals(app, closer, combined, quit)
	a.fail() // retain a restart fence even on clean stop; owner-driven recovery only
	return result
}
