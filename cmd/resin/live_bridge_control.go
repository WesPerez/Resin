package main

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Resinat/Resin/internal/buildinfo"
	"github.com/Resinat/Resin/internal/model"
)

const liveMarker = "live-handoff.json"

type liveRecord struct {
	Phase        string `json:"phase"`
	SHA          string `json:"sha"`
	Epoch        uint64 `json:"epoch"`
	LeaseDigest  string `json:"lease_digest"`
	LeaseCount   int    `json:"lease_count"`
	StrongDigest string `json:"strong_digest"`
}

type liveStageRequest struct {
	Epoch        uint64        `json:"epoch"`
	CutoffNs     int64         `json:"cutoff_ns"`
	StrongDigest string        `json:"strong_digest"`
	LeaseDigest  string        `json:"lease_digest"`
	Leases       []model.Lease `json:"leases"`
}

// The online digest includes committed WAL; immutable=1 is ONLY correct for
// the existing stopped preflight copies, never a running source database.
func liveStrongDigest(ctx context.Context, path string) (string, error) {
	u := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return "", err
	}
	defer db.Close()
	return logicalDigestDB(ctx, db)
}

func liveLoopbackListener(address string) (net.Listener, error) {
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() || port == "" || port == "0" {
		return nil, errors.New("live control requires explicit loopback address")
	}
	return net.Listen("tcp", address)
}

func (b *liveBridge) startControl() error {
	if b.app.envCfg.AdminToken == "" {
		return errors.New("live control requires admin authentication")
	}
	control, err := liveLoopbackListener(os.Getenv("RESIN_LIVE_CONTROL"))
	if err != nil {
		return err
	}
	probe, err := liveLoopbackListener(os.Getenv("RESIN_LIVE_PROBE"))
	if err != nil {
		control.Close()
		return err
	}
	b.listeners = []net.Listener{control, probe}
	b.control = &http.Server{Handler: http.HandlerFunc(b.controlHTTP), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 4 * time.Second, WriteTimeout: 5 * time.Second}
	b.probe = &http.Server{Handler: http.HandlerFunc(b.probeHTTP), ReadHeaderTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second}
	go b.control.Serve(control)
	go b.probe.Serve(probe)
	return nil
}

func (b *liveBridge) status() map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	sockets := make([]bridgeSocket, 0, len(b.sockets))
	for _, s := range b.sockets {
		sockets = append(sockets, s)
	}
	return map[string]any{"phase": b.phase, "durable": b.durable, "epoch": b.epoch, "inflight": b.inflight, "probes": b.probes, "sockets": sockets, "source": b.source, "sha": buildinfo.GitCommit}
}

func decodeLive(r *http.Request, v any) error {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4*1024*1024+1))
	if err != nil || len(raw) > 4*1024*1024 {
		return errors.New("live body too large")
	}
	return strictAuthorityJSON(raw, v)
}

func (b *liveBridge) controlHTTP(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+b.app.envCfg.AdminToken)) != 1 {
		http.Error(w, "unauthorized", 401)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet && r.URL.Path == "/live/status" {
		_ = json.NewEncoder(w).Encode(b.status())
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/live/strong" {
		d, err := liveStrongDigest(r.Context(), filepath.Join(b.app.envCfg.StateDir, "state.db"))
		if err != nil {
			http.Error(w, "digest failed", 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"strong_digest": d})
		return
	}
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var err error
	switch r.URL.Path {
	case "/live/pause":
		var req struct {
			Milliseconds int `json:"milliseconds"`
		}
		if err = decodeLive(r, &req); err == nil {
			var epoch uint64
			epoch, err = b.pause(time.Duration(req.Milliseconds) * time.Millisecond)
			if err == nil {
				_ = json.NewEncoder(w).Encode(map[string]any{"epoch": epoch})
				return
			}
		}
	case "/live/resume":
		var req struct {
			Epoch uint64 `json:"epoch"`
		}
		if err = decodeLive(r, &req); err == nil {
			b.mu.Lock()
			if b.epoch != req.Epoch || b.phase != "queued" {
				err = errors.New("resume epoch or phase differs")
			} else {
				b.resumeLocked()
			}
			b.mu.Unlock()
		}
	case "/live/stage":
		var req liveStageRequest
		if err = decodeLive(r, &req); err == nil {
			err = b.stage(r.Context(), req)
		}
	case "/live/activate":
		var req struct {
			Epoch       uint64 `json:"epoch"`
			LeaseDigest string `json:"lease_digest"`
		}
		if err = decodeLive(r, &req); err == nil {
			err = b.activate(r.Context(), req.Epoch, req.LeaseDigest)
		}
	case "/live/finalize":
		var req struct {
			Epoch       uint64 `json:"epoch"`
			LeaseDigest string `json:"lease_digest"`
		}
		if err = decodeLive(r, &req); err == nil {
			err = b.finalize(req.Epoch, req.LeaseDigest)
		}
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "live transition refused; read status", 409)
		return
	}
	_ = json.NewEncoder(w).Encode(b.status())
}

func (b *liveBridge) stage(ctx context.Context, req liveStageRequest) error {
	if !b.transitionMu.TryLock() {
		return errors.New("transition already running")
	}
	defer b.transitionMu.Unlock()
	if !b.nativeMu.TryLock() {
		return errors.New("native probe is still running")
	}
	defer b.nativeMu.Unlock()
	b.mu.Lock()
	allowed := b.phase == "queued" && b.epoch == req.Epoch && b.inflight == 0 && b.probes == 0 && time.Now().Before(b.deadline)
	deadline := b.deadline
	b.mu.Unlock()
	if !allowed {
		return errors.New("standby is not quiescent")
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if req.CutoffNs < time.Now().Add(-3*time.Second).UnixNano() || req.CutoffNs > time.Now().Add(3*time.Second).UnixNano() {
		return errors.New("stale cutoff")
	}
	digest, err := canonicalLeaseDigest(req.Leases)
	if err != nil || digest != req.LeaseDigest {
		return errors.New("lease digest mismatch")
	}
	strong, err := liveStrongDigest(ctx, filepath.Join(b.app.envCfg.StateDir, "state.db"))
	if err != nil || strong != req.StrongDigest {
		return errors.New("strong snapshot differs")
	}
	if err = b.app.topoRuntime.router.ValidateHandoffLeases(req.Leases, req.CutoffNs); err != nil {
		return err
	}
	if err = b.app.engine.ReplaceHandoffLeases(ctx, req.Leases); err != nil {
		return err
	}
	b.app.topoRuntime.router.ReplaceHandoffLeases(req.Leases)
	rows, err := b.app.engine.LoadAllLeases()
	if err != nil {
		return err
	}
	persisted, err := canonicalLeaseDigest(rows)
	if err != nil || persisted != digest {
		return errors.New("lease persistence differs")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = b.app.engine.CheckpointDurable(ctx); err != nil {
		return err
	}
	if err = syncMaintenanceFiles(filepath.Join(b.app.envCfg.StateDir, "state.db"), filepath.Join(b.app.envCfg.CacheDir, "cache.db")); err != nil {
		return err
	}
	record := liveRecord{Phase: "staged", SHA: buildinfo.GitCommit, Epoch: req.Epoch, LeaseDigest: digest, LeaseCount: len(rows), StrongDigest: strong}
	_, err = installDurableRecord(filepath.Join(b.app.envCfg.StateDir, liveMarker), record)
	return err
}

func (b *liveBridge) activate(ctx context.Context, epoch uint64, digest string) error {
	if !b.transitionMu.TryLock() {
		return errors.New("transition already running")
	}
	defer b.transitionMu.Unlock()
	path := filepath.Join(b.app.envCfg.StateDir, liveMarker)
	raw, err := os.ReadFile(path)
	var record liveRecord
	if err != nil || strictAuthorityJSON(raw, &record) != nil || record.Phase != "staged" || record.Epoch != epoch || record.LeaseDigest != digest || record.SHA != buildinfo.GitCommit {
		return errors.New("staged identity differs")
	}
	b.mu.Lock()
	ready := b.phase == "queued" && b.epoch == epoch && b.inflight == 0 && b.probes == 0 && time.Now().Before(b.deadline)
	b.mu.Unlock()
	if !ready {
		return errors.New("activation no longer quiescent")
	}
	rows, err := b.app.engine.LoadAllLeases()
	if err != nil {
		return err
	}
	actual, err := canonicalLeaseDigest(rows)
	if err != nil || actual != record.LeaseDigest {
		return errors.New("staged lease set changed")
	}
	strong, err := liveStrongDigest(ctx, filepath.Join(b.app.envCfg.StateDir, "state.db"))
	if err != nil || strong != record.StrongDigest {
		return errors.New("staged strong state changed")
	}
	// Persist intent outside the mode lock: a stalled fsync must not prevent
	// the three-second timer from resuming the old authority.
	record.Phase = "intent"
	if _, err = installDurableRecord(path, record); err != nil {
		return err
	}
	b.mu.Lock()
	if ctx.Err() != nil || b.phase != "queued" || b.epoch != epoch || b.inflight != 0 || b.probes != 0 || !time.Now().Before(b.deadline) {
		b.resumeLocked()
		b.mu.Unlock()
		return errors.New("activation expired; bridge resumed")
	}
	b.phase = "local"
	close(b.wake)
	b.mu.Unlock()
	b.app.startBackgroundServices()
	record.Phase = "local"
	_, err = installDurableRecord(path, record)
	if err == nil {
		b.mu.Lock()
		b.durable = true
		b.mu.Unlock()
	}
	return err // an unknown reply is recovered by status, never replay activate
}

// An idempotent durability repair after confirmed activation; never flips mode
// or restarts workers. It cannot certify an expired staged/bridge authority.
func (b *liveBridge) finalize(epoch uint64, digest string) error {
	if !b.transitionMu.TryLock() {
		return errors.New("transition already running")
	}
	defer b.transitionMu.Unlock()
	b.mu.Lock()
	local := b.phase == "local" && b.epoch == epoch
	b.mu.Unlock()
	if !local {
		return errors.New("local authority not confirmed")
	}
	path := filepath.Join(b.app.envCfg.StateDir, liveMarker)
	raw, err := os.ReadFile(path)
	var record liveRecord
	if err != nil || strictAuthorityJSON(raw, &record) != nil || record.Epoch != epoch || record.LeaseDigest != digest || record.SHA != buildinfo.GitCommit || (record.Phase != "intent" && record.Phase != "local") {
		return errors.New("local marker identity differs")
	}
	record.Phase = "local"
	if _, err = installDurableRecord(path, record); err != nil {
		return err
	}
	b.mu.Lock()
	b.durable = true
	b.mu.Unlock()
	return nil
}

func (b *liveBridge) probeHTTP(w http.ResponseWriter, r *http.Request) {
	b.nativeMu.RLock()
	defer b.nativeMu.RUnlock()
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Resin-Live-Probe")), []byte(b.app.envCfg.AdminToken)) != 1 {
		http.Error(w, "unauthorized", 401)
		return
	}
	// Native smoke may only use an already existing guarded lease. It cannot
	// allocate, rotate, delete, or write control-plane configuration.
	allowed := r.Method == http.MethodGet && (r.URL.Path == "/healthz" || strings.HasPrefix(r.URL.Path, "/api/v1/"))
	if r.Method == http.MethodConnect {
		encoded := strings.TrimPrefix(r.Header.Get("Proxy-Authorization"), "Basic ")
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		user, _, _ := strings.Cut(string(decoded), ":")
		allowed = err == nil && strings.Contains(user, "~r1~")
	}
	if !allowed {
		http.Error(w, "only read-only or guarded native probes allowed", 405)
		return
	}
	b.mu.Lock()
	if b.phase != "bridge" {
		b.mu.Unlock()
		http.Error(w, "native probe unavailable", 409)
		return
	}
	b.probes++
	b.mu.Unlock()
	defer func() { b.mu.Lock(); b.probes--; b.mu.Unlock() }()
	r.Header.Del("X-Resin-Live-Probe")
	b.localHTTP.ServeHTTP(w, r)
}

// Explicit local marker is the only restart permission for the imported DB.
// An intent after an interrupted commit is not inferred to be either authority.
func readLiveRestart(stateDir string) (bool, error) {
	raw, err := os.ReadFile(filepath.Join(stateDir, liveMarker))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var record liveRecord
	if strictAuthorityJSON(raw, &record) != nil || record.SHA != buildinfo.GitCommit {
		return false, errors.New("invalid live handoff marker")
	}
	if record.Phase == "local" {
		return true, nil
	}
	if record.Phase == "staged" {
		return false, nil
	}
	return false, errors.New("unknown live handoff authority requires owner recovery")
}
