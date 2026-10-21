package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/Resinat/Resin/internal/buildinfo"
	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/node"
)

const maintenancePath = "/api/v1/system/maintenance"

// This protocol is an opt-in cold stop, not the old drain-only contract. A
// retained marker blocks bootstrap before migrations/consistency repair. No
// HTTP response, PID disappearance or dirty count is a handoff certificate.
type maintenanceRecord struct {
	Version     int                   `json:"version"`
	TransferID  string                `json:"transfer_id"`
	SourceSHA   string                `json:"source_sha"`
	PID         int                   `json:"pid"`
	StartedAtNs int64                 `json:"started_at_ns"`
	Phase       string                `json:"phase"`
	LeaseDigest string                `json:"lease_digest,omitempty"`
	LeaseCount  int                   `json:"lease_count"`
	Databases   []maintenanceDatabase `json:"databases,omitempty"`
}

type maintenanceDatabase struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type maintenanceController struct {
	mu        sync.Mutex
	path      string
	token     string
	enabled   bool
	closing   bool
	install   func(string, maintenanceRecord) (bool, error)
	record    maintenanceRecord
	requested chan struct{}
}

func maintenanceMarker(stateDir string) string {
	return filepath.Join(stateDir, "maintenance-handoff.json")
}

func rejectRetainedMaintenance(stateDir string) error {
	_, err := os.Lstat(maintenanceMarker(stateDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect maintenance marker: %w", err)
	}
	return errors.New("retained maintenance handoff blocks startup; explicit owner recovery required")
}

func newMaintenanceController(stateDir, token string, enabled bool) *maintenanceController {
	return &maintenanceController{path: maintenanceMarker(stateDir), token: token,
		enabled: enabled, install: installMaintenanceRecord, requested: make(chan struct{}),
		record: maintenanceRecord{Version: 1, SourceSHA: buildinfo.GitCommit,
			PID: os.Getpid(), StartedAtNs: time.Now().UnixNano(), Phase: "running"}}
}

func writeMaintenanceRecord(path string, record maintenanceRecord) error {
	_, err := installMaintenanceRecord(path, record)
	return err
}

// installed distinguishes the restart-fence rename from its durability ack.
func installMaintenanceRecord(path string, record maintenanceRecord) (installed bool, result error) {
	data, err := json.Marshal(record)
	if err != nil {
		return false, err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".maintenance-")
	if err != nil {
		return false, err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return false, err
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return false, err
	}
	if err := os.Rename(temporary, path); err != nil {
		return false, err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return true, err
	}
	return true, errors.Join(dir.Sync(), dir.Close())
}

func (m *maintenanceController) request() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.enabled || m.token == "" || m.closing {
		return errors.New("maintenance is not available")
	}
	if _, err := os.Lstat(m.path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("maintenance marker already exists or is inaccessible")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	m.record.TransferID = hex.EncodeToString(nonce)
	m.record.Phase = "requested"
	if installed, err := m.install(m.path, m.record); err != nil {
		// Atomic rename may already have happened. Retain admission closure and
		// notify the owner; failed durability must never return accepted/complete.
		// A pre-rename failure did not install a restart fence. Do not
		// stop a live app without that durable recovery boundary.
		if !installed {
			m.record.TransferID = ""
			m.record.Phase = "running"
			return err
		}
		m.closing = true
		m.record.Phase = "failed"
		close(m.requested)
		return err
	}
	m.closing = true
	close(m.requested)
	return nil
}

func (m *maintenanceController) closeAdmission() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closing = true
	return m.record.TransferID != ""
}

func (m *maintenanceController) isRequested() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.record.TransferID != ""
}

func (m *maintenanceController) phase(phase string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.record.Phase == "failed" && phase != "failed" {
		return errors.New("failed maintenance cannot produce a successful handoff")
	}
	m.record.Phase = phase
	if err := writeMaintenanceRecord(m.path, m.record); err != nil {
		m.record.Phase = "failed"
		return err
	}
	return nil
}

func (m *maintenanceController) wrapHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Authenticate protocol routes independently, including when ordinary
		// management auth is deliberately disabled. Empty token disables entry.
		if r.URL != nil && r.URL.Path == maintenancePath && m.enabled {
			if m.token == "" || r.Header.Get("Authorization") != "Bearer "+m.token {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if r.Method == http.MethodPost {
				if err := m.request(); err != nil {
					http.Error(w, "maintenance refused", http.StatusConflict)
					return
				}
			} else if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			m.mu.Lock()
			record := m.record
			m.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusAccepted)
			}
			_ = json.NewEncoder(w).Encode(record)
			return
		}
		m.mu.Lock()
		closed := m.closing
		m.mu.Unlock()
		if closed {
			http.Error(w, "maintenance admission closed", http.StatusServiceUnavailable)
			return
		}
		// The demux tracks this entire handler, including service memory side
		// effects, hijacked lifetime and tunnel timer recovery. Any handler that
		// passes before closure is joined by endpoint Shutdown, not forgotten.
		next.ServeHTTP(w, r)
	})
}

type maintenanceSOCKS struct {
	controller *maintenanceController
	next       inboundConnHandler
}

func (g *maintenanceSOCKS) ServeConnContext(ctx context.Context, conn net.Conn) {
	g.controller.mu.Lock()
	closed := g.controller.closing
	g.controller.mu.Unlock()
	if closed {
		_ = conn.Close()
		return
	}
	g.next.ServeConnContext(ctx, conn)
}

// verifyMaintenanceLeases is valid only after all handlers, timers, cleaners,
// scheduler, probes and feedback are joined and both persistence entries sealed.
// The sorted complete set checks missing/extra rows as well as all seven fields.
func (a *resinApp) verifyMaintenanceLeases() error {
	memory := a.topoRuntime.router.MaintenanceLeases()
	stored, err := a.engine.LoadAllLeases()
	if err != nil {
		return err
	}
	want, err := canonicalLeaseDigest(memory)
	if err != nil {
		return err
	}
	got, err := canonicalLeaseDigest(stored)
	if err != nil {
		return err
	}
	if want != got || len(memory) != len(stored) {
		return errors.New("maintenance seven-field lease set mismatch")
	}
	if err := a.verifyMaintenanceReferences(stored); err != nil {
		return err
	}
	a.maintenance.mu.Lock()
	a.maintenance.record.LeaseDigest = want
	a.maintenance.record.LeaseCount = len(memory)
	a.maintenance.mu.Unlock()
	return nil
}

// Reject leases that bootstrap RepairConsistency would remove. This is a
// read-only precondition, never cleanup/normalization or a replacement lease.
func (a *resinApp) verifyMaintenanceReferences(leases []model.Lease) error {
	platforms, err := a.engine.ListPlatforms()
	if err != nil {
		return err
	}
	subs, err := a.engine.ListSubscriptions()
	if err != nil {
		return err
	}
	statics, err := a.engine.LoadAllNodesStatic()
	if err != nil {
		return err
	}
	bindings, err := a.engine.LoadAllSubscriptionNodes()
	if err != nil {
		return err
	}
	platformIDs, subIDs, nodeIDs, retainedNodes := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, p := range platforms {
		platformIDs[p.ID] = true
	}
	for _, s := range subs {
		subIDs[s.ID] = true
	}
	for _, n := range statics {
		nodeIDs[n.Hash] = true
	}
	for _, b := range bindings {
		if !b.Evicted && subIDs[b.SubscriptionID] && nodeIDs[b.NodeHash] {
			retainedNodes[b.NodeHash] = true
		}
	}
	for _, lease := range leases {
		_, hashErr := node.ParseHex(lease.NodeHash)
		ip, ipErr := netip.ParseAddr(lease.EgressIP)
		if lease.PlatformID == "" || lease.Account == "" || !platformIDs[lease.PlatformID] ||
			!retainedNodes[lease.NodeHash] || hashErr != nil || ipErr != nil || !ip.IsValid() ||
			lease.CreatedAtNs <= 0 || lease.ExpiryNs < lease.CreatedAtNs || lease.LastAccessedNs < lease.CreatedAtNs {
			return errors.New("maintenance lease identity or bootstrap reference invalid")
		}
	}
	return nil
}

// canonicalLeaseDigest does not normalize identifiers or timestamps. JSON
// integer encoding retains nanosecond identity without float64 conversion.
func canonicalLeaseDigest(leases []model.Lease) (string, error) {
	sort.Slice(leases, func(i, j int) bool {
		if leases[i].PlatformID == leases[j].PlatformID {
			return leases[i].Account < leases[j].Account
		}
		return leases[i].PlatformID < leases[j].PlatformID
	})
	for i := 1; i < len(leases); i++ {
		if leases[i-1].PlatformID == leases[i].PlatformID && leases[i-1].Account == leases[i].Account {
			return "", errors.New("duplicate lease identity")
		}
	}
	if leases == nil {
		leases = []model.Lease{}
	}
	body, err := json.Marshal(leases)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

func syncMaintenanceFiles(paths ...string) error {
	for _, path := range paths {
		file, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return err
		}
		if err := errors.Join(file.Sync(), file.Close()); err != nil {
			return err
		}
		// Fsync directory entries as well; no WAL byte-copy as a snapshot.
		dir, err := os.Open(filepath.Dir(path))
		if err != nil {
			return err
		}
		if err := errors.Join(dir.Sync(), dir.Close()); err != nil {
			return err
		}
	}
	return nil
}

// Bind complete to the closed, fsynced file set, not just DirtyCount or SQL
// commit. A nonempty remaining WAL is not a closed-file snapshot boundary.
func (m *maintenanceController) bindClosedDatabases(paths ...string) error {
	var databases []maintenanceDatabase
	for _, path := range paths {
		if wal, err := os.Stat(path + "-wal"); err == nil && wal.Size() != 0 {
			return errors.New("nonempty WAL remains after database close")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return err
		}
		digest := sha256.New()
		_, readErr := io.Copy(digest, file)
		closeErr := file.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() == 0 {
			return errors.New("invalid closed database file")
		}
		db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1")
		if err != nil {
			return err
		}
		var check string
		checkErr := db.QueryRow("PRAGMA quick_check").Scan(&check)
		closeDBErr := db.Close()
		if err := errors.Join(checkErr, closeDBErr); err != nil {
			return err
		}
		if check != "ok" {
			return errors.New("closed database integrity confirmation failed")
		}
		databases = append(databases, maintenanceDatabase{Path: path, Size: info.Size(), SHA256: hex.EncodeToString(digest.Sum(nil))})
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.record.Databases = databases
	return nil
}

// timeoutFailure latches failure even if a Stop/SQL source ignores cancellation.
// The owner then parks with open DB handles, rather than entering a success join.
func (m *maintenanceController) timeoutFailure(ctx context.Context, stopped <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	select {
	case <-ctx.Done():
		_ = m.phase("failed")
	case <-stopped:
	}
}

func (a *resinApp) maintenanceBarrierError(ctx context.Context) error {
	var feedbackErr error
	if a.healthFeedback != nil {
		feedbackErr = a.healthFeedback.StopAndWait(ctx)
	}
	return errors.Join(ctx.Err(), a.engine.StrongWriteBarrierError(), a.engine.WeakWriteBarrierError(),
		a.topoRuntime.scheduler.BarrierError(), feedbackErr)
}
