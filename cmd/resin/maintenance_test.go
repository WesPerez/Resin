package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/model"
)

func TestMaintenanceAuthenticationDurableRequestAndRestartBlock(t *testing.T) {
	dir := t.TempDir()
	m := newMaintenanceController(dir, "fixture-admin", true)
	called := 0
	h := m.wrapHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called++ }))
	request := httptest.NewRequest(http.MethodPost, maintenancePath, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request)
	if w.Code != http.StatusUnauthorized || m.isRequested() {
		t.Fatal("unauthenticated maintenance changed admission")
	}
	request.Header.Set("Authorization", "Bearer fixture-admin")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, request)
	if w.Code != http.StatusAccepted || called != 0 {
		t.Fatalf("request was not accepted: %d", w.Code)
	}
	var record maintenanceRecord
	body, err := os.ReadFile(maintenanceMarker(dir))
	if err != nil || json.Unmarshal(body, &record) != nil || record.Phase != "requested" || record.TransferID == "" {
		t.Fatalf("durable requested record missing: %v", err)
	}
	if err := rejectRetainedMaintenance(dir); err == nil {
		t.Fatal("retained request failed to block startup before database repair")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPatch, "/api/v1/platforms/p/leases/a/display-name", nil))
	if w.Code != http.StatusServiceUnavailable || called != 0 {
		t.Fatal("management mutation admitted after closure")
	}
	if err := m.phase("failed"); err != nil {
		t.Fatal(err)
	}
	if err := m.phase("complete"); err == nil {
		t.Fatal("failed operation generated successful handoff")
	}
}

func TestMaintenanceMarkerUnknownAndSymlinkBlockBeforeBootstrap(t *testing.T) {
	for _, kind := range []string{"unknown", "symlink"} {
		dir := t.TempDir()
		path := maintenanceMarker(dir)
		var err error
		if kind == "unknown" {
			err = os.WriteFile(path, []byte("not-json"), 0o600)
		} else {
			err = os.Symlink(filepath.Join(dir, "missing"), path)
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := rejectRetainedMaintenance(dir); err == nil {
			t.Fatal("unknown marker accepted")
		}
	}
}

func TestMaintenanceDemuxJoinsLastAdmittedManagementHandler(t *testing.T) {
	m := newMaintenanceController(t.TempDir(), "fixture", true)
	entered, release, completed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unlock := func() { once.Do(func() { close(release) }) }
	h := m.wrapHTTP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release // represents SQL commit followed by last memory side effect.
		close(completed)
		w.WriteHeader(http.StatusNoContent)
	}))
	s := newInboundDemuxServer(&http.Server{Handler: h}, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan struct{})
	go func() { defer close(serveDone); _ = s.Serve(ln) }()
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		client := &http.Client{Timeout: 2 * time.Second}
		response, err := client.Get("http://" + ln.Addr().String() + "/api/v1/fixture")
		if err == nil {
			_ = response.Body.Close()
		}
	}()
	t.Cleanup(func() { unlock(); _ = s.Shutdown(context.Background(), false); <-serveDone; <-clientDone })
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler not admitted")
	}
	if err := m.request(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.Shutdown(ctx, true); err == nil {
		t.Fatal("deadline certified while management handler was live")
	}
	select {
	case <-completed:
		t.Fatal("fixture side effect ran before release")
	default:
	}
	unlock()
	if err := s.Shutdown(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	<-completed
}

func TestCanonicalSevenFieldLeaseSetRejectsEveryFieldChange(t *testing.T) {
	want := model.Lease{PlatformID: "p", Account: "a", NodeHash: "n", EgressIP: "203.0.113.9",
		CreatedAtNs: 1700000000000000001, ExpiryNs: 1800000000000000002, LastAccessedNs: 1700000000000000003}
	base, err := canonicalLeaseDigest([]model.Lease{want})
	if err != nil {
		t.Fatal(err)
	}
	variants := make([]model.Lease, 7)
	for i := range variants {
		variants[i] = want
	}
	variants[0].PlatformID += "x"
	variants[1].Account += "x"
	variants[2].NodeHash += "x"
	variants[3].EgressIP = "203.0.113.10"
	variants[4].CreatedAtNs++
	variants[5].ExpiryNs++
	variants[6].LastAccessedNs++
	for _, changed := range variants {
		got, err := canonicalLeaseDigest([]model.Lease{changed})
		if err != nil || got == base {
			t.Fatal("changed seven-field tuple was accepted")
		}
	}
	if _, err := canonicalLeaseDigest([]model.Lease{want, want}); err == nil {
		t.Fatal("duplicate accepted")
	}
	missing, _ := canonicalLeaseDigest(nil)
	if missing == base {
		t.Fatal("missing lease accepted")
	}
}
