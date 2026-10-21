package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/config"
	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/state"
)

func preflightFixture(t *testing.T, change func(*state.StateEngine)) preflightOptions {
	t.Helper()
	t.Setenv("RESIN_ADMIN_TOKEN", "preflight-fixture")
	t.Setenv("RESIN_PROXY_TOKEN", "preflight-fixture")
	root := t.TempDir()
	snapshot := filepath.Join(root, "snapshot")
	e, c, err := state.PersistenceBootstrap(snapshot, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	env, err := config.LoadEnvConfig()
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureDefaultPlatform(e, env, nil); err != nil {
		t.Fatal(err)
	}
	if err := ensureDefaultAccountHeaderRule(e); err != nil {
		t.Fatal(err)
	}
	l := model.Lease{PlatformID: "fixture-platform", Account: "fixture\u2028😀", NodeHash: strings.Repeat("a", 32), EgressIP: "203.0.113.9", CreatedAtNs: 1700000000000000001, ExpiryNs: 1900000000000000002, LastAccessedNs: 1700000000000000003}
	if err := e.UpsertPlatform(model.Platform{ID: l.PlatformID, Name: "Fixture", StickyTTLNs: int64(time.Hour), ReverseProxyMissAction: "TREAT_AS_EMPTY", AllocationPolicy: "BALANCED"}); err != nil {
		t.Fatal(err)
	}
	if err := e.UpsertSubscription(model.Subscription{ID: "sub", Name: "Sub", URL: "https://fixture.invalid/never-fetch", UpdateIntervalNs: int64(time.Minute), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := e.BulkUpsertNodesStatic([]model.NodeStatic{{Hash: l.NodeHash, RawOptions: json.RawMessage(`{"type":"http","server":"127.0.0.1","server_port":1}`), CreatedAtNs: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := e.BulkUpsertSubscriptionNodes([]model.SubscriptionNode{{SubscriptionID: "sub", NodeHash: l.NodeHash}}); err != nil {
		t.Fatal(err)
	}
	if err := e.BulkUpsertLeases([]model.Lease{l}); err != nil {
		t.Fatal(err)
	}
	if err := e.SetLeaseDisplayName(l.PlatformID, l.Account, "preserve-label"); err != nil {
		t.Fatal(err)
	}
	if change != nil {
		change(e)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	b := newMaintenanceController("", "", false)
	if err := b.bindClosedDatabases(context.Background(), filepath.Join(snapshot, "state.db"), filepath.Join(snapshot, "cache.db")); err != nil {
		t.Fatal(err)
	}
	leases, err := offlineLeases(context.Background(), filepath.Join(snapshot, "cache.db"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := canonicalLeaseDigest(leases)
	if err != nil {
		t.Fatal(err)
	}
	return preflightOptions{snapshot: snapshot, output: filepath.Join(root, "candidate"), stateSHA: b.record.Databases[0].SHA256, cacheSHA: b.record.Databases[1].SHA256, leaseSHA: d, leaseCount: len(leases)}
}

func sourceBytes(t *testing.T, o preflightOptions) [][]byte {
	t.Helper()
	var all [][]byte
	for _, name := range []string{"state.db", "cache.db"} {
		b, err := os.ReadFile(filepath.Join(o.snapshot, name))
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, b)
	}
	return all
}

func TestPreflightActualBootstrapPreservesCompleteLeaseAndStrongState(t *testing.T) {
	o := preflightFixture(t, nil)
	before := sourceBytes(t, o)
	r, err := candidatePreflight(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if r.Phase != "validated" || r.LeaseCount != 1 || r.LeaseDigest != o.leaseSHA || r.OutboundValidated || r.AuthorityActivated {
		t.Fatalf("incorrect proof: %+v", r)
	}
	if !reflect.DeepEqual(before, sourceBytes(t, o)) {
		t.Fatal("authority source changed")
	}
	leases, err := offlineLeases(context.Background(), r.Candidate[1].Path)
	if err != nil || !reflect.DeepEqual(leases, r.Leases) {
		t.Fatalf("candidate seven fields mismatch: %v", err)
	}
	for _, row := range r.Candidate {
		b, err := os.ReadFile(row.Path)
		if err != nil {
			t.Fatal(err)
		}
		d := sha256.Sum256(b)
		if hex.EncodeToString(d[:]) != row.SHA256 || int64(len(b)) != row.Size {
			t.Fatal("false candidate file identity")
		}
	}
	if err := rejectRetainedMaintenance(filepath.Join(o.output, "state")); err == nil {
		t.Fatal("validated copy started without authority commit")
	}
	if _, err := os.Stat(filepath.Join(o.output, "log")); !os.IsNotExist(err) {
		t.Fatal("observability initialized")
	}
	if _, err := candidatePreflight(context.Background(), o); err == nil {
		t.Fatal("existing candidate overwritten")
	}
}

func TestPreflightRejectsActualRepairPruningAndKeepsSource(t *testing.T) {
	for _, kind := range []string{"orphan", "invalid_ip", "missing_defaults"} {
		t.Run(kind, func(t *testing.T) {
			o := preflightFixture(t, func(e *state.StateEngine) {
				var err error
				switch kind {
				case "orphan":
					err = e.DeleteSubscription("sub")
				case "invalid_ip":
					ls, x := e.LoadAllLeases()
					if x != nil {
						t.Fatal(x)
					}
					ls[0].EgressIP = "not-an-IP"
					err = e.BulkUpsertLeases(ls)
				case "missing_defaults":
					err = e.DeleteAccountHeaderRule("*")
				}
				if err != nil {
					t.Fatal(err)
				}
			})
			before := sourceBytes(t, o)
			if _, err := candidatePreflight(context.Background(), o); err == nil {
				t.Fatal("lossy/mutating bootstrap certified")
			}
			if !reflect.DeepEqual(before, sourceBytes(t, o)) {
				t.Fatal("failed bootstrap changed authority")
			}
			raw, err := os.ReadFile(filepath.Join(o.output, "state", "candidate-preflight.json"))
			if err != nil {
				t.Fatal(err)
			}
			var m maintenanceRecord
			if json.Unmarshal(raw, &m) != nil || m.Phase != "failed" {
				t.Fatal("failure fence missing")
			}
		})
	}
}

func TestPreflightFixedIdentityAndClosedSidecarGates(t *testing.T) {
	o := preflightFixture(t, nil)
	original := o
	for _, kind := range []string{"digest", "count", "wal", "symlink", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			o = original
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "digest":
				o.stateSHA = strings.Repeat("0", 64)
			case "count":
				o.leaseCount++
			case "wal":
				p := filepath.Join(o.snapshot, "cache.db-wal")
				if err := os.WriteFile(p, []byte("unfinished"), 0600); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(p)
			case "symlink":
				link := filepath.Join(filepath.Dir(o.snapshot), "link")
				if err := os.Symlink(o.snapshot, link); err != nil {
					t.Fatal(err)
				}
				o.snapshot = link
			case "cancel":
				cancel()
			}
			if _, err := candidatePreflight(ctx, o); err == nil {
				t.Fatal("invalid precondition certified")
			}
			if _, err := os.Stat(o.output); !os.IsNotExist(err) {
				t.Fatal("failure before copy created candidate")
			}
		})
	}
}

func TestPreflightCLINoSecretsOrFalseSuccess(t *testing.T) {
	var out bytes.Buffer
	if err := preflightCLI([]string{"--snapshot-dir", "fixture-secret"}, &out); err == nil || strings.Contains(err.Error(), "fixture-secret") || out.Len() != 0 {
		t.Fatal("unsafe CLI failure")
	}
}

type preflightBrokenWriter struct{}

func (preflightBrokenWriter) Write([]byte) (int, error) { return 0, errors.New("fixture") }
func TestPreflightOutputFailureKeepsCandidateFenced(t *testing.T) {
	o := preflightFixture(t, nil)
	args := []string{"--snapshot-dir", o.snapshot, "--output-dir", o.output, "--state-sha256", o.stateSHA, "--cache-sha256", o.cacheSHA, "--lease-sha256", o.leaseSHA, "--lease-count", strconv.Itoa(o.leaseCount)}
	if err := preflightCLI(args, preflightBrokenWriter{}); err == nil {
		t.Fatal("failed receipt write succeeded")
	}
	raw, err := os.ReadFile(filepath.Join(o.output, "state", "candidate-preflight.json"))
	if err != nil {
		t.Fatal(err)
	}
	var marker maintenanceRecord
	if json.Unmarshal(raw, &marker) != nil || marker.Phase != "failed" {
		t.Fatal("output failure left validated marker")
	}
	if err := rejectRetainedMaintenance(filepath.Join(o.output, "state")); err == nil {
		t.Fatal("failed candidate allowed startup")
	}
}
