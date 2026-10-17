package api

import (
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/Resinat/Resin/internal/model"
)

func TestLeaseDisplayNameDoesNotChangeRoutingAndSearchIsCompatible(t *testing.T) {
	srv, cp, _ := newControlPlaneTestServer(t)
	id, account, _ := seedRotateLease(t, srv, cp, "display-names", 1)
	key := model.LeaseKey{PlatformID: id, Account: account}
	before := *cp.Router.ReadLease(key)
	path := "/api/v1/platforms/" + id + "/leases/" + account + "/display-name"
	name := "wd-account-42"
	rec := doJSONRequest(t, srv, http.MethodPatch, path, map[string]any{"display_name": name}, true)
	if rec.Code != http.StatusOK || decodeJSONMap(t, rec)["display_name"] != name {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body.String())
	}
	if after := cp.Router.ReadLease(key); after == nil || !reflect.DeepEqual(before, *after) {
		t.Fatalf("display edit changed lease: before=%+v after=%+v", before, after)
	}
	for _, search := range []string{name, account, "WD-ACCOUNT"} {
		rec = doJSONRequest(t, srv, http.MethodGet, "/api/v1/platforms/"+id+"/leases?search="+url.QueryEscape(search), nil, true)
		body := decodeJSONMap(t, rec)
		if rec.Code != http.StatusOK || body["total"] != float64(1) {
			t.Fatalf("search %q: %d %s", search, rec.Code, rec.Body.String())
		}
		item := body["items"].([]any)[0].(map[string]any)
		if item["account"] != account || item["display_name"] != name {
			t.Fatalf("wrong identity: %+v", item)
		}
	}
	// Existing account-prefix inventory clients must not start matching labels.
	rec = doJSONRequest(t, srv, http.MethodGet, "/api/v1/platforms/"+id+"/leases?account=wd-&fuzzy=true", nil, true)
	if decodeJSONMap(t, rec)["total"] != float64(0) {
		t.Fatal("account filter changed semantics")
	}
	// Expiry/deletion and renewal of the same identity do not erase its name.
	if err := cp.DeleteLease(id, account); err != nil {
		t.Fatal(err)
	}
	if err := cp.Router.UpsertLease(before); err != nil {
		t.Fatal(err)
	}
	renewed, err := cp.GetLease(id, account)
	if err != nil || renewed.DisplayName != name {
		t.Fatalf("name lost on renewal: %+v %v", renewed, err)
	}
	rec = doJSONRequest(t, srv, http.MethodPatch, path, map[string]any{"display_name": ""}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("clear: %s", rec.Body.String())
	}
	if !reflect.DeepEqual(before, *cp.Router.ReadLease(key)) {
		t.Fatal("clear changed lease")
	}
}

func TestLeaseDisplayNameAutomaticCAS(t *testing.T) {
	srv, cp, _ := newControlPlaneTestServer(t)
	id, account, _ := seedRotateLease(t, srv, cp, "display-cas", 1)
	key := model.LeaseKey{PlatformID: id, Account: account}
	before := *cp.Router.ReadLease(key)
	path := "/api/v1/platforms/" + id + "/leases/" + account + "/display-name"
	body := func() map[string]any {
		return map[string]any{
			"display_name": "hub-16", "if_empty": true, "expected_node_hash": before.NodeHash,
			"expected_egress_ip": before.EgressIP, "expected_created_at_ns": strconv.FormatInt(before.CreatedAtNs, 10),
		}
	}
	for field, value := range map[string]string{"expected_node_hash": strings.Repeat("b", 32), "expected_egress_ip": "192.0.2.254", "expected_created_at_ns": strconv.FormatInt(before.CreatedAtNs+1, 10)} {
		request := body()
		request[field] = value
		rec := doJSONRequest(t, srv, http.MethodPatch, path, request, true)
		if rec.Code != http.StatusConflict {
			t.Fatalf("stale %s: %d %s", field, rec.Code, rec.Body.String())
		}
		got, err := cp.GetLease(id, account)
		if err != nil || got.DisplayName != "" || !reflect.DeepEqual(before, *cp.Router.ReadLease(key)) {
			t.Fatal("rejected CAS changed metadata or route")
		}
	}
	for _, field := range []string{"expected_node_hash", "expected_egress_ip", "expected_created_at_ns"} {
		request := body()
		delete(request, field)
		if rec := doJSONRequest(t, srv, http.MethodPatch, path, request, true); rec.Code != http.StatusBadRequest {
			t.Fatalf("missing %s: %d", field, rec.Code)
		}
	}
	for i := 0; i < 2; i++ {
		rec := doJSONRequest(t, srv, http.MethodPatch, path, body(), true)
		if rec.Code != http.StatusOK || decodeJSONMap(t, rec)["display_name_cas_version"] != float64(1) {
			t.Fatalf("CAS: %d %s", rec.Code, rec.Body.String())
		}
	}
	get := doJSONRequest(t, srv, http.MethodGet, strings.TrimSuffix(path, "/display-name"), nil, true)
	if get.Code != http.StatusOK || decodeJSONMap(t, get)["display_name_cas_version"] != float64(1) {
		t.Fatal("GET did not advertise CAS capability")
	}
	if !reflect.DeepEqual(before, *cp.Router.ReadLease(key)) {
		t.Fatal("CAS changed route")
	}
	if rec := doJSONRequest(t, srv, http.MethodPatch, path, map[string]any{"display_name": "manual"}, true); rec.Code != http.StatusOK {
		t.Fatal("manual edit failed")
	}
	if rec := doJSONRequest(t, srv, http.MethodPatch, path, body(), true); rec.Code != http.StatusConflict {
		t.Fatal("automatic edit replaced manual name")
	}
	got, err := cp.GetLease(id, account)
	if err != nil || got.DisplayName != "manual" {
		t.Fatal("manual name lost")
	}
	request := body()
	request["display_name"] = ""
	if rec := doJSONRequest(t, srv, http.MethodPatch, path, request, true); rec.Code != http.StatusBadRequest {
		t.Fatal("automatic clear accepted")
	}
}

func TestLeaseDisplayNameRejectsInvalidOrUnauthenticatedUpdates(t *testing.T) {
	srv, cp, _ := newControlPlaneTestServer(t)
	id, account, _ := seedRotateLease(t, srv, cp, "display-invalid", 1)
	path := "/api/v1/platforms/" + id + "/leases/" + account + "/display-name"
	for _, body := range []any{map[string]any{}, map[string]any{"display_name": nil}, map[string]any{"display_name": "a\nb"}, map[string]any{"display_name": "a\u202eb"}, map[string]any{"display_name": strings.Repeat("a", 129)}, map[string]any{"display_name": "ok", "account": "other"}} {
		rec := doJSONRequest(t, srv, http.MethodPatch, path, body, true)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid body accepted: %d %s", rec.Code, rec.Body.String())
		}
	}
	rec := doJSONRequest(t, srv, http.MethodPatch, path, map[string]any{"display_name": "wd-42"}, false)
	if rec.Code == http.StatusOK {
		t.Fatal("unauthenticated edit accepted")
	}
}
