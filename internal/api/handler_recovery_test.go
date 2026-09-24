package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRecoveryActions_AuthenticationAndContract(t *testing.T) {
	srv, cp, _ := newControlPlaneTestServer(t)
	name := "Recovery"
	mustCreatePlatform(t, srv, name)
	for _, action := range []string{"acquire", "report-failure"} {
		body := `{"target_host":"example.com:443"}`
		if action == "report-failure" {
			body = `{"target_host":"example.com:443","expected_node_hash":"11111111111111111111111111111111","expected_created_at_ns":"1790000000000000001","reason":"empty_stream"}`
		}
		for _, tc := range []struct {
			name, configured, auth string
			status                 int
		}{
			{"missing", "test-secret", "", http.StatusNotFound},
			{"wrong", "test-secret", "Bearer wrong", http.StatusNotFound},
			{"admin-not-proxy", "test-secret", "Bearer " + testAdminToken, http.StatusNotFound},
			{"empty-config", "", "Bearer test-secret", http.StatusNotFound},
			{"good", "test-secret", "Bearer test-secret", http.StatusOK},
		} {
			t.Run(action+"/"+tc.name, func(t *testing.T) {
				handler := NewTokenActionHandler(tc.configured, cp, 1<<20)
				req := httptest.NewRequest(http.MethodPost, "/proxy-api/v1/"+name+"/leases/sub2-test/actions/"+action, strings.NewReader(body))
				req.Header.Set("Authorization", tc.auth)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != tc.status {
					t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.status, rec.Body.String())
				}
				if strings.Contains(rec.Body.String(), "test-secret") {
					t.Fatal("token leaked in response")
				}
				if tc.status == http.StatusOK {
					value := decodeJSONMap(t, rec)
					if value["recovery_version"] != float64(1) {
						t.Fatalf("missing capability: %v", value)
					}
					want := "no_alternative"
					if action == "report-failure" {
						want = "stale_lease"
					}
					if value["status"] != want {
						t.Fatalf("status=%v want=%s", value["status"], want)
					}
				}
			})
		}
	}
}

func TestRecoveryActions_RejectMalformedInput(t *testing.T) {
	srv, cp, _ := newControlPlaneTestServer(t)
	mustCreatePlatform(t, srv, "Recovery")
	handler := NewTokenActionHandler("test-secret", cp, 1024)
	for _, tc := range []struct{ name, action, account, body string }{
		{"missing-target", "acquire", "account", `{}`},
		{"url-not-host", "acquire", "account", `{"target_host":"https://example.com"}`},
		{"bad-port", "acquire", "account", `{"target_host":"example.com:99999"}`},
		{"guard-account", "acquire", "account~r1~bad", `{"target_host":"example.com"}`},
		{"extra-field", "acquire", "account", `{"target_host":"example.com","extra":true}`},
		{"suffix", "acquire", "account", `{"target_host":"example.com"}{}`},
		{"invalid-reason", "report-failure", "account", `{"target_host":"example.com","reason":"quota_exhausted"}`},
		{"invalid-node", "report-failure", "account", `{"target_host":"example.com","reason":"empty_stream","expected_node_hash":"bad","expected_created_at_ns":"1"}`},
		{"invalid-generation", "report-failure", "account", `{"target_host":"example.com","reason":"transport_error","expected_node_hash":"11111111111111111111111111111111","expected_created_at_ns":"0"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/proxy-api/v1/Recovery/leases/"+tc.account+"/actions/"+tc.action, strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer test-secret")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestRecoveryStatus_RequiresAdminAndExposesNoIdentities(t *testing.T) {
	srv, _, _ := newControlPlaneTestServer(t)
	unauth := doJSONRequest(t, srv, http.MethodGet, "/api/v1/system/recovery", nil, false)
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", unauth.Code)
	}
	authed := doJSONRequest(t, srv, http.MethodGet, "/api/v1/system/recovery", nil, true)
	if authed.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", authed.Code, authed.Body.String())
	}
	value := decodeJSONMap(t, authed)
	if value["rotated"] != float64(0) || value["limited"] != float64(0) || value["since"] == nil {
		t.Fatalf("invalid counters: %v", value)
	}
	for _, field := range []string{"account", "token", "node", "platform_id"} {
		if _, found := value[field]; found {
			t.Fatalf("unexpected identity field: %s", field)
		}
	}
}
