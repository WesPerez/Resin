package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/node"
)

func testAccountTLSProfile(index int) accountTLSProfile {
	return accountTLSProfile{ID: fmt.Sprintf("v1:%d:%s", index, strings.Repeat("a", 64)), Index: index}
}

func TestAccountTLSProfileValidation(t *testing.T) {
	valid := testAccountTLSProfile(42726)
	got, err := resolveAccountTLSProfile(valid.ID, "p", "a", true)
	if err != nil || got != valid {
		t.Fatalf("profile: %+v; error: %+v", got, err)
	}
	for _, value := range []string{"invalid", "v1:103680:" + strings.Repeat("a", 64), valid.ID + "\n"} {
		if _, err := resolveAccountTLSProfile(value, "p", "a", true); err != ErrInvalidTLSProfile {
			t.Fatalf("invalid profile accepted: %q", value)
		}
	}
	if _, err := resolveAccountTLSProfile(valid.ID, "p", "a", false); err != ErrAuthRequired {
		t.Fatal("open proxy accepted a control header")
	}
}

func TestTransportPoolSeparatesAccountsPlatformsProfilesAndBoundsCache(t *testing.T) {
	pool := NewOutboundTransportPool(OutboundTransportConfig{MaxTransports: 4})
	defer pool.CloseAll()
	hash := node.Hash{1}
	identity := outboundIdentity{Platform: "platform", Account: "a", TLS: testAccountTLSProfile(42726)}
	first := pool.getForIdentity(hash, &noopOutbound{}, nil, identity)
	if first.DialTLSContext == nil || first.ForceAttemptHTTP2 {
		t.Fatal("account transport must use its TLS dialer and a matching ALPN protocol")
	}
	for _, variant := range []outboundIdentity{
		{Platform: "platform", Account: "b", TLS: identity.TLS},
		{Platform: "other", Account: "a", TLS: identity.TLS},
		{Platform: "platform", Account: "a", TLS: testAccountTLSProfile(43735)},
	} {
		if first == pool.getForIdentity(hash, &noopOutbound{}, nil, variant) {
			t.Fatal("transport shared across an identity boundary")
		}
	}
	if first != pool.getForIdentity(hash, &noopOutbound{}, nil, identity) {
		t.Fatal("same account should reuse its transport")
	}
	pool.getForIdentity(node.Hash{2}, &noopOutbound{}, nil, identity)
	if len(pool.transports) != 4 || first != pool.getForIdentity(hash, &noopOutbound{}, nil, identity) {
		t.Fatal("LRU must bound the cache while preserving its most recently used entry")
	}
	pool.Evict(hash)
	if len(pool.transports) != 1 {
		t.Fatal("node eviction must remove all of its account transports")
	}
}

func TestAccountTLSClientHelloOnWire(t *testing.T) {
	type hello struct {
		Ciphers  []uint16
		Curves   []tls.CurveID
		Versions []uint16
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	observed := make(chan hello, 3)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			server := tls.Server(conn, &tls.Config{GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
				observed <- hello{append([]uint16(nil), info.CipherSuites...), append([]tls.CurveID(nil), info.SupportedCurves...), append([]uint16(nil), info.SupportedVersions...)}
				return nil, errors.New("capture complete")
			}})
			_ = server.Handshake()
			server.Close()
		}
	}()
	pool := newOutboundTransportPool()
	defer pool.CloseAll()
	var captures []hello
	for _, index := range []int{42726, 43735, 42726} {
		transport := pool.getForIdentity(node.Hash{}, nil, nil, outboundIdentity{Account: strconv.Itoa(index), TLS: testAccountTLSProfile(index)})
		req, _ := http.NewRequest(http.MethodGet, "https://"+listener.Addr().String(), nil)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := transport.RoundTrip(req.WithContext(ctx))
		cancel()
		if err == nil {
			t.Fatal("capture server unexpectedly completed a request")
		}
		select {
		case result := <-observed:
			captures = append(captures, result)
		case <-time.After(time.Second):
			t.Fatalf("ClientHello missing: %v", err)
		}
	}
	listener.Close()
	<-done
	if !reflect.DeepEqual(captures[0], captures[2]) || reflect.DeepEqual(captures[0], captures[1]) {
		t.Fatalf("profiles are not stable and distinct: %+v", captures)
	}
	if !reflect.DeepEqual(captures[0].Ciphers, []uint16{0x1303, 0x1302, 0x1301, 0xc02b, 0xc02c, 0xc02f, 0xcca8, 0xc030, 0xcca9}) {
		t.Fatalf("cipher order differs from the Metapi/curl v1 contract: %v", captures[0].Ciphers)
	}
	if !reflect.DeepEqual(captures[0].Curves, []tls.CurveID{tls.CurveP256, tls.CurveP521, tls.X25519, tls.CurveP384}) {
		t.Fatalf("curve order differs from the v1 contract: %v", captures[0].Curves)
	}
}

func TestAccountTLSRejectsUntrustedCertificates(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unverified request reached the server") }))
	defer server.Close()
	pool := newOutboundTransportPool()
	defer pool.CloseAll()
	transport := pool.getForIdentity(node.Hash{}, nil, nil, outboundIdentity{Account: "a", TLS: testAccountTLSProfile(42726)})
	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	_, err := transport.RoundTrip(req)
	var untrusted x509.UnknownAuthorityError
	if !errors.As(err, &untrusted) {
		t.Fatalf("expected certificate validation failure, got %v", err)
	}
}

func TestAccountTLSLocalTrustedHandshake(t *testing.T) {
	if target := os.Getenv("RESIN_TLS_TEST_TARGET"); target != "" {
		pool := newOutboundTransportPool()
		defer pool.CloseAll()
		var connections []string
		for _, index := range []int{42726, 42726, 43735, 42726} {
			transport := pool.getForIdentity(node.Hash{}, nil, nil, outboundIdentity{Account: strconv.Itoa(index), TLS: testAccountTLSProfile(index)})
			req, _ := http.NewRequest(http.MethodGet, target, nil)
			response, err := transport.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || string(body) != "verified" || response.ProtoMajor != 1 || response.Header.Get("X-Test-Version") != os.Getenv("RESIN_TLS_TEST_VERSION") {
				t.Fatalf("invalid TLS response: %v", err)
			}
			connections = append(connections, response.Header.Get("X-Test-Connection"))
		}
		if connections[0] != connections[1] || connections[0] != connections[3] || connections[0] == connections[2] {
			t.Fatalf("account connections are not isolated and reusable: %v", connections)
		}
		return
	}
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(strconv.Itoa(int(version)), func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Test-Version", strconv.Itoa(int(r.TLS.Version)))
				w.Header().Set("X-Test-Connection", r.RemoteAddr)
				w.Write([]byte("verified"))
			}))
			server.TLS = &tls.Config{MinVersion: version, MaxVersion: version}
			server.StartTLS()
			defer server.Close()
			certFile := filepath.Join(t.TempDir(), "test-root.pem")
			if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			// Root CA discovery is process-cached. A child process uses only this
			// temporary test CA, without changing trust or services on the host.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAccountTLSLocalTrustedHandshake$")
			cmd.Env = append(os.Environ(), "RESIN_TLS_TEST_TARGET="+server.URL, "RESIN_TLS_TEST_VERSION="+strconv.Itoa(int(version)), "SSL_CERT_FILE="+certFile, "SSL_CERT_DIR="+t.TempDir())
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("trusted TLS handshake failed: %v\n%s", err, output)
			}
		})
	}
}

func TestTLSControlHeaderIsStrippedAndAcknowledgedOnForwardAndReverseBypass(t *testing.T) {
	profile := testAccountTLSProfile(42726)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(accountTLSProfileHeader) != "" {
			t.Error("TLS control header leaked to upstream")
		}
		w.Header().Set(accountTLSProfileHeader, "spoofed")
		w.Header().Set("X-Resin-Error", "UPSTREAM_REQUEST_FAILED")
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	forward := NewForwardProxy(ForwardProxyConfig{ProxyToken: "tok", ProxyBypassRules: []string{"127.*"}})
	reverse := NewReverseProxy(ReverseProxyConfig{ProxyToken: "tok", ProxyBypassRules: []string{"127.*"}})
	defer forward.transportPool.CloseAll()
	defer reverse.transportPool.CloseAll()
	for _, handler := range []http.Handler{forward, reverse} {
		target := upstream.URL
		if handler == reverse {
			target = "/tok/plat:acct/http+tls-v1/" + strings.TrimPrefix(upstream.URL, "http://") + "/"
		}
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Header.Set("Proxy-Authorization", basicAuth("plat.acct", "tok"))
		req.Header.Set(accountTLSProfileHeader, profile.ID)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK || recorder.Header().Get(accountTLSProfileHeader) != profile.ID {
			t.Fatalf("status %d, acknowledgment %q", recorder.Code, recorder.Header().Get(accountTLSProfileHeader))
		}
		if recorder.Header().Get("X-Resin-Error") != "" {
			t.Fatal("upstream forged an internal Resin error")
		}
	}
}

func TestVersionedReversePathRequiresExplicitTLSProfile(t *testing.T) {
	proxy := NewReverseProxy(ReverseProxyConfig{ProxyToken: "tok"})
	defer proxy.transportPool.CloseAll()
	parsed, err := proxy.parsePath("/tok/plat:acct/https+tls-v1/example.com/a%2Fb")
	if err != nil || !parsed.RequiresTLSProfile || parsed.Protocol != "https" || parsed.Path != "a%2Fb" {
		t.Fatalf("invalid versioned reverse path: %+v; %v", parsed, err)
	}
	if _, err := proxy.parsePath("/tok/plat:acct/https+tls-v2/example.com/"); err != ErrInvalidProtocol {
		t.Fatalf("unsupported TLS protocol accepted: %v", err)
	}
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/tok/plat:acct/https+tls-v1/example.com/", nil))
	if recorder.Code != ErrInvalidTLSProfile.HTTPCode || recorder.Header().Get("X-Resin-Error") != ErrInvalidTLSProfile.ResinError {
		t.Fatalf("missing profile was not rejected before routing: %d", recorder.Code)
	}
}
