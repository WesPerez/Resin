package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/config"
	"github.com/Resinat/Resin/internal/state"
)

func fixtureBridge(t *testing.T, handler http.Handler) (*liveBridge, *httptest.Server) {
	t.Helper()
	source := httptest.NewServer(handler)
	t.Cleanup(source.Close)
	b, err := newLiveBridge(strings.TrimPrefix(source.URL, "http://"), "127.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	candidate := httptest.NewServer(b)
	t.Cleanup(candidate.Close)
	return b, candidate
}

func TestLiveBridgeNoReplayOfUnknownPOST(t *testing.T) {
	var received atomic.Int64
	b, candidate := fixtureBridge(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != "one payload" {
			t.Errorf("body=%q", body)
		}
		received.Add(1)
		c, _, _ := w.(http.Hijacker).Hijack()
		c.Close()
	}))
	r, err := http.Post(candidate.URL, "application/octet-stream", strings.NewReader("one payload"))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 502 || received.Load() != 1 {
		t.Fatalf("status=%d requests=%d", r.StatusCode, received.Load())
	}
	if b.status()["inflight"] != 0 {
		t.Fatal("request ownership leaked")
	}
}

func TestLiveBridgeQueueExpiresWithoutResetOrReplay(t *testing.T) {
	var calls atomic.Int64
	b, candidate := fixtureBridge(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, "source") }))
	if _, err := b.pause(120 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var failures atomic.Int64
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := http.Get(candidate.URL)
			if err != nil {
				failures.Add(1)
				return
			}
			body, _ := io.ReadAll(r.Body)
			r.Body.Close()
			if r.StatusCode != 200 || string(body) != "source" {
				failures.Add(1)
			}
		}()
	}
	time.Sleep(30 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatal("request bypassed queue")
	}
	wg.Wait()
	if failures.Load() != 0 || calls.Load() != 24 || b.status()["phase"] != "bridge" {
		t.Fatalf("queue lost requests: calls=%d failures=%d", calls.Load(), failures.Load())
	}
}

func openFixtureConnect(t *testing.T, address string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(c, "CONNECT echo.invalid:443 HTTP/1.1\r\nHost: echo.invalid:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	response, err := http.ReadResponse(r, &http.Request{Method: "CONNECT"})
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("CONNECT: %v %+v", err, response)
	}
	return c, r
}

func TestLiveBridgeOldTunnelAndKeepaliveSurviveModeFlip(t *testing.T) {
	b, candidate := fixtureBridge(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			io.WriteString(w, "source")
			return
		}
		c, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		io.WriteString(buf, "HTTP/1.1 200 Connection Established\r\n\r\n")
		buf.Flush()
		for {
			line, err := buf.ReadBytes('\n')
			if err != nil {
				return
			}
			if _, err = c.Write(line); err != nil {
				return
			}
		}
	}))
	b.localHTTP = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "local") })
	address := strings.TrimPrefix(candidate.URL, "http://")
	old, reader := openFixtureConnect(t, address)
	defer old.Close()
	checkEcho := func(value string) {
		t.Helper()
		old.SetDeadline(time.Now().Add(time.Second))
		io.WriteString(old, value+"\n")
		line, err := reader.ReadString('\n')
		if err != nil || line != value+"\n" {
			t.Fatalf("tunnel lost: %q %v", line, err)
		}
	}
	checkEcho("before")
	keep, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer keep.Close()
	kr := bufio.NewReader(keep)
	get := func(want string) {
		t.Helper()
		io.WriteString(keep, "GET / HTTP/1.1\r\nHost: fixture\r\n\r\n")
		response, err := http.ReadResponse(kr, &http.Request{Method: "GET"})
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if string(body) != want {
			t.Fatalf("got %q want %q", body, want)
		}
	}
	get("source")
	if _, err := b.pause(time.Second); err != nil {
		t.Fatal(err)
	}
	if b.status()["inflight"] != 0 {
		t.Fatal("established tunnel counted as handshake")
	}
	b.mu.Lock()
	b.phase = "local"
	close(b.wake)
	b.mu.Unlock()
	get("local")
	checkEcho("after")
	response, err := http.Get(candidate.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != "local" {
		t.Fatal("new connection did not reach local")
	}
}

func TestLiveBridgeSOCKSHandshakeAndTunnel(t *testing.T) {
	source, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	sourceDone := make(chan struct{})
	go func() {
		defer close(sourceDone)
		c, err := source.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		h := make([]byte, 3)
		if _, err = io.ReadFull(c, h); err != nil {
			return
		}
		c.Write([]byte{5, 0})
		request := make([]byte, 10)
		if _, err = io.ReadFull(c, request); err != nil {
			return
		}
		c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80})
		io.Copy(c, c)
	}()
	b, err := newLiveBridge(source.Addr().String(), "127.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	bridgeDone := make(chan struct{})
	go func() {
		defer close(bridgeDone)
		c, err := ln.Accept()
		if err == nil {
			b.ServeConnContext(context.Background(), c)
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write([]byte{5, 1, 0})
	reply := make([]byte, 2)
	io.ReadFull(c, reply)
	if !bytes.Equal(reply, []byte{5, 0}) {
		t.Fatalf("greeting %v", reply)
	}
	c.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80})
	reply = make([]byte, 10)
	io.ReadFull(c, reply)
	if reply[1] != 0 {
		t.Fatal("SOCKS failed")
	}
	c.Write([]byte("echo"))
	reply = make([]byte, 4)
	_, err = io.ReadFull(c, reply)
	if err != nil || string(reply) != "echo" {
		t.Fatalf("SOCKS echo %q %v", reply, err)
	}
	c.Close()
	<-bridgeDone
	<-sourceDone
	if b.status()["inflight"] != 0 {
		t.Fatal("SOCKS ownership leaked")
	}
}

func TestLiveDigestReadsCommittedWAL(t *testing.T) {
	o := preflightFixture(t, nil)
	before, err := liveStrongDigest(context.Background(), o.snapshot+"/state.db")
	if err != nil {
		t.Fatal(err)
	}
	db, err := readonlyDB(o.snapshot + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	// The write uses the ordinary state API and remains visible regardless of\n+	// whether SQLite has checkpointed the main file yet.
	e, c, err := state.PersistenceBootstrap(o.snapshot, o.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = e.SetLeaseDisplayName("fixture-platform", "fixture\u2028😀", "changed"); err != nil {
		t.Fatal(err)
	}
	after, err := liveStrongDigest(context.Background(), o.snapshot+"/state.db")
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("online digest missed committed strong write")
	}
}

func TestLiveControlRejectsUnauthenticatedPause(t *testing.T) {
	b, _ := newLiveBridge("127.0.0.1:1", "127.0.0.2")
	b.app = &resinApp{envCfg: &config.EnvConfig{AdminToken: "fixture-secret"}}
	r := httptest.NewRequest("POST", "/live/pause", strings.NewReader(`{"milliseconds":100}`))
	w := httptest.NewRecorder()
	b.controlHTTP(w, r)
	if w.Code != 401 || b.status()["phase"] != "bridge" {
		t.Fatal("unauthorized transition")
	}
	var output bytes.Buffer
	json.NewEncoder(&output).Encode(b.status())
	if strings.Contains(output.String(), "secret") {
		t.Fatal("status leaked secret")
	}
}
