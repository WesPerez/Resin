package main

// A live bridge keeps the old process as the only routing authority while new
// ingress moves to this process. Pausing queues requests briefly; expiry resumes
// forwarding automatically. Established tunnels never wait on the mode lock.
import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type bridgeSocket struct {
	Local  string `json:"local"`
	Remote string `json:"remote"`
	Tunnel bool   `json:"tunnel"`
}

type liveBridge struct {
	mu               sync.Mutex
	transitionMu     sync.Mutex
	nativeMu         sync.RWMutex
	source, bind     string
	phase            string
	wake             chan struct{}
	deadline         time.Time
	epoch            uint64
	inflight, probes int
	sockets          map[net.Conn]bridgeSocket
	localHTTP        http.Handler
	localSOCKS       inboundConnHandler
	app              *resinApp
	control, probe   *http.Server
	listeners        []net.Listener
}

func newLiveBridge(source, bind string) (*liveBridge, error) {
	host, port, err := net.SplitHostPort(source)
	ip := net.ParseIP(host)
	local := net.ParseIP(bind)
	if err != nil || port == "" || port == "0" || ip == nil || local == nil || !local.IsLoopback() {
		return nil, errors.New("live bridge requires an explicit source IP:port and loopback source bind")
	}
	return &liveBridge{source: source, bind: bind, phase: "bridge", sockets: make(map[net.Conn]bridgeSocket)}, nil
}

// enter is held only through an ordinary HTTP response or tunnel handshake.
// Each subsequent HTTP keepalive request chooses the current mode afresh.
func (b *liveBridge) enter(ctx context.Context) (bool, func(), error) {
	for {
		b.mu.Lock()
		if b.phase != "queued" {
			local := b.phase == "local"
			if !local {
				b.inflight++
			}
			b.mu.Unlock()
			if local {
				return true, func() {}, nil
			}
			var once sync.Once
			return false, func() { once.Do(func() { b.mu.Lock(); b.inflight--; b.mu.Unlock() }) }, nil
		}
		wake := b.wake
		b.mu.Unlock()
		select {
		case <-wake:
		case <-ctx.Done():
			return false, nil, ctx.Err()
		}
	}
}

func (b *liveBridge) resumeLocked() {
	if b.phase == "queued" {
		b.phase = "bridge"
		close(b.wake)
	}
}

func (b *liveBridge) pause(wait time.Duration) (uint64, error) {
	if wait <= 0 || wait > 3*time.Second {
		return 0, errors.New("pause must be at most three seconds")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.phase != "bridge" {
		return 0, errors.New("bridge is not available for pause")
	}
	b.epoch++
	epoch := b.epoch
	b.phase = "queued"
	b.wake = make(chan struct{})
	b.deadline = time.Now().Add(wait)
	time.AfterFunc(wait, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.epoch == epoch {
			b.resumeLocked()
		}
	})
	return epoch, nil
}

func (b *liveBridge) dial(ctx context.Context) (net.Conn, func(), error) {
	d := net.Dialer{Timeout: 10 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(b.bind)}}
	c, err := d.DialContext(ctx, "tcp", b.source)
	if err != nil {
		return nil, nil, err
	}
	b.mu.Lock()
	b.sockets[c] = bridgeSocket{Local: c.LocalAddr().String(), Remote: c.RemoteAddr().String()}
	b.mu.Unlock()
	var once sync.Once
	return c, func() {
		once.Do(func() {
			_ = c.Close()
			b.mu.Lock()
			delete(b.sockets, c)
			b.mu.Unlock()
		})
	}, nil
}

func (b *liveBridge) tunnel(c net.Conn, release func()) {
	b.mu.Lock()
	s := b.sockets[c]
	s.Tunnel = true
	b.sockets[c] = s
	b.mu.Unlock()
	release()
}

func copyBridgeHeaders(dst, src http.Header) {
	for k, values := range src {
		for _, v := range values {
			dst.Add(k, v)
		}
	}
}

type bridgeFlushWriter struct{ w http.ResponseWriter }

func (f bridgeFlushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if flush, ok := f.w.(http.Flusher); ok {
		flush.Flush()
	}
	return n, err
}

func bridgePump(client net.Conn, cr io.Reader, upstream net.Conn, ur io.Reader) {
	defer client.Close()
	defer upstream.Close()
	done := make(chan error, 2)
	go func() {
		_, err := io.Copy(upstream, cr)
		if c, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		} else {
			_ = upstream.Close()
		}
		done <- err
	}()
	go func() {
		_, err := io.Copy(client, ur)
		if c, ok := client.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		} else {
			_ = client.Close()
		}
		done <- err
	}()
	// A clean half-close must still allow the final response in the opposite
	// direction. Actual stream errors release both sides promptly.
	if err := <-done; err != nil {
		_ = client.Close()
		_ = upstream.Close()
	}
	<-done
}

func (b *liveBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	local, release, err := b.enter(r.Context())
	if err != nil {
		return
	}
	defer release()
	if local {
		b.localHTTP.ServeHTTP(w, r)
		return
	}
	c, closeConn, err := b.dial(r.Context())
	if err != nil {
		http.Error(w, "bridge source unavailable", 502)
		return
	}
	defer closeConn()
	stop := context.AfterFunc(r.Context(), func() { _ = c.Close() })
	defer stop()
	out := r.Clone(r.Context())
	out.RequestURI = ""
	// A single upstream connection per HTTP request avoids implicit replay of
	// POSTs and makes every source-side connection visible in the status set.
	out.Close = r.Method != http.MethodConnect && !strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
	if r.URL.IsAbs() && r.Method != http.MethodConnect {
		err = out.WriteProxy(c)
	} else {
		err = out.Write(c)
	}
	if err != nil {
		http.Error(w, "bridge request failed", 502)
		return
	}
	reader := bufio.NewReader(c)
	response, err := http.ReadResponse(reader, out)
	if err != nil {
		http.Error(w, "bridge response failed", 502)
		return
	}
	defer response.Body.Close()
	if (r.Method == http.MethodConnect && response.StatusCode == 200) || response.StatusCode == 101 {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "bridge hijack unavailable", 500)
			return
		}
		client, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		_, err = fmt.Fprintf(buf, "HTTP/1.1 %s\r\n", response.Status)
		if err == nil {
			err = response.Header.Write(buf)
		}
		if err == nil {
			_, err = buf.WriteString("\r\n")
		}
		if err == nil {
			err = buf.Flush()
		}
		if err != nil {
			return
		}
		b.tunnel(c, release)
		bridgePump(client, buf.Reader, c, reader)
		return
	}
	copyBridgeHeaders(w.Header(), response.Header)
	w.Header().Del("Connection")
	w.Header().Del("Proxy-Connection")
	w.Header().Del("Keep-Alive")
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(bridgeFlushWriter{w}, response.Body)
}

func bridgeBytes(dst io.Writer, src io.Reader, n int) ([]byte, error) {
	p := make([]byte, n)
	if _, err := io.ReadFull(src, p); err != nil {
		return nil, err
	}
	_, err := dst.Write(p)
	return p, err
}

func bridgeSOCKSAddress(dst io.Writer, src io.Reader, atyp byte) error {
	n := 0
	switch atyp {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		p, err := bridgeBytes(dst, src, 1)
		if err != nil {
			return err
		}
		n = int(p[0])
	default:
		return errors.New("invalid SOCKS address")
	}
	_, err := bridgeBytes(dst, src, n+2)
	return err
}

func (b *liveBridge) ServeConnContext(ctx context.Context, client net.Conn) {
	local, release, err := b.enter(ctx)
	if err != nil {
		_ = client.Close()
		return
	}
	defer release()
	if local {
		b.localSOCKS.ServeConnContext(ctx, client)
		return
	}
	defer client.Close()
	c, closeConn, err := b.dial(ctx)
	if err != nil {
		return
	}
	defer closeConn()
	stop := context.AfterFunc(ctx, func() { _ = client.Close(); _ = c.Close() })
	defer stop()
	deadline := time.Now().Add(15 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = c.SetDeadline(deadline)
	h, err := bridgeBytes(c, client, 2)
	if err != nil || h[0] != 5 {
		return
	}
	if _, err = bridgeBytes(c, client, int(h[1])); err != nil {
		return
	}
	h, err = bridgeBytes(client, c, 2)
	if err != nil || h[0] != 5 {
		return
	}
	switch h[1] {
	case 0:
	case 2:
		h, err = bridgeBytes(c, client, 2)
		if err != nil || h[0] != 1 {
			return
		}
		if _, err = bridgeBytes(c, client, int(h[1])); err != nil {
			return
		}
		h, err = bridgeBytes(c, client, 1)
		if err != nil {
			return
		}
		if _, err = bridgeBytes(c, client, int(h[0])); err != nil {
			return
		}
		h, err = bridgeBytes(client, c, 2)
		if err != nil || h[0] != 1 || h[1] != 0 {
			return
		}
	default:
		return
	}
	h, err = bridgeBytes(c, client, 4)
	if err != nil || h[0] != 5 || h[1] != 1 {
		return
	}
	if err = bridgeSOCKSAddress(c, client, h[3]); err != nil {
		return
	}
	h, err = bridgeBytes(client, c, 4)
	if err != nil || h[0] != 5 {
		return
	}
	if err = bridgeSOCKSAddress(client, c, h[3]); err != nil || h[1] != 0 {
		return
	}
	_ = client.SetDeadline(time.Time{})
	_ = c.SetDeadline(time.Time{})
	b.tunnel(c, release)
	bridgePump(client, client, c, c)
}

func bridgeFromEnvironment(stateDir string) (*liveBridge, error) {
	source := os.Getenv("RESIN_LIVE_SOURCE")
	if source == "" {
		return nil, nil
	}
	local, err := readLiveRestart(stateDir)
	if err != nil {
		return nil, err
	}
	if local {
		return nil, nil
	}
	return newLiveBridge(source, os.Getenv("RESIN_LIVE_BIND"))
}
