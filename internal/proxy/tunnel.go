package proxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Resinat/Resin/internal/netutil"
	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/outbound"
	"github.com/Resinat/Resin/internal/routing"
	M "github.com/sagernet/sing/common/metadata"
)

type tunnelDeps struct {
	router           *routing.Router
	pool             outbound.PoolAccessor
	health           HealthRecorder
	metricsSink      MetricsEventSink
	bypass           *TargetBypassMatcher
	connectTimeout   time.Duration
	connectRetries   int
	firstByteTimeout time.Duration
}

type preparedTunnel struct {
	upstreamConn net.Conn
	recordResult func(bool)
}

type tunnelPrepareResult struct {
	route         routing.RouteResult
	session       *preparedTunnel
	proxyErr      *ProxyError
	upstreamStage string
	upstreamErr   error
	canceled      bool
}

type tunnelRelayResult struct {
	ingressBytes  int64
	egressBytes   int64
	netOK         bool
	proxyErr      *ProxyError
	upstreamStage string
	upstreamErr   error
}

type tunnelPumpOptions struct {
	requireBidirectionalTraffic bool
	onFirstIngressByte          func()
	firstByteTimeout            time.Duration
	onFirstByteTimeout          func()
}

const (
	firstByteWaiting uint32 = iota
	firstByteReceived
	firstByteTimedOut
	firstByteStopped
)

type tunnelFirstByteWatch struct {
	timeout   time.Duration
	onTimeout func()
	state     atomic.Uint32
	mu        sync.Mutex
	timer     *time.Timer
}

func (w *tunnelFirstByteWatch) start() {
	if w == nil || w.timeout <= 0 || w.state.Load() != firstByteWaiting {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.timer != nil || w.state.Load() != firstByteWaiting {
		return
	}
	w.timer = time.AfterFunc(w.timeout, func() {
		if w.state.CompareAndSwap(firstByteWaiting, firstByteTimedOut) && w.onTimeout != nil {
			w.onTimeout()
		}
	})
}

func (w *tunnelFirstByteWatch) receive() bool {
	if w == nil {
		return true
	}
	if !w.state.CompareAndSwap(firstByteWaiting, firstByteReceived) {
		return w.state.Load() == firstByteReceived
	}
	w.stopTimer()
	return true
}

func (w *tunnelFirstByteWatch) stop() {
	if w == nil {
		return
	}
	w.state.CompareAndSwap(firstByteWaiting, firstByteStopped)
	w.stopTimer()
}

func (w *tunnelFirstByteWatch) stopTimer() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.timer != nil {
		w.timer.Stop()
	}
}

func (w *tunnelFirstByteWatch) timedOut() bool {
	return w != nil && w.state.Load() == firstByteTimedOut
}

type firstByteReader struct {
	reader      io.Reader
	onFirstByte func()
	once        sync.Once
}

func (r *firstByteReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 && r.onFirstByte != nil {
		r.once.Do(r.onFirstByte)
	}
	return n, err
}

func prepareConnectTunnel(
	ctx context.Context,
	deps tunnelDeps,
	platformName string,
	account string,
	target string,
) tunnelPrepareResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if deps.bypass != nil && deps.bypass.ShouldBypass(target) {
		return prepareDirectConnectTunnel(ctx, deps, target)
	}

	domain := netutil.ExtractDomain(target)
	retries := deps.connectRetries
	if retries < 0 {
		retries = 0
	}
	if retries > 2 {
		retries = 2
	}
	excluded := make([]node.Hash, 0, retries)
	attempts := retries + 1
	var lastFailure tunnelPrepareResult
	for attempt := 0; attempt < attempts; attempt++ {
		routed, routeErr := resolveRoutedOutboundExcluding(
			deps.router,
			deps.pool,
			platformName,
			account,
			target,
			excluded,
		)
		if routeErr != nil {
			if lastFailure.proxyErr != nil {
				return lastFailure
			}
			return tunnelPrepareResult{proxyErr: routeErr}
		}

		nodeHashRaw := routed.Route.NodeHash
		if deps.health != nil {
			go deps.health.RecordLatency(nodeHashRaw, domain, nil)
		}

		rawConn, err := dialTunnelWithTimeout(ctx, deps.connectTimeout, func(dialCtx context.Context) (net.Conn, error) {
			return routed.Outbound.DialContext(dialCtx, "tcp", M.ParseSocksaddr(target))
		})
		if err != nil {
			proxyErr := classifyConnectError(err)
			if proxyErr == nil {
				return tunnelPrepareResult{
					route:    routed.Route,
					canceled: true,
				}
			}
			if deps.health != nil {
				recordPassiveResultAsync(deps.health, routed.Route, false)
			}
			invalidateTunnelLease(deps.router, routed.Route, account)
			lastFailure = tunnelPrepareResult{
				route:         routed.Route,
				proxyErr:      proxyErr,
				upstreamStage: "connect_dial",
				upstreamErr:   err,
			}
		excluded = append(excluded, routed.Route.NodeHash)
			if attempt+1 < attempts {
				log.Printf(
					"proxy connect retry: platform_id=%s failed_node_hash=%s next_attempt=%d/%d",
					routed.Route.PlatformID,
					routed.Route.NodeHash.Hex(),
					attempt+2,
					attempts,
				)
			}
			continue
		}

		recordResult := func(ok bool) {
			if deps.health != nil {
				recordPassiveResultAsync(deps.health, routed.Route, ok)
			}
		}

		var upstreamBase net.Conn = rawConn
		if deps.metricsSink != nil {
			deps.metricsSink.OnConnectionLifecycle(ConnectionOutbound, ConnectionOpen)
			upstreamBase = newCountingConn(rawConn, deps.metricsSink)
		}

		upstreamConn := newTLSLatencyConn(upstreamBase, func(latency time.Duration) {
			if deps.health != nil {
				deps.health.RecordLatency(nodeHashRaw, domain, &latency)
			}
		})

		return tunnelPrepareResult{
			route: routed.Route,
			session: &preparedTunnel{
				upstreamConn: upstreamConn,
				recordResult: recordResult,
			},
		}
	}
	return lastFailure
}

func prepareDirectConnectTunnel(ctx context.Context, deps tunnelDeps, target string) tunnelPrepareResult {
	var dialer net.Dialer
	rawConn, err := dialTunnelWithTimeout(ctx, deps.connectTimeout, func(dialCtx context.Context) (net.Conn, error) {
		return dialer.DialContext(dialCtx, "tcp", target)
	})
	if err != nil {
		proxyErr := classifyConnectError(err)
		if proxyErr == nil {
			return tunnelPrepareResult{canceled: true}
		}
		return tunnelPrepareResult{
			proxyErr:      proxyErr,
			upstreamStage: "connect_direct_dial",
			upstreamErr:   err,
		}
	}

	var upstreamConn net.Conn = rawConn
	if deps.metricsSink != nil {
		deps.metricsSink.OnConnectionLifecycle(ConnectionOutbound, ConnectionOpen)
		upstreamConn = newCountingConn(rawConn, deps.metricsSink)
	}
	return tunnelPrepareResult{
		session: &preparedTunnel{
			upstreamConn: upstreamConn,
			recordResult: func(bool) {},
		},
	}
}

func dialTunnelWithTimeout(
	ctx context.Context,
	timeout time.Duration,
	dial func(context.Context) (net.Conn, error),
) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		return dial(ctx)
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dial(dialCtx)
	if err == nil && dialCtx.Err() != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, dialCtx.Err()
	}
	return conn, err
}

func invalidateTunnelLease(router *routing.Router, route routing.RouteResult, account string) bool {
	if router == nil || account == "" || route.PlatformID == "" || route.NodeHash.IsZero() {
		return false
	}
	deleted := router.DeleteLeaseIfNode(route.PlatformID, account, route.NodeHash)
	if deleted {
		log.Printf(
			"proxy sticky lease invalidated: platform_id=%s node_hash=%s",
			route.PlatformID,
			route.NodeHash.Hex(),
		)
	}
	return deleted
}

func pumpPreparedTunnel(
	clientConn net.Conn,
	clientReader *bufio.Reader,
	session *preparedTunnel,
	opts tunnelPumpOptions,
) tunnelRelayResult {
	clientToUpstream, err := makeTunnelClientReader(clientConn, clientReader)
	if err != nil {
		if session != nil && session.upstreamConn != nil {
			_ = session.upstreamConn.Close()
		}
		if clientConn != nil {
			_ = clientConn.Close()
		}
		return tunnelRelayResult{
			proxyErr:      ErrUpstreamRequestFailed,
			upstreamStage: "connect_client_prefetch_drain",
			upstreamErr:   err,
		}
	}
	return pumpPreparedTunnelReader(clientConn, clientToUpstream, session, opts)
}

func pumpPreparedTunnelReader(
	clientConn net.Conn,
	clientToUpstream io.Reader,
	session *preparedTunnel,
	opts tunnelPumpOptions,
) tunnelRelayResult {
	if clientConn == nil || clientToUpstream == nil || session == nil || session.upstreamConn == nil {
		return tunnelRelayResult{}
	}

	type copyResult struct {
		n   int64
		err error
	}
	var closeBothOnce sync.Once
	closeBoth := func() {
		closeBothOnce.Do(func() {
			_ = clientConn.Close()
			_ = session.upstreamConn.Close()
		})
	}
	firstByteWatch := &tunnelFirstByteWatch{
		timeout: opts.firstByteTimeout,
		onTimeout: func() {
			if opts.onFirstByteTimeout != nil {
				opts.onFirstByteTimeout()
			}
			closeBoth()
		},
	}
	ingressBytesCh := make(chan copyResult, 1)
	egressBytesCh := make(chan copyResult, 1)
	go func() {
		var clientReader io.Reader = clientToUpstream
		if opts.firstByteTimeout > 0 {
			clientReader = &firstByteReader{reader: clientToUpstream, onFirstByte: firstByteWatch.start}
		}
		n, copyErr := io.Copy(session.upstreamConn, clientReader)
		if !isBenignTunnelCopyError(copyErr) || !closeWriteConn(session.upstreamConn) {
			closeBoth()
		}
		egressBytesCh <- copyResult{n: n, err: copyErr}
	}()
	go func() {
		var upstreamReader io.Reader = session.upstreamConn
		if opts.onFirstIngressByte != nil || opts.firstByteTimeout > 0 {
			// 隧道首字耗时以目标站点返回的第一批字节为准，而不是 CONNECT/SOCKS 握手完成。
			upstreamReader = &firstByteReader{reader: session.upstreamConn, onFirstByte: func() {
				if firstByteWatch.receive() && opts.onFirstIngressByte != nil {
					opts.onFirstIngressByte()
				}
			}}
		}
		n, copyErr := io.Copy(clientConn, upstreamReader)
		if !isBenignTunnelCopyError(copyErr) || !closeWriteConn(clientConn) {
			closeBoth()
		}
		ingressBytesCh <- copyResult{n: n, err: copyErr}
	}()

	ingressResult := <-ingressBytesCh
	egressResult := <-egressBytesCh
	firstByteWatch.stop()
	closeBoth()

	ingressErrBenign := isBenignTunnelCopyError(ingressResult.err)
	egressErrBenign := isBenignTunnelCopyError(egressResult.err)
	// A client-side TCP reset after the upstream response has already started is
	// a shutdown artifact, not an upstream failure. This commonly happens when a
	// tunnel client exits immediately after consuming the response.
	if !egressErrBenign && ingressResult.n > 0 && isClientReadResetError(egressResult.err) {
		egressErrBenign = true
	}

	result := tunnelRelayResult{
		ingressBytes: ingressResult.n,
		egressBytes:  egressResult.n,
		netOK:        true,
	}
	switch {
	case firstByteWatch.timedOut():
		result.netOK = false
		result.proxyErr = ErrUpstreamTimeout
		result.upstreamStage = "connect_first_byte_timeout"
		result.upstreamErr = context.DeadlineExceeded
	case !ingressErrBenign:
		result.netOK = false
		result.proxyErr = ErrUpstreamRequestFailed
		result.upstreamStage = "connect_upstream_to_client_copy"
		result.upstreamErr = ingressResult.err
	case !egressErrBenign:
		result.netOK = false
		result.proxyErr = ErrUpstreamRequestFailed
		result.upstreamStage = "connect_client_to_upstream_copy"
		result.upstreamErr = egressResult.err
	case opts.requireBidirectionalTraffic && (ingressResult.n == 0 || egressResult.n == 0):
		result.netOK = false
		result.proxyErr = ErrUpstreamRequestFailed
		switch {
		case ingressResult.n == 0 && egressResult.n == 0:
			result.upstreamStage = "connect_zero_traffic"
		case ingressResult.n == 0:
			result.upstreamStage = "connect_no_ingress_traffic"
			result.upstreamErr = io.EOF
		default:
			result.upstreamStage = "connect_no_egress_traffic"
		}
	case opts.firstByteTimeout > 0 && egressResult.n > 0 && ingressResult.n == 0:
		result.netOK = false
		result.proxyErr = ErrUpstreamRequestFailed
		result.upstreamStage = "connect_no_ingress_traffic"
		result.upstreamErr = io.EOF
	}
	return result
}

func shouldInvalidateTunnelLease(result tunnelRelayResult) bool {
	if result.netOK || result.ingressBytes > 0 {
		return false
	}
	switch result.upstreamStage {
	case "connect_first_byte_timeout", "connect_upstream_to_client_copy", "connect_no_ingress_traffic":
		return true
	default:
		return false
	}
}

func closeWriteConn(conn net.Conn) bool {
	return closeWriteErr(conn) == nil
}

// makeTunnelClientReader returns a reader for client->upstream copy that
// preserves any bytes already buffered by a protocol reader before tunneling.
func makeTunnelClientReader(clientConn net.Conn, buffered *bufio.Reader) (io.Reader, error) {
	if buffered == nil {
		return clientConn, nil
	}
	n := buffered.Buffered()
	if n == 0 {
		return clientConn, nil
	}
	prefetched := make([]byte, n)
	if _, err := io.ReadFull(buffered, prefetched); err != nil {
		return nil, err
	}
	return io.MultiReader(bytes.NewReader(prefetched), clientConn), nil
}
