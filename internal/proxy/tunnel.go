package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
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
	upstreamConn   net.Conn
	recordResult   func(bool)
	recoveryClosed atomic.Bool
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
	ingressBytes       int64
	egressBytes        int64
	netOK              bool
	proxyErr           *ProxyError
	upstreamStage      string
	upstreamErr        error
	upstreamReadFailed bool
}

type tunnelCopyObserver struct {
	reader  io.Reader
	readErr error
}

func (o *tunnelCopyObserver) Read(p []byte) (int, error) {
	n, err := o.reader.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		o.readErr = err
	}
	return n, err
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
	if deps.bypass != nil && !routing.HasLeaseGuard(account) && deps.bypass.ShouldBypass(target) {
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
	var grant *routing.RecoveryAttempt
	finishFailedRecovery := func() {
		if grant != nil && ctx.Err() == nil {
			_, _, _ = deps.router.CommitRecovery(grant, target, routing.RotateLeaseOptions{
				ExcludeEgressIP: true, PreserveConnections: true, ApplyTargetCooldown: true, FailureCooldown: 10 * time.Minute,
				ExcludedNodes: excluded,
			})
		}
	}
	for attempt := 0; attempt < attempts; attempt++ {
		resolve := resolveRoutedOutboundExcluding
		if attempt > 0 {
			resolve = resolveRoutedOutboundPeek
		}
		routed, routeErr := resolve(
			deps.router,
			deps.pool,
			platformName,
			account,
			target,
			excluded,
		)
		if routeErr != nil {
			if lastFailure.proxyErr != nil {
				finishFailedRecovery()
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
			lastFailure = tunnelPrepareResult{
				route:         routed.Route,
				proxyErr:      proxyErr,
				upstreamStage: "connect_dial",
				upstreamErr:   err,
			}
			if routed.Route.LeaseGuarded {
				return lastFailure
			}
			if attempt == 0 && account != "" && routed.Route.LeaseCreatedAtNs != 0 {
				var beginErr error
				grant, beginErr = deps.router.BeginRecovery(routed.Route.PlatformID, account, routed.Route.NodeHash, routed.Route.LeaseCreatedAtNs)
				if beginErr != nil {
					// A concurrent rotation or policy limit leaves retries read-only.
					grant = nil
				}
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

		if grant != nil {
			next, _, commitErr := deps.router.CommitRecovery(grant, target, routing.RotateLeaseOptions{
				PreferredNode: routed.Route.NodeHash, ExpectedTargetIP: routed.Route.EgressIP, VerifiedPreferred: true,
				PreserveConnections: true, ApplyTargetCooldown: true, FailureCooldown: 10 * time.Minute,
			})
			if commitErr != nil && !errors.Is(commitErr, routing.ErrRecoveryLimited) && !errors.Is(commitErr, routing.ErrRecoveryDisabled) {
				_ = rawConn.Close()
				return tunnelPrepareResult{route: routed.Route, proxyErr: mapRouteError(commitErr), upstreamStage: "connect_recovery", upstreamErr: commitErr}
			}
			if next != nil {
				routed.Route.LeaseCreatedAtNs = next.CreatedAtNs
				routed.Route.LeaseCreated = true
			}
		}

		if routed.Route.LeaseGuarded {
			if err := rawConn.SetDeadline(time.UnixMilli(routed.Route.LeaseGuardUntilMs)); err != nil {
				_ = rawConn.Close()
				return tunnelPrepareResult{route: routed.Route, proxyErr: ErrLeaseGuard}
			}
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
	finishFailedRecovery()
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
	// A failed image/font/echo connection cannot invalidate a whole browser job.
	// Explicit administrative recovery may still change the lease; every later
	// guarded CONNECT will reject that generation instead of following it.
	if route.LeaseGuarded {
		return false
	}
	if router == nil || account == "" || route.PlatformID == "" || route.NodeHash.IsZero() || route.LeaseCreatedAtNs == 0 {
		return false
	}
	deleted := router.DeleteLeaseIfGeneration(route.PlatformID, account, route.NodeHash, route.LeaseCreatedAtNs)
	if deleted {
		log.Printf(
			"proxy sticky lease invalidated: platform_id=%s node_hash=%s",
			route.PlatformID,
			route.NodeHash.Hex(),
		)
	}
	return deleted
}

// Recover directly from the completed tunnel's structured failure. Log retention
// and log enablement cannot affect this path; client cancellation is filtered by
// shouldInvalidateTunnelLease before it reaches here.
func recoverTunnelLease(router *routing.Router, route routing.RouteResult, account, target string) {
	if router == nil || route.LeaseGuarded || account == "" || route.PlatformID == "" || route.NodeHash.IsZero() || route.LeaseCreatedAtNs == 0 {
		return
	}
	_, _, err := router.RecoverLease(route.PlatformID, account, route.NodeHash, route.LeaseCreatedAtNs, target,
		routing.RotateLeaseOptions{ExcludeEgressIP: true, PreserveConnections: true, ApplyTargetCooldown: true, FailureCooldown: 10 * time.Minute})
	if err == nil {
		log.Printf("proxy sticky lease recovered: platform_id=%s observed_node_hash=%s", route.PlatformID, route.NodeHash.Hex())
	}
}

func registerPreparedTunnel(router *routing.Router, route routing.RouteResult, account string, client net.Conn, session *preparedTunnel) (func(), bool) {
	closeForRecovery := func() {
		session.recoveryClosed.Store(true)
		_ = client.Close()
		_ = session.upstreamConn.Close()
	}
	unregister, ok := router.RegisterLeaseConnection(route, account, closeForRecovery)
	if !ok {
		closeForRecovery()
	}
	return unregister, ok
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
		n       int64
		err     error
		readErr error
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
		observedUpstream := &tunnelCopyObserver{reader: session.upstreamConn}
		var upstreamReader io.Reader = observedUpstream
		if opts.onFirstIngressByte != nil || opts.firstByteTimeout > 0 {
			// 隧道首字耗时以目标站点返回的第一批字节为准，而不是 CONNECT/SOCKS 握手完成。
			upstreamReader = &firstByteReader{reader: observedUpstream, onFirstByte: func() {
				if firstByteWatch.receive() && opts.onFirstIngressByte != nil {
					opts.onFirstIngressByte()
				}
			}}
		}
		n, copyErr := io.Copy(clientConn, upstreamReader)
		if !isBenignTunnelCopyError(copyErr) || !closeWriteConn(clientConn) {
			closeBoth()
		}
		// io.Copy reports destination write errors through copyErr too. Retain
		// the source read error separately so a client-side write failure cannot
		// be mistaken for an upstream transport failure.
		ingressBytesCh <- copyResult{n: n, err: copyErr, readErr: observedUpstream.readErr}
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
		ingressBytes:       ingressResult.n,
		egressBytes:        egressResult.n,
		netOK:              true,
		upstreamReadFailed: ingressResult.readErr != nil,
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
	if result.netOK {
		return false
	}
	if result.upstreamReadFailed {
		return true
	}
	if result.upstreamStage == "connect_upstream_to_client_copy" {
		return false
	}
	if result.ingressBytes > 0 {
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
