package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/proxy"
	"github.com/Resinat/Resin/internal/service"
)

type managedEndpointRuntime struct {
	config   atomic.Pointer[model.Endpoint]
	server   *inboundDemuxServer
	listener net.Listener
	started  bool
}

func (r *managedEndpointRuntime) current() model.Endpoint {
	if r == nil {
		return model.Endpoint{}
	}
	endpoint := r.config.Load()
	if endpoint == nil {
		return model.Endpoint{}
	}
	return *endpoint
}

type endpointRuntimeManager struct {
	mu               sync.Mutex
	listenAddress    string
	proxyToken       string
	forward          http.Handler
	reverse          http.Handler
	apiHandler       http.Handler
	tokenAPI         http.Handler
	socks5           inboundConnHandler
	metricsSink      proxy.MetricsEventSink
	maintenance      *maintenanceController
	liveBridge       *liveBridge
	runtimes         map[string]*managedEndpointRuntime
	statuses         map[string]service.EndpointRuntimeStatus
	started          bool
	stopping         bool
	serverErrCh      chan error
	retirementWG     sync.WaitGroup
	serveWG          sync.WaitGroup
	shutdownMu       sync.Mutex
	stoppingRuntimes []*managedEndpointRuntime
	sourcesOnce      sync.Once
	sourcesDone      chan struct{}
	sourceErr        error
}

func newEndpointRuntimeManager(
	listenAddress string,
	proxyToken string,
	forward, reverse, apiHandler, tokenAPI http.Handler,
	socks5 inboundConnHandler,
	metricsSink proxy.MetricsEventSink,
) *endpointRuntimeManager {
	return &endpointRuntimeManager{
		listenAddress: listenAddress,
		proxyToken:    proxyToken,
		forward:       forward,
		reverse:       reverse,
		apiHandler:    apiHandler,
		tokenAPI:      tokenAPI,
		socks5:        socks5,
		metricsSink:   metricsSink,
		runtimes:      make(map[string]*managedEndpointRuntime),
		statuses:      make(map[string]service.EndpointRuntimeStatus),
		serverErrCh:   make(chan error, 1),
		sourcesDone:   make(chan struct{}),
	}
}

func (m *endpointRuntimeManager) ApplyEndpoint(endpoint model.Endpoint) error {
	if m == nil {
		return fmt.Errorf("endpoint runtime manager is nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopping {
		return net.ErrClosed
	}

	if current := m.runtimes[endpoint.ID]; current != nil && current.current().Port == endpoint.Port {
		copy := endpoint
		current.config.Store(&copy)
		if current.started {
			m.statuses[endpoint.ID] = service.EndpointRuntimeStatus{State: "active"}
		} else {
			m.statuses[endpoint.ID] = service.EndpointRuntimeStatus{State: "starting"}
		}
		return nil
	}

	listener, err := net.Listen("tcp", formatListenAddress(m.listenAddress, endpoint.Port))
	if err != nil {
		if m.runtimes[endpoint.ID] == nil {
			m.statuses[endpoint.ID] = service.EndpointRuntimeStatus{State: "error", LastError: err.Error()}
		}
		return err
	}
	listener = proxy.NewCountingListener(listener, m.metricsSink)

	runtime := &managedEndpointRuntime{listener: listener}
	copy := endpoint
	runtime.config.Store(&copy)
	currentConfig := func() model.Endpoint { return runtime.current() }
	httpHandler := newEndpointInboundMux(
		currentConfig,
		m.proxyToken,
		m.forward,
		m.reverse,
		m.apiHandler,
		m.tokenAPI,
	)
	var socksHandler inboundConnHandler = &endpointSocksGate{current: currentConfig, next: m.socks5}
	if m.liveBridge != nil {
		if len(m.runtimes) != 0 {
			_ = listener.Close()
			return fmt.Errorf("live bridge supports only the default endpoint")
		}
		m.liveBridge.localHTTP = httpHandler
		m.liveBridge.localSOCKS = socksHandler
		httpHandler = m.liveBridge
		socksHandler = m.liveBridge
	}
	if m.maintenance != nil {
		httpHandler = m.maintenance.wrapHTTP(httpHandler)
		socksHandler = &maintenanceSOCKS{controller: m.maintenance, next: socksHandler}
	}
	runtime.server = newInboundDemuxServer(
		&http.Server{Handler: httpHandler, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second},
		socksHandler,
	)
	old := m.runtimes[endpoint.ID]
	m.runtimes[endpoint.ID] = runtime
	m.statuses[endpoint.ID] = service.EndpointRuntimeStatus{State: "starting"}
	if m.started {
		m.startRuntimeLocked(runtime)
	}
	if old != nil {
		m.retireLocked(old)
	}
	return nil
}

func (m *endpointRuntimeManager) RemoveEndpoint(id string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.stopping {
		m.mu.Unlock()
		return
	}
	runtime := m.runtimes[id]
	delete(m.runtimes, id)
	delete(m.statuses, id)
	if runtime != nil {
		// Release the port before returning so a following start can rebind it.
		_ = runtime.listener.Close()
		m.retireLocked(runtime)
	}
	m.mu.Unlock()
}

func (m *endpointRuntimeManager) EndpointStatus(id string) service.EndpointRuntimeStatus {
	if m == nil {
		return service.EndpointRuntimeStatus{State: "inactive"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	status := m.statuses[id]
	if status.State == "" {
		status.State = "inactive"
	}
	return status
}

func (m *endpointRuntimeManager) RecordEndpointError(endpoint model.Endpoint, err error) {
	if m == nil || err == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statuses[endpoint.ID] = service.EndpointRuntimeStatus{State: "error", LastError: err.Error()}
}

func (m *endpointRuntimeManager) Start() <-chan error {
	m.mu.Lock()
	if !m.started && !m.stopping {
		m.started = true
		for _, runtime := range m.runtimes {
			m.startRuntimeLocked(runtime)
		}
	}
	m.mu.Unlock()
	return m.serverErrCh
}

func (m *endpointRuntimeManager) startRuntimeLocked(runtime *managedEndpointRuntime) {
	if runtime == nil || runtime.started {
		return
	}
	runtime.started = true
	endpoint := runtime.current()
	m.statuses[endpoint.ID] = service.EndpointRuntimeStatus{State: "active"}
	log.Printf("Endpoint %s starting on %s", endpoint.ID, formatListenAddress(m.listenAddress, endpoint.Port))
	m.serveWG.Add(1)
	go func() {
		defer m.serveWG.Done()
		err := runtime.server.Serve(runtime.listener)
		if err == nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			return
		}
		m.handleRuntimeError(runtime, err)
	}()
}

func (m *endpointRuntimeManager) handleRuntimeError(runtime *managedEndpointRuntime, err error) {
	endpoint := runtime.current()
	m.mu.Lock()
	if m.sourceErr == nil {
		m.sourceErr = fmt.Errorf("endpoint serve: %w", err)
	}
	if m.runtimes[endpoint.ID] == runtime {
		delete(m.runtimes, endpoint.ID)
		m.statuses[endpoint.ID] = service.EndpointRuntimeStatus{State: "error", LastError: err.Error()}
		if !m.stopping {
			m.retireLocked(runtime)
		}
	}
	stopping := m.stopping
	m.mu.Unlock()
	if !stopping && endpoint.ID == service.DefaultEndpointID {
		select {
		case m.serverErrCh <- fmt.Errorf("default endpoint: %w", err):
		default:
		}
	}
}

func (m *endpointRuntimeManager) Shutdown(ctx context.Context, preserveConnections bool) error {
	if m == nil {
		return nil
	}
	m.shutdownMu.Lock()
	defer m.shutdownMu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	if !m.stopping {
		m.stopping = true
		for _, runtime := range m.runtimes {
			m.stoppingRuntimes = append(m.stoppingRuntimes, runtime)
		}
		m.runtimes = make(map[string]*managedEndpointRuntime)
	}
	runtimes := m.stoppingRuntimes
	m.mu.Unlock()

	errCh := make(chan error, len(runtimes))
	var wg sync.WaitGroup
	for _, runtime := range runtimes {
		wg.Add(1)
		go func(runtime *managedEndpointRuntime) {
			defer wg.Done()
			if err := runtime.server.Shutdown(ctx, preserveConnections); err != nil {
				errCh <- err
			}
			_ = runtime.listener.Close()
		}(runtime)
	}
	wg.Wait()
	// Apply/Remove retire old listeners asynchronously. They no longer appear
	// in runtimes, but may still own a handler and its last lease event.
	// Registration is under mu and stopping prevents any later Add.
	close(errCh)
	var shutdownErrs []error
	for err := range errCh {
		shutdownErrs = append(shutdownErrs, err)
	}
	m.sourcesOnce.Do(func() {
		go func() {
			m.serveWG.Wait()
			m.retirementWG.Wait()
			for _, runtime := range runtimes {
				_ = runtime.server.waitForConnectionDrain(context.Background())
			}
			close(m.sourcesDone)
		}()
	})
	select {
	case <-m.sourcesDone:
		shutdownErrs = append(shutdownErrs, m.takeSourceError())
	case <-ctx.Done():
		shutdownErrs = append(shutdownErrs, ctx.Err())
	}
	// A failed attempt is not cached as a permanent historical failure. A later
	// attempt can only succeed once every tracked source has really exited.
	return errors.Join(shutdownErrs...)
}

// WaitQuiescent is a safety join, not a deadline promise. If Shutdown timed
// out, the app must still join pending users before closing their databases.
func (m *endpointRuntimeManager) WaitQuiescent() error {
	if m == nil {
		return nil
	}
	<-m.sourcesDone
	return m.takeSourceError()
}

// WaitQuiescentContext does not consume ownership on a failed wait.
func (m *endpointRuntimeManager) WaitQuiescentContext(ctx context.Context) error {
	if m == nil {
		return nil
	}
	select {
	case <-m.sourcesDone:
		return m.takeSourceError()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *endpointRuntimeManager) takeSourceError() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	err := m.sourceErr
	m.sourceErr = nil // Archive completed-source failure once, including safety joins.
	return err
}

// retireLocked must be called with m.mu held, before publishing the removal.
func (m *endpointRuntimeManager) retireLocked(runtime *managedEndpointRuntime) {
	m.retirementWG.Add(1)
	go func() {
		defer m.retirementWG.Done()
		if err := stopManagedEndpoint(runtime, 5*time.Second); err != nil {
			log.Printf("Retired endpoint did not quiesce within its close deadline: %v", err)
			m.mu.Lock()
			if m.sourceErr == nil {
				m.sourceErr = fmt.Errorf("retired endpoint close: %w", err)
			}
			m.mu.Unlock()
		}
		// Timeout is not removal from ownership. Keep this runtime registered
		// until even an uncooperative final handler exits. Shutdown's own ctx
		// bounds its wait on this proof, without forgetting the pending source.
		_ = runtime.server.waitForConnectionDrain(context.Background())
	}()
}

func stopManagedEndpoint(runtime *managedEndpointRuntime, timeout time.Duration) error {
	if runtime == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err := runtime.server.Shutdown(ctx, false)
	_ = runtime.listener.Close()
	return err
}

type endpointSocksGate struct {
	current func() model.Endpoint
	next    inboundConnHandler
}

func (g *endpointSocksGate) ServeConnContext(ctx context.Context, conn net.Conn) {
	endpoint := model.Endpoint{}
	if g != nil && g.current != nil {
		endpoint = g.current()
	}
	if !endpoint.AllowProxy || !endpoint.AllowSOCKS5 || g == nil || g.next == nil {
		if conn != nil {
			_, _ = conn.Write([]byte{0x05, 0xFF})
			_ = conn.Close()
		}
		return
	}
	ctx = proxy.ContextWithInboundPolicy(ctx, proxy.InboundPolicy{
		RequireProxyAuthInfo: endpoint.RequireProxyAuthInfo,
	})
	g.next.ServeConnContext(ctx, conn)
}
