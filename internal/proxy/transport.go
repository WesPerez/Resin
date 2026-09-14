package proxy

import (
	"container/list"
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Resinat/Resin/internal/node"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

type OutboundTransportConfig struct {
	MaxTransports       int
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	IdleConnTimeout     time.Duration
}

const (
	defaultMaxTransports                = 1024
	defaultTransportMaxIdleConns        = 1024
	defaultTransportMaxIdleConnsPerHost = 64
	defaultTransportIdleConnTimeout     = 90 * time.Second
)

func normalizeOutboundTransportConfig(cfg OutboundTransportConfig) OutboundTransportConfig {
	if cfg.MaxTransports <= 0 {
		cfg.MaxTransports = defaultMaxTransports
	}
	if cfg.MaxIdleConns <= 0 {
		cfg.MaxIdleConns = defaultTransportMaxIdleConns
	}
	if cfg.MaxIdleConnsPerHost <= 0 {
		cfg.MaxIdleConnsPerHost = defaultTransportMaxIdleConnsPerHost
	}
	if cfg.IdleConnTimeout <= 0 {
		cfg.IdleConnTimeout = defaultTransportIdleConnTimeout
	}
	return cfg
}

type outboundTransportKey struct {
	Node     node.Hash
	Identity outboundIdentity
}

type outboundTransportEntry struct {
	key       outboundTransportKey
	transport *http.Transport
}

// OutboundTransportPool isolates connections by node, platform, account and TLS
// profile. Bounded LRU eviction also closes idle connections for retired accounts.
type OutboundTransportPool struct {
	config     OutboundTransportConfig
	mu         sync.Mutex
	transports map[outboundTransportKey]*list.Element
	order      *list.List
}

func newOutboundTransportPool() *OutboundTransportPool {
	return NewOutboundTransportPool(OutboundTransportConfig{})
}

func newOutboundTransportPoolWithConfig(cfg OutboundTransportConfig) *OutboundTransportPool {
	return NewOutboundTransportPool(cfg)
}

// NewOutboundTransportPool creates a transport pool with normalized settings.
func NewOutboundTransportPool(cfg OutboundTransportConfig) *OutboundTransportPool {
	return &OutboundTransportPool{
		config:     normalizeOutboundTransportConfig(cfg),
		transports: make(map[outboundTransportKey]*list.Element),
		order:      list.New(),
	}
}

// Get returns a reusable transport for the given node hash.
func (p *OutboundTransportPool) Get(
	hash node.Hash,
	ob adapter.Outbound,
	sink MetricsEventSink,
) *http.Transport {
	return p.getForIdentity(hash, ob, sink, outboundIdentity{})
}

func (p *OutboundTransportPool) getForIdentity(hash node.Hash, ob adapter.Outbound, sink MetricsEventSink, identity outboundIdentity) *http.Transport {
	key := outboundTransportKey{Node: hash, Identity: identity}
	p.mu.Lock()
	defer p.mu.Unlock()
	if element := p.transports[key]; element != nil {
		p.order.MoveToBack(element)
		return element.Value.(outboundTransportEntry).transport
	}
	transport := p.newReusableOutboundTransport(ob, sink)
	if identity.TLS.ID != "" {
		transport.ForceAttemptHTTP2 = false
		transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := transport.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return dialAccountTLS(ctx, conn, addr, identity.TLS)
		}
	}
	p.transports[key] = p.order.PushBack(outboundTransportEntry{key, transport})
	if len(p.transports) > p.config.MaxTransports {
		oldest := p.order.Front()
		entry := oldest.Value.(outboundTransportEntry)
		delete(p.transports, entry.key)
		p.order.Remove(oldest)
		entry.transport.CloseIdleConnections()
	}
	return transport
}

// Evict closes idle connections for one node transport and removes it from pool.
func (p *OutboundTransportPool) Evict(hash node.Hash) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, element := range p.transports {
		if key.Node != hash {
			continue
		}
		element.Value.(outboundTransportEntry).transport.CloseIdleConnections()
		p.order.Remove(element)
		delete(p.transports, key)
	}
}

// CloseAll closes idle connections and clears all pooled transports.
func (p *OutboundTransportPool) CloseAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, element := range p.transports {
		element.Value.(outboundTransportEntry).transport.CloseIdleConnections()
	}
	clear(p.transports)
	p.order.Init()
}

func (p *OutboundTransportPool) newReusableOutboundTransport(ob adapter.Outbound, sink MetricsEventSink) *http.Transport {
	if ob == nil {
		return newDirectHTTPTransport(p.config, sink)
	}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := ob.DialContext(ctx, network, M.ParseSocksaddr(addr))
			if err != nil {
				return nil, err
			}
			if sink != nil {
				sink.OnConnectionLifecycle(ConnectionOutbound, ConnectionOpen)
				conn = newCountingConn(conn, sink)
			}
			return conn, nil
		},
		DisableKeepAlives:   false,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        p.config.MaxIdleConns,
		MaxIdleConnsPerHost: p.config.MaxIdleConnsPerHost,
		IdleConnTimeout:     p.config.IdleConnTimeout,
	}
}

func newDirectHTTPTransport(cfg OutboundTransportConfig, sink MetricsEventSink) *http.Transport {
	cfg = normalizeOutboundTransportConfig(cfg)
	dialer := &net.Dialer{}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if sink != nil {
				sink.OnConnectionLifecycle(ConnectionOutbound, ConnectionOpen)
				conn = newCountingConn(conn, sink)
			}
			return conn, nil
		},
		DisableKeepAlives:   false,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        cfg.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.MaxIdleConnsPerHost,
		IdleConnTimeout:     cfg.IdleConnTimeout,
	}
}
