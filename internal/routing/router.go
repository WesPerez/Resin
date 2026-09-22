package routing

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/netutil"
	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/platform"
	"github.com/puzpuzpuz/xsync/v4"
)

var (
	ErrPlatformNotFound = errors.New("platform not found")
)

type PoolAccessor interface {
	GetEntry(hash node.Hash) (*node.NodeEntry, bool)
	GetPlatform(id string) (*platform.Platform, bool)
	GetPlatformByName(name string) (*platform.Platform, bool)
	RangePlatforms(fn func(*platform.Platform) bool)
}

// Router handles route selection and lease management.
type Router struct {
	pool              PoolAccessor
	states            *xsync.Map[string, *PlatformRoutingState]
	authorities       func() []string
	p2cWindow         func() time.Duration
	onLeaseEvent      LeaseEventFunc
	nodeTagResolver   func(node.Hash) string
	recoveryMu        sync.RWMutex
	leaseConnections  map[leaseConnectionKey]map[*leaseConnection]struct{}
	targetCooldowns   map[targetCooldownKey]targetCooldown
	recoveryPolicy    func() RecoveryPolicy
	recoveryAccounts  map[model.LeaseKey]recoveryAccountHistory
	recoveryPlatforms map[string]*recoveryPlatformHistory
	recoveryStatus    RecoveryStatus
}

type RouterConfig struct {
	Pool        PoolAccessor
	Authorities func() []string
	P2CWindow   func() time.Duration
	// OnLeaseEvent is called synchronously; handlers must stay lightweight.
	OnLeaseEvent LeaseEventFunc
	// NodeTagResolver resolves a node hash to its display tag ("<Sub>/<Tag>").
	// If nil, NodeTag will be empty.
	NodeTagResolver func(node.Hash) string
	// RecoveryPolicy is read for automatic recovery only, never manual rotation.
	RecoveryPolicy func() RecoveryPolicy
}

func NewRouter(cfg RouterConfig) *Router {
	return &Router{
		pool:            cfg.Pool,
		states:          xsync.NewMap[string, *PlatformRoutingState](),
		authorities:     cfg.Authorities,
		p2cWindow:       cfg.P2CWindow,
		onLeaseEvent:    cfg.OnLeaseEvent,
		nodeTagResolver: cfg.NodeTagResolver,
		recoveryPolicy:  cfg.RecoveryPolicy,
		recoveryStatus:  RecoveryStatus{Since: time.Now()},
	}
}

type RouteResult struct {
	PlatformID        string
	PlatformName      string
	NodeHash          node.Hash
	EgressIP          netip.Addr
	NodeTag           string // display tag: "<Subscription>/<Tag>" (DESIGN.md §601)
	LeaseCreated      bool
	LeaseCreatedAtNs  int64
	LeaseAccount      string
	LeaseGuarded      bool
	LeaseGuardUntilMs int64
}

const livePickAttempts = 2 // first pick + one retry

type leaseInvalidationReason int

const (
	leaseInvalidationNone leaseInvalidationReason = iota
	leaseInvalidationExpire
	leaseInvalidationRemove
)

func (r *Router) RouteRequest(platName, account, target string) (RouteResult, error) {
	return r.routeRequest(platName, account, target, nil, false)
}

// AcquireRecoveryRoute never deletes an existing binding when selection fails.
func (r *Router) AcquireRecoveryRoute(platName, account, target string) (RouteResult, error) {
	return r.routeRequest(platName, account, target, nil, true)
}

// RouteRequestExcluding routes one request while excluding a node that failed
// earlier in the same connection attempt.
func (r *Router) RouteRequestExcluding(platName, account, target string, excluded node.Hash) (RouteResult, error) {
	if excluded.IsZero() {
		return r.routeRequest(platName, account, target, nil, false)
	}
	return r.routeRequest(platName, account, target, nodeExclusionSet{excluded: struct{}{}}, false)
}

// RouteRequestExcludingNodes routes one request while excluding every node
// that already failed during the same bounded connection attempt.
func (r *Router) RouteRequestExcludingNodes(platName, account, target string, excluded []node.Hash) (RouteResult, error) {
	return r.routeRequest(platName, account, target, newNodeExclusionSet(excluded), false)
}

// PeekRouteExcludingNodes selects a retry candidate without changing a sticky
// lease, load counters or lease events. A zero lease generation intentionally
// leaves one-off connections outside lease registration and recovery.
func (r *Router) PeekRouteExcludingNodes(platName, account, target string, excluded []node.Hash) (RouteResult, error) {
	if HasLeaseGuard(account) {
		return RouteResult{}, ErrLeaseGuard
	}
	plat, err := r.resolvePlatform(platName)
	if err != nil {
		return RouteResult{}, err
	}
	exclusions := newNodeExclusionSet(excluded)
	if exclusions == nil {
		exclusions = make(nodeExclusionSet)
	}
	r.recoveryMu.RLock()
	r.addTargetCooldownExclusionsLocked(plat.ID, account, target, time.Now(), exclusions)
	result, err := r.routeRandom(plat, r.ensurePlatformState(plat.ID), netutil.ExtractDomain(target), exclusions)
	r.recoveryMu.RUnlock()
	if err != nil {
		return RouteResult{}, err
	}
	result = withPlatformContext(plat, result)
	if r.nodeTagResolver != nil {
		result.NodeTag = r.nodeTagResolver(result.NodeHash)
	}
	return result, nil
}

type nodeExclusionSet map[node.Hash]struct{}

func newNodeExclusionSet(nodes []node.Hash) nodeExclusionSet {
	if len(nodes) == 0 {
		return nil
	}
	excluded := make(nodeExclusionSet, len(nodes))
	for _, hash := range nodes {
		if !hash.IsZero() {
			excluded[hash] = struct{}{}
		}
	}
	return excluded
}

func (s nodeExclusionSet) contains(hash node.Hash) bool {
	if len(s) == 0 || hash.IsZero() {
		return false
	}
	_, ok := s[hash]
	return ok
}

func (r *Router) routeRequest(platName, account, target string, excluded nodeExclusionSet, preserveOnFailure bool) (RouteResult, error) {
	now := time.Now()
	guard, err := parseLeaseGuard(account, now)
	if err != nil {
		return RouteResult{}, err
	}
	plat, err := r.resolvePlatform(platName)
	if err != nil {
		return RouteResult{}, err
	}

	targetDomain := netutil.ExtractDomain(target)
	state := r.ensurePlatformState(plat.ID)
	var result RouteResult
	if guard != nil {
		result, err = r.routeGuarded(plat, state, guard, now, excluded)
	} else if account == "" {
		result, err = r.routeRandom(plat, state, targetDomain, excluded)
	} else {
		result, err = r.routeSticky(plat, state, account, targetDomain, now, excluded, preserveOnFailure)
	}
	if err != nil {
		return RouteResult{}, err
	}
	result = withPlatformContext(plat, result)
	if r.nodeTagResolver != nil {
		result.NodeTag = r.nodeTagResolver(result.NodeHash)
	}
	return result, nil
}

func withPlatformContext(plat *platform.Platform, res RouteResult) RouteResult {
	res.PlatformID = plat.ID
	res.PlatformName = plat.Name
	return res
}

func (r *Router) resolvePlatform(platName string) (*platform.Platform, error) {
	if platName == "" {
		if p, ok := r.pool.GetPlatform(platform.DefaultPlatformID); ok {
			return p, nil
		}
		return nil, ErrPlatformNotFound
	}
	p, ok := r.pool.GetPlatformByName(platName)
	if !ok {
		return nil, ErrPlatformNotFound
	}
	return p, nil
}

func (r *Router) ensurePlatformState(platformID string) *PlatformRoutingState {
	state, _ := r.states.LoadOrCompute(platformID, func() (*PlatformRoutingState, bool) {
		return NewPlatformRoutingState(), false
	})
	return state
}

func (r *Router) routeRandom(
	plat *platform.Platform,
	state *PlatformRoutingState,
	targetDomain string,
	excluded nodeExclusionSet,
) (RouteResult, error) {
	h, entry, err := r.selectLiveRandomRoute(plat, state.IPLoadStats, targetDomain, excluded)
	if err != nil {
		return RouteResult{}, err
	}
	return RouteResult{
		NodeHash:     h,
		EgressIP:     entry.GetEgressIP(),
		LeaseCreated: false,
	}, nil
}

func (r *Router) routeSticky(
	plat *platform.Platform,
	state *PlatformRoutingState,
	account string,
	targetDomain string,
	now time.Time,
	excluded nodeExclusionSet,
	preserveOnFailure bool,
) (RouteResult, error) {
	r.recoveryMu.RLock()
	if preserveOnFailure {
		if excluded == nil {
			excluded = make(nodeExclusionSet)
		}
		// Apply cooldowns before any sticky hit or same-IP replacement commits.
		r.addTargetCooldownExclusionsLocked(plat.ID, account, targetDomain, now, excluded)
	}
	nowNs := now.UnixNano()
	var result RouteResult
	var routeErr error
	var events []LeaseEvent

	_, _ = state.Leases.leases.Compute(account, func(current Lease, loaded bool) (Lease, xsync.ComputeOp) {
		newLease, op, routeResult, err := r.decideStickyLease(
			plat,
			state,
			account,
			targetDomain,
			now,
			nowNs,
			current,
			loaded,
			excluded,
			&events,
			preserveOnFailure,
		)
		if err != nil {
			routeErr = err
			return newLease, op
		}
		result = routeResult
		return newLease, op
	})
	r.recoveryMu.RUnlock()
	for _, event := range events {
		r.emitLeaseEvent(event)
	}

	return result, routeErr
}

func (r *Router) decideStickyLease(
	plat *platform.Platform,
	state *PlatformRoutingState,
	account string,
	targetDomain string,
	now time.Time,
	nowNs int64,
	current Lease,
	loaded bool,
	excluded nodeExclusionSet,
	events *[]LeaseEvent,
	preserveOnFailure bool,
) (Lease, xsync.ComputeOp, RouteResult, error) {
	hadPreviousLease := loaded
	invalidation := leaseInvalidationNone

	if loaded && current.IsExpired(now) {
		invalidation = leaseInvalidationExpire
		loaded = false
	}

	if loaded {
		if newLease, hitResult, ok := r.tryLeaseHit(plat, account, current, nowNs, excluded, events); ok {
			return newLease, xsync.UpdateOp, hitResult, nil
		}
		if newLease, rotatedResult, ok := r.tryLeaseSameIPRotation(plat, account, current, targetDomain, nowNs, excluded, events); ok {
			return newLease, xsync.UpdateOp, rotatedResult, nil
		}
		invalidation = leaseInvalidationRemove
	}

	return r.createOrAbortStickyLease(
		plat,
		state,
		account,
		targetDomain,
		now,
		nowNs,
		current,
		hadPreviousLease,
		invalidation,
		excluded,
		events,
		preserveOnFailure,
	)
}

func (r *Router) createOrAbortStickyLease(
	plat *platform.Platform,
	state *PlatformRoutingState,
	account string,
	targetDomain string,
	now time.Time,
	nowNs int64,
	previous Lease,
	hadPreviousLease bool,
	invalidation leaseInvalidationReason,
	excluded nodeExclusionSet,
	events *[]LeaseEvent,
	preserveOnFailure bool,
) (Lease, xsync.ComputeOp, RouteResult, error) {
	if hadPreviousLease {
		nowNs = max(nowNs, previous.CreatedAtNs+1)
	}
	newLease, createdResult, err := r.createLease(plat, state, targetDomain, now, nowNs, excluded)
	if err != nil {
		if hadPreviousLease && preserveOnFailure {
			return previous, xsync.CancelOp, RouteResult{}, err
		}
		r.cleanupPreviousLease(state, previous, hadPreviousLease, invalidation, plat.ID, account, events)
		lease, op := abortLeaseCreate(previous, hadPreviousLease)
		return lease, op, RouteResult{}, err
	}

	r.cleanupPreviousLease(state, previous, hadPreviousLease, invalidation, plat.ID, account, events)
	state.IPLoadStats.Inc(newLease.EgressIP)
	*events = append(*events, LeaseEvent{
		Type:       LeaseCreate,
		PlatformID: plat.ID,
		Account:    account,
		NodeHash:   newLease.NodeHash,
		EgressIP:   newLease.EgressIP,
	})
	return newLease, xsync.UpdateOp, createdResult, nil
}

func (r *Router) tryLeaseHit(
	plat *platform.Platform,
	account string,
	current Lease,
	nowNs int64,
	excluded nodeExclusionSet,
	events *[]LeaseEvent,
) (Lease, RouteResult, bool) {
	if excluded.contains(current.NodeHash) {
		return Lease{}, RouteResult{}, false
	}
	entry, ok := r.pool.GetEntry(current.NodeHash)
	if !ok || !plat.View().Contains(current.NodeHash) || entry.GetEgressIP() != current.EgressIP {
		return Lease{}, RouteResult{}, false
	}

	newLease := current
	newLease.LastAccessedNs = nowNs
	*events = append(*events, LeaseEvent{
		Type:       LeaseTouch,
		PlatformID: plat.ID,
		Account:    account,
		NodeHash:   current.NodeHash,
		EgressIP:   current.EgressIP,
	})
	return newLease, RouteResult{
		NodeHash:         current.NodeHash,
		EgressIP:         current.EgressIP,
		LeaseCreated:     false,
		LeaseCreatedAtNs: current.CreatedAtNs,
	}, true
}

func (r *Router) tryLeaseSameIPRotation(
	plat *platform.Platform,
	account string,
	current Lease,
	targetDomain string,
	nowNs int64,
	excluded nodeExclusionSet,
	events *[]LeaseEvent,
) (Lease, RouteResult, bool) {
	bestHash, ok := chooseSameIPRotationCandidate(
		plat,
		r.pool,
		current.EgressIP,
		targetDomain,
		r.authorities(),
		r.p2cWindow(),
		excluded,
	)
	if !ok {
		return Lease{}, RouteResult{}, false
	}

	newLease := current
	newLease.NodeHash = bestHash
	newLease.CreatedAtNs = max(nowNs, current.CreatedAtNs+1)
	newLease.LastAccessedNs = nowNs
	*events = append(*events, LeaseEvent{
		Type:        LeaseReplace,
		PlatformID:  plat.ID,
		Account:     account,
		NodeHash:    bestHash,
		EgressIP:    current.EgressIP,
		CreatedAtNs: newLease.CreatedAtNs,
	})
	return newLease, RouteResult{
		NodeHash:         bestHash,
		EgressIP:         current.EgressIP,
		LeaseCreated:     false,
		LeaseCreatedAtNs: newLease.CreatedAtNs,
	}, true
}

func (r *Router) createLease(
	plat *platform.Platform,
	state *PlatformRoutingState,
	targetDomain string,
	now time.Time,
	nowNs int64,
	excluded nodeExclusionSet,
) (Lease, RouteResult, error) {
	h, entry, err := r.selectLiveRandomRoute(plat, state.IPLoadStats, targetDomain, excluded)
	if err != nil {
		return Lease{}, RouteResult{}, err
	}
	lease := leaseForNode(plat, h, entry.GetEgressIP(), now, nowNs)
	return lease, RouteResult{
		NodeHash:         lease.NodeHash,
		EgressIP:         lease.EgressIP,
		LeaseCreated:     true,
		LeaseCreatedAtNs: lease.CreatedAtNs,
	}, nil
}

func leaseForNode(plat *platform.Platform, h node.Hash, ip netip.Addr, now time.Time, nowNs int64) Lease {
	ttl := plat.StickyTTLNs
	if ttl <= 0 {
		ttl = int64(24 * time.Hour) // Default safeguard
	}

	return Lease{
		NodeHash:       h,
		EgressIP:       ip,
		CreatedAtNs:    nowNs,
		ExpiryNs:       now.Add(time.Duration(ttl)).UnixNano(),
		LastAccessedNs: nowNs,
	}
}

func (r *Router) cleanupPreviousLease(
	state *PlatformRoutingState,
	lease Lease,
	hadPreviousLease bool,
	invalidation leaseInvalidationReason,
	platformID string,
	account string,
	events *[]LeaseEvent,
) {
	if !hadPreviousLease {
		return
	}
	state.Leases.stats.Dec(lease.EgressIP)
	switch invalidation {
	case leaseInvalidationExpire:
		*events = append(*events, LeaseEvent{
			Type:        LeaseExpire,
			PlatformID:  platformID,
			Account:     account,
			NodeHash:    lease.NodeHash,
			EgressIP:    lease.EgressIP,
			CreatedAtNs: lease.CreatedAtNs,
		})
	case leaseInvalidationRemove:
		*events = append(*events, LeaseEvent{
			Type:        LeaseRemove,
			PlatformID:  platformID,
			Account:     account,
			NodeHash:    lease.NodeHash,
			EgressIP:    lease.EgressIP,
			CreatedAtNs: lease.CreatedAtNs,
		})
	}
}

func abortLeaseCreate(current Lease, hadPreviousLease bool) (Lease, xsync.ComputeOp) {
	if hadPreviousLease {
		return current, xsync.DeleteOp
	}
	return current, xsync.CancelOp
}

func (r *Router) emitLeaseEvent(event LeaseEvent) {
	if r.onLeaseEvent != nil {
		r.onLeaseEvent(event)
	}
}

func (r *Router) selectLiveRandomRoute(
	plat *platform.Platform,
	stats *IPLoadStats,
	targetDomain string,
	excluded nodeExclusionSet,
) (node.Hash, *node.NodeEntry, error) {
	var lastMissing node.Hash
	for i := 0; i < livePickAttempts; i++ {
		h, err := randomRouteExcluding(plat, stats, r.pool, targetDomain, r.authorities(), r.p2cWindow(), excluded)
		if err != nil {
			return node.Zero, nil, err
		}
		entry, ok := r.pool.GetEntry(h)
		if ok {
			return h, entry, nil
		}
		lastMissing = h
	}
	if lastMissing != node.Zero {
		return node.Zero, nil, fmt.Errorf("%w: selected node %s no longer in pool", ErrNoAvailableNodes, lastMissing.Hex())
	}
	return node.Zero, nil, ErrNoAvailableNodes
}

func chooseSameIPRotationCandidate(
	plat *platform.Platform,
	pool PoolAccessor,
	targetIP netip.Addr,
	targetDomain string,
	authorities []string,
	window time.Duration,
	excluded nodeExclusionSet,
) (node.Hash, bool) {
	bestKnownHash := node.Zero
	bestKnownLatency := time.Duration(math.MaxInt64)
	fallbackHash := node.Zero

	plat.View().Range(func(h node.Hash) bool {
		if excluded.contains(h) {
			return true
		}
		entry, ok := pool.GetEntry(h)
		if !ok || entry.GetEgressIP() != targetIP {
			return true
		}
		if fallbackHash == node.Zero {
			fallbackHash = h
		}

		latency, hasLatency := sameIPCandidateLatency(entry, targetDomain, authorities, window)
		if hasLatency && latency < bestKnownLatency {
			bestKnownLatency = latency
			bestKnownHash = h
		}
		return true
	})

	if bestKnownHash != node.Zero {
		return bestKnownHash, true
	}
	if fallbackHash != node.Zero {
		return fallbackHash, true
	}
	return node.Zero, false
}

func sameIPCandidateLatency(
	entry *node.NodeEntry,
	targetDomain string,
	authorities []string,
	window time.Duration,
) (time.Duration, bool) {
	now := time.Now()
	if latency, ok := lookupRecentDomainLatency(entry, targetDomain, now, window); ok {
		return latency, true
	}

	if latency, ok := averageRecentAuthorityLatency(entry, authorities, now, window); ok {
		return latency, true
	}
	return 0, false
}

// ReadLease implements weak persistence read.
func (r *Router) ReadLease(key model.LeaseKey) *model.Lease {
	state, ok := r.states.Load(key.PlatformID)
	if !ok {
		return nil
	}
	lease, ok := state.Leases.GetLease(key.Account)
	if !ok {
		return nil
	}
	return &model.Lease{
		PlatformID:     key.PlatformID,
		Account:        key.Account,
		NodeHash:       lease.NodeHash.Hex(),
		EgressIP:       lease.EgressIP.String(),
		CreatedAtNs:    lease.CreatedAtNs,
		ExpiryNs:       lease.ExpiryNs,
		LastAccessedNs: lease.LastAccessedNs,
	}
}

// UpsertLease writes or replaces a lease for (platform_id, account).
// It updates per-IP lease counters and emits LeaseCreate/LeaseReplace events.
func (r *Router) UpsertLease(ml model.Lease) error {
	platformID := strings.TrimSpace(ml.PlatformID)
	if platformID == "" {
		return errors.New("platform_id is required")
	}
	account := strings.TrimSpace(ml.Account)
	if account == "" {
		return errors.New("account is required")
	}

	h, err := node.ParseHex(ml.NodeHash)
	if err != nil {
		return fmt.Errorf("parse node_hash: %w", err)
	}
	ip, err := netip.ParseAddr(ml.EgressIP)
	if err != nil {
		return fmt.Errorf("parse egress_ip: %w", err)
	}

	r.recoveryMu.RLock()

	state := r.ensurePlatformState(platformID)
	lease := Lease{
		NodeHash:       h,
		EgressIP:       ip,
		CreatedAtNs:    ml.CreatedAtNs,
		ExpiryNs:       ml.ExpiryNs,
		LastAccessedNs: ml.LastAccessedNs,
	}

	eventType := LeaseCreate
	_, _ = state.Leases.leases.Compute(account, func(current Lease, loaded bool) (Lease, xsync.ComputeOp) {
		if loaded {
			state.Leases.stats.Dec(current.EgressIP)
			eventType = LeaseReplace
		}
		state.Leases.stats.Inc(lease.EgressIP)
		return lease, xsync.UpdateOp
	})
	r.recoveryMu.RUnlock()

	r.emitLeaseEvent(LeaseEvent{
		Type:       eventType,
		PlatformID: platformID,
		Account:    account,
		NodeHash:   lease.NodeHash,
		EgressIP:   lease.EgressIP,
	})
	return nil
}

// SnapshotIPLoad returns a best-effort point-in-time IP load snapshot for a platform.
// If the platform has no routing state yet, it returns an empty snapshot.
func (r *Router) SnapshotIPLoad(platformID string) map[netip.Addr]int64 {
	state, ok := r.states.Load(platformID)
	if !ok {
		return map[netip.Addr]int64{}
	}
	return state.IPLoadStats.Snapshot()
}

// RestoreLeases restores leases from persistence during bootstrap.
func (r *Router) RestoreLeases(leases []model.Lease) {
	r.recoveryMu.RLock()
	defer r.recoveryMu.RUnlock()

	for _, ml := range leases {
		h, err := node.ParseHex(ml.NodeHash)
		if err != nil {
			continue
		}
		ip, err := netip.ParseAddr(ml.EgressIP)
		if err != nil {
			continue
		}

		state, _ := r.states.LoadOrCompute(ml.PlatformID, func() (*PlatformRoutingState, bool) {
			return NewPlatformRoutingState(), false
		})

		l := Lease{
			NodeHash:       h,
			EgressIP:       ip,
			CreatedAtNs:    ml.CreatedAtNs,
			ExpiryNs:       ml.ExpiryNs,
			LastAccessedNs: ml.LastAccessedNs,
		}
		// Directly insert into table and stats
		state.Leases.CreateLease(ml.Account, l)
	}
}

// RangeLeases iterates over all leases for a platform.
// Returns false if the platform has no routing state.
func (r *Router) RangeLeases(platformID string, fn func(account string, lease Lease) bool) bool {
	state, ok := r.states.Load(platformID)
	if !ok {
		return false
	}
	state.Leases.Range(fn)
	return true
}

// DeleteLease removes a single lease by platform and account.
// Returns true if a lease was deleted. Emits a LeaseRemove event.
func (r *Router) DeleteLease(platformID, account string) bool {
	r.recoveryMu.RLock()
	state, ok := r.states.Load(platformID)
	if !ok {
		r.recoveryMu.RUnlock()
		return false
	}
	lease, deleted := state.Leases.DeleteLease(account)
	r.recoveryMu.RUnlock()
	if !deleted {
		return false
	}
	r.emitLeaseEvent(LeaseEvent{
		Type:        LeaseRemove,
		PlatformID:  platformID,
		Account:     account,
		NodeHash:    lease.NodeHash,
		EgressIP:    lease.EgressIP,
		CreatedAtNs: lease.CreatedAtNs,
	})
	return true
}

// DeleteLeaseIfNode removes a lease only if it still references expectedNode.
// Returns false when another request has already replaced the lease.
func (r *Router) DeleteLeaseIfGeneration(platformID, account string, expectedNode node.Hash, expectedCreatedAtNs int64) bool {
	r.recoveryMu.RLock()
	state, ok := r.states.Load(platformID)
	if !ok {
		r.recoveryMu.RUnlock()
		return false
	}
	lease, deleted := state.Leases.DeleteLeaseIfGeneration(account, expectedNode, expectedCreatedAtNs)
	r.recoveryMu.RUnlock()
	if !deleted {
		return false
	}
	r.emitLeaseEvent(LeaseEvent{
		Type:        LeaseRemove,
		PlatformID:  platformID,
		Account:     account,
		NodeHash:    lease.NodeHash,
		EgressIP:    lease.EgressIP,
		CreatedAtNs: lease.CreatedAtNs,
	})
	return true
}

// DeleteLeaseIfNode removes a lease only if it still references expectedNode.
// Callers that observed a full lease generation should use DeleteLeaseIfGeneration.
func (r *Router) DeleteLeaseIfNode(platformID, account string, expectedNode node.Hash) bool {
	r.recoveryMu.RLock()
	state, ok := r.states.Load(platformID)
	if !ok {
		r.recoveryMu.RUnlock()
		return false
	}
	lease, deleted := state.Leases.DeleteLeaseIfNode(account, expectedNode)
	r.recoveryMu.RUnlock()
	if !deleted {
		return false
	}
	r.emitLeaseEvent(LeaseEvent{
		Type:        LeaseRemove,
		PlatformID:  platformID,
		Account:     account,
		NodeHash:    lease.NodeHash,
		EgressIP:    lease.EgressIP,
		CreatedAtNs: lease.CreatedAtNs,
	})
	return true
}

// DeleteAllLeases removes all leases for a platform.
// Returns the number of leases deleted. Emits a LeaseRemove event for each.
func (r *Router) DeleteAllLeases(platformID string) int {
	r.recoveryMu.RLock()
	state, ok := r.states.Load(platformID)
	if !ok {
		r.recoveryMu.RUnlock()
		return 0
	}
	count := 0
	var events []LeaseEvent
	state.Leases.Range(func(account string, _ Lease) bool {
		removed, deleted := state.Leases.DeleteLease(account)
		if deleted {
			events = append(events, LeaseEvent{
				Type:        LeaseRemove,
				PlatformID:  platformID,
				Account:     account,
				NodeHash:    removed.NodeHash,
				EgressIP:    removed.EgressIP,
				CreatedAtNs: removed.CreatedAtNs,
			})
			count++
		}
		return true
	})
	r.recoveryMu.RUnlock()
	for _, event := range events {
		r.emitLeaseEvent(event)
	}
	return count
}
