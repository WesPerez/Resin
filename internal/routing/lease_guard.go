package routing

import (
	"encoding/base64"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/platform"
	"github.com/puzpuzpuz/xsync/v4"
)

// Guarded accounts are an opt-in, stateless constraint on an existing lease.
// No extra account, lease or platform is allocated. Every connection carries
// the expected generation, so restart, expiry or explicit recovery fails closed.
const LeaseGuardMarker = "~r1~"
const LeaseGuardVersion = 1
const MaxLeaseGuardDuration = 15 * time.Minute

var ErrLeaseGuard = errors.New("guarded lease changed, expired, or unavailable")

type leaseGuard struct {
	account   string
	node      node.Hash
	createdNs int64
	ip        netip.Addr
	untilMs   int64
}

func HasLeaseGuard(account string) bool {
	return strings.Contains(account, LeaseGuardMarker)
}

func parseLeaseGuard(account string, now time.Time) (*leaseGuard, error) {
	base, suffix, found := strings.Cut(account, LeaseGuardMarker)
	if !found {
		return nil, nil
	}
	parts := strings.Split(suffix, "~")
	if base == "" || len(base) > 64 || len(parts) != 4 || len(suffix) > 160 {
		return nil, ErrLeaseGuard
	}
	for _, ch := range base {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return nil, ErrLeaseGuard
		}
	}
	hash, err := node.ParseHex(parts[0])
	if err != nil || hash.IsZero() {
		return nil, ErrLeaseGuard
	}
	created, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || created <= 0 {
		return nil, ErrLeaseGuard
	}
	until, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || until <= now.UnixMilli() || until > now.Add(MaxLeaseGuardDuration).UnixMilli() {
		return nil, ErrLeaseGuard
	}
	encodedIP, err := base64.RawURLEncoding.Strict().DecodeString(parts[3])
	if err != nil {
		return nil, ErrLeaseGuard
	}
	ip, err := netip.ParseAddr(string(encodedIP))
	if err != nil || ip.Zone() != "" || !ip.IsGlobalUnicast() {
		return nil, ErrLeaseGuard
	}
	return &leaseGuard{account: base, node: hash, createdNs: created, ip: ip.Unmap(), untilMs: until}, nil
}

func (r *Router) routeGuarded(plat *platform.Platform, state *PlatformRoutingState, guard *leaseGuard, now time.Time, excluded nodeExclusionSet) (RouteResult, error) {
	r.recoveryMu.RLock()
	var result RouteResult
	var events []LeaseEvent
	routeErr := ErrLeaseGuard
	_, _ = state.Leases.leases.Compute(guard.account, func(current Lease, loaded bool) (Lease, xsync.ComputeOp) {
		now = time.Now()
		if now.UnixMilli() >= guard.untilMs || !loaded || current.IsExpired(now) || current.NodeHash != guard.node || current.CreatedAtNs != guard.createdNs || current.EgressIP != guard.ip {
			return current, xsync.CancelOp
		}
		entry, ok := r.pool.GetEntry(current.NodeHash)
		if !ok || !entry.IsHealthy() {
			return current, xsync.CancelOp
		}
		next, hit, ok := r.tryLeaseHit(plat, guard.account, current, now.UnixNano(), excluded, &events)
		if !ok {
			return current, xsync.CancelOp
		}
		hit.LeaseAccount = guard.account
		hit.LeaseGuarded = true
		hit.LeaseGuardUntilMs = guard.untilMs
		result, routeErr = hit, nil
		return next, xsync.UpdateOp
	})
	r.recoveryMu.RUnlock()
	for _, event := range events {
		r.emitLeaseEvent(event)
	}
	return result, routeErr
}
