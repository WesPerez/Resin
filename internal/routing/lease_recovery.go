package routing

import (
	"errors"
	"time"

	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/netutil"
	"github.com/Resinat/Resin/internal/node"
	"github.com/puzpuzpuz/xsync/v4"
)

var ErrLeaseChanged = errors.New("lease absent, expired, or changed")

type leaseConnectionKey struct {
	platformID  string
	account     string
	node        node.Hash
	createdAtNs int64
}

type leaseConnection struct {
	close func()
}

// RegisterLeaseConnection rejects a dial that completed after its lease rotated.
// The recovery lock covers both registration and replacement, including late dials.
func (r *Router) RegisterLeaseConnection(route RouteResult, account string, closeConnection func()) (func(), bool) {
	if r == nil || account == "" || route.PlatformID == "" || route.LeaseCreatedAtNs == 0 || closeConnection == nil {
		return func() {}, true
	}
	key := leaseConnectionKey{route.PlatformID, account, route.NodeHash, route.LeaseCreatedAtNs}
	r.recoveryMu.Lock()
	defer r.recoveryMu.Unlock()
	lease := r.ReadLease(model.LeaseKey{PlatformID: route.PlatformID, Account: account})
	if lease == nil || lease.NodeHash != route.NodeHash.Hex() || lease.CreatedAtNs != route.LeaseCreatedAtNs {
		return func() {}, false
	}
	if r.leaseConnections == nil {
		r.leaseConnections = make(map[leaseConnectionKey]map[*leaseConnection]struct{})
	}
	if r.leaseConnections[key] == nil {
		r.leaseConnections[key] = make(map[*leaseConnection]struct{})
	}
	connection := &leaseConnection{close: closeConnection}
	r.leaseConnections[key][connection] = struct{}{}
	return func() {
		r.recoveryMu.Lock()
		defer r.recoveryMu.Unlock()
		delete(r.leaseConnections[key], connection)
		if len(r.leaseConnections[key]) == 0 {
			delete(r.leaseConnections, key)
		}
	}, true
}

// RotateLease replaces exactly the observed lease. No candidate leaves it intact.
// Existing tunnels for that version are closed before the caller receives success.
func (r *Router) RotateLease(platformID, account string, expectedNode node.Hash, expectedCreatedAtNs int64, target string, excludeEgressIP bool) (*model.Lease, int, error) {
	plat, ok := r.pool.GetPlatform(platformID)
	if !ok {
		return nil, 0, ErrPlatformNotFound
	}
	state := r.ensurePlatformState(platformID)
	key := leaseConnectionKey{platformID, account, expectedNode, expectedCreatedAtNs}
	var next *model.Lease
	var event *LeaseEvent
	var rotateErr error
	r.recoveryMu.Lock()
	_, _ = state.Leases.leases.Compute(account, func(current Lease, loaded bool) (Lease, xsync.ComputeOp) {
		now := time.Now()
		if !loaded || current.IsExpired(now) || current.NodeHash != expectedNode || current.CreatedAtNs != expectedCreatedAtNs {
			rotateErr = ErrLeaseChanged
			return current, xsync.CancelOp
		}
		excluded := nodeExclusionSet{expectedNode: struct{}{}}
		if excludeEgressIP {
			plat.View().Range(func(hash node.Hash) bool {
				if entry, exists := r.pool.GetEntry(hash); exists && entry.GetEgressIP() == current.EgressIP {
					excluded[hash] = struct{}{}
				}
				return true
			})
		}
		nowNs := max(now.UnixNano(), current.CreatedAtNs+1)
		replacement, _, err := r.createLease(plat, state, netutil.ExtractDomain(target), now, nowNs, excluded)
		if err != nil {
			rotateErr = err
			return current, xsync.CancelOp
		}
		// Recheck the selected IP because an egress probe can update it concurrently.
		if replacement.NodeHash == current.NodeHash || (excludeEgressIP && replacement.EgressIP == current.EgressIP) {
			rotateErr = ErrNoAvailableNodes
			return current, xsync.CancelOp
		}
		state.IPLoadStats.Dec(current.EgressIP)
		state.IPLoadStats.Inc(replacement.EgressIP)
		next = &model.Lease{
			PlatformID: platformID, Account: account, NodeHash: replacement.NodeHash.Hex(),
			EgressIP: replacement.EgressIP.String(), CreatedAtNs: replacement.CreatedAtNs,
			ExpiryNs: replacement.ExpiryNs, LastAccessedNs: replacement.LastAccessedNs,
		}
		event = &LeaseEvent{Type: LeaseReplace, PlatformID: platformID, Account: account,
			NodeHash: replacement.NodeHash, EgressIP: replacement.EgressIP, CreatedAtNs: replacement.CreatedAtNs}
		return replacement, xsync.UpdateOp
	})
	var connections []*leaseConnection
	if rotateErr == nil {
		for connection := range r.leaseConnections[key] {
			connections = append(connections, connection)
		}
		delete(r.leaseConnections, key)
	}
	r.recoveryMu.Unlock()
	for _, connection := range connections {
		connection.close()
	}
	if event != nil {
		r.emitLeaseEvent(*event)
	}
	return next, len(connections), rotateErr
}
