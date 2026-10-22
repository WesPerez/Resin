package routing

import (
	"errors"
	"net/netip"

	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/node"
	"github.com/puzpuzpuz/xsync/v4"
)

var ErrLeaseMetadataBusy = errors.New("lease metadata busy")

// LeaseGeneration identifies the exact route observed by a metadata writer.
// Access time and expiry are deliberately excluded: ordinary use renews them.
type LeaseGeneration struct {
	NodeHash    node.Hash
	EgressIP    netip.Addr
	CreatedAtNs int64
}

func (t *LeaseTable) withLeaseGeneration(account string, expected LeaseGeneration, write func() error) (Lease, bool, error) {
	var observed Lease
	var matched bool
	var err error
	t.leases.Compute(account, func(current Lease, loaded bool) (Lease, xsync.ComputeOp) {
		if !loaded || current.NodeHash != expected.NodeHash || current.EgressIP != expected.EgressIP || current.CreatedAtNs != expected.CreatedAtNs {
			return current, xsync.CancelOp
		}
		observed, matched = current, true
		// Lock order: recovery -> lease key -> StateRepo.TryLock. The callback
		// may only attempt the context-bound, single-row label insert; never
		// call routing, emit events, access the network or wait for StateRepo.
		err = write()
		return current, xsync.CancelOp
	})
	return observed, matched, err
}

// WithLeaseGeneration serializes an optional metadata write with deletion and
// replacement of this lease. It never allocates or changes a route. A recovery
// already holding the global lock wins over optional metadata work.
func (r *Router) WithLeaseGeneration(platformID, account string, expected LeaseGeneration, write func() error) (model.Lease, bool, error) {
	if !r.recoveryMu.TryRLock() {
		return model.Lease{}, false, ErrLeaseMetadataBusy
	}
	defer r.recoveryMu.RUnlock()
	state, ok := r.states.Load(platformID)
	if !ok {
		return model.Lease{}, false, nil
	}
	lease, matched, err := state.Leases.withLeaseGeneration(account, expected, write)
	if !matched || err != nil {
		return model.Lease{}, matched, err
	}
	return model.Lease{
		PlatformID: platformID, Account: account, NodeHash: lease.NodeHash.Hex(),
		EgressIP: lease.EgressIP.String(), CreatedAtNs: lease.CreatedAtNs,
		ExpiryNs: lease.ExpiryNs, LastAccessedNs: lease.LastAccessedNs,
	}, true, nil
}
