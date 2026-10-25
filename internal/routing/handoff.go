package routing

import (
	"errors"
	"net/netip"

	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/node"
	"github.com/puzpuzpuz/xsync/v4"
)

// ValidateHandoffLeases builds the complete replacement before any mutation.
// The caller must keep local admission and background services stopped until
// persistence and replacement have both succeeded.
func (r *Router) ValidateHandoffLeases(rows []model.Lease, cutoff int64) error {
	seen := make(map[model.LeaseKey]bool, len(rows))
	for _, l := range rows {
		key := model.LeaseKey{PlatformID: l.PlatformID, Account: l.Account}
		h, err := node.ParseHex(l.NodeHash)
		ip, ipErr := netip.ParseAddr(l.EgressIP)
		_, exists := r.pool.GetPlatform(l.PlatformID)
		if err != nil || ipErr != nil || h.IsZero() || !ip.IsValid() || l.Account == "" || !exists || seen[key] || l.CreatedAtNs <= 0 || l.ExpiryNs <= cutoff || l.LastAccessedNs < l.CreatedAtNs || l.CreatedAtNs > cutoff || l.LastAccessedNs > cutoff || l.ExpiryNs <= l.CreatedAtNs {
			return errors.New("invalid handoff lease")
		}
		// Historical leases may outlive a removed node. Preserve their identity;
		// the owner separately verifies currently usable bindings before cutover.
		seen[key] = true
	}
	return nil
}

func (r *Router) ReplaceHandoffLeases(rows []model.Lease) {
	// No local handler/cleaner/flush is running. recoveryMu also excludes the
	// ordinary recovery registration paths during the in-memory replacement.
	r.recoveryMu.Lock()
	defer r.recoveryMu.Unlock()
	states := xsync.NewMap[string, *PlatformRoutingState]()
	for _, l := range rows {
		h, _ := node.ParseHex(l.NodeHash)
		ip, _ := netip.ParseAddr(l.EgressIP)
		s, _ := states.LoadOrCompute(l.PlatformID, func() (*PlatformRoutingState, bool) { return NewPlatformRoutingState(), false })
		s.Leases.CreateLease(l.Account, Lease{NodeHash: h, EgressIP: ip, CreatedAtNs: l.CreatedAtNs, ExpiryNs: l.ExpiryNs, LastAccessedNs: l.LastAccessedNs})
	}
	r.states = states
}
