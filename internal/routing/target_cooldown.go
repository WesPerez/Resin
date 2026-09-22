package routing

import (
	"net/netip"
	"strings"
	"time"

	"github.com/Resinat/Resin/internal/netutil"
	"github.com/Resinat/Resin/internal/node"
)

const (
	maxTargetCooldowns   = 4096
	maxTargetCooldownTTL = 10 * time.Minute
)

type targetCooldownKey struct {
	platformID string
	account    string
	domain     string
	node       node.Hash
}

type targetCooldown struct {
	ip    netip.Addr
	until time.Time
}

func recoveryDomain(target string) string {
	return strings.TrimSuffix(strings.ToLower(netutil.ExtractDomain(target)), ".")
}

// TargetCooling only reads account-local observations. It never changes the
// shared node health or the routing view used by other proxy consumers.
func (r *Router) TargetCooling(platformID, account, target string, hash node.Hash, ip netip.Addr) bool {
	r.recoveryMu.RLock()
	defer r.recoveryMu.RUnlock()
	now := time.Now()
	domain := recoveryDomain(target)
	for key, entry := range r.targetCooldowns {
		if key.platformID == platformID && key.account == account && key.domain == domain && now.Before(entry.until) &&
			(key.node == hash || (ip.IsValid() && ip == entry.ip)) {
			return true
		}
	}
	return false
}

func (r *Router) addTargetCooldownExclusionsLocked(platformID, account, target string, now time.Time, excluded nodeExclusionSet) {
	domain := recoveryDomain(target)
	ips := make(map[netip.Addr]struct{})
	for key, entry := range r.targetCooldowns {
		if key.platformID != platformID || key.account != account || key.domain != domain || !now.Before(entry.until) {
			continue
		}
		excluded[key.node] = struct{}{}
		if entry.ip.IsValid() {
			ips[entry.ip] = struct{}{}
		}
	}
	if plat, ok := r.pool.GetPlatform(platformID); ok && len(ips) > 0 {
		plat.View().Range(func(hash node.Hash) bool {
			if entry, exists := r.pool.GetEntry(hash); exists {
				if _, cooling := ips[entry.GetEgressIP()]; cooling {
					excluded[hash] = struct{}{}
				}
			}
			return true
		})
	}
}

func (r *Router) recordTargetCooldownLocked(platformID, account, target string, lease Lease, now time.Time, ttl time.Duration) {
	if r.targetCooldowns == nil {
		r.targetCooldowns = make(map[targetCooldownKey]targetCooldown)
	}
	for key, entry := range r.targetCooldowns {
		if !now.Before(entry.until) {
			delete(r.targetCooldowns, key)
		}
	}
	key := targetCooldownKey{platformID, account, recoveryDomain(target), lease.NodeHash}
	if _, exists := r.targetCooldowns[key]; !exists && len(r.targetCooldowns) >= maxTargetCooldowns {
		var oldestKey targetCooldownKey
		var oldest time.Time
		for candidate, entry := range r.targetCooldowns {
			if oldest.IsZero() || entry.until.Before(oldest) {
				oldestKey, oldest = candidate, entry.until
			}
		}
		delete(r.targetCooldowns, oldestKey)
	}
	r.targetCooldowns[key] = targetCooldown{lease.EgressIP, now.Add(min(ttl, maxTargetCooldownTTL))}
}
