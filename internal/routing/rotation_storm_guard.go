package routing

import (
	"errors"
	"time"

	"github.com/Resinat/Resin/internal/model"
)

var (
	ErrRecoveryLimited  = errors.New("automatic lease recovery is cooling down")
	ErrRecoveryDisabled = errors.New("automatic lease recovery is disabled")
)

const (
	recoveryPlatformWindow     = time.Minute
	recoveryAccountInterval    = 30 * time.Second
	recoveryAccountBurstWindow = 15 * time.Minute
	recoveryAccountBurstLimit  = 3
	recoveryAccountCooldown    = time.Hour
	maxRecoveryAccounts        = 4096
	maxRecoveryPlatforms       = 256
)

// RecoveryPolicy contains the operator-adjustable limits. Per-account limits
// remain safety bounds: 30s between rotations, at most 3 per 15m, then 1h quiet.
type RecoveryPolicy struct {
	Enabled              bool
	PlatformAccountLimit int
	PlatformCooldown     time.Duration
}

func DefaultRecoveryPolicy() RecoveryPolicy {
	return RecoveryPolicy{Enabled: true, PlatformAccountLimit: 20, PlatformCooldown: 5 * time.Minute}
}

type recoveryAccountHistory struct {
	lastRotation time.Time
	burstStarted time.Time
	burstCount   int
	holdUntil    time.Time
}

type recoveryPlatformHistory struct {
	recent    map[string]time.Time
	holdUntil time.Time
}

// RecoveryStatus contains bounded, credential-free counters for this process.
// It is independent of request logging, so disabling logs cannot disable recovery.
type RecoveryStatus struct {
	Since            time.Time  `json:"since"`
	Enabled          bool       `json:"enabled"`
	Rotated          uint64     `json:"rotated"`
	Limited          uint64     `json:"limited"`
	NoAlternative    uint64     `json:"no_alternative"`
	Stale            uint64     `json:"stale"`
	LastStatus       string     `json:"last_status,omitempty"`
	LastAt           *time.Time `json:"last_at,omitempty"`
	CoolingPlatforms int        `json:"cooling_platforms"`
}

func (r *Router) currentRecoveryPolicy() RecoveryPolicy {
	policy := DefaultRecoveryPolicy()
	if r.recoveryPolicy != nil {
		policy = r.recoveryPolicy()
	}
	if policy.PlatformAccountLimit < 1 || policy.PlatformAccountLimit > 100 {
		policy.PlatformAccountLimit = 20
	}
	if policy.PlatformCooldown < time.Minute || policy.PlatformCooldown > time.Hour {
		policy.PlatformCooldown = 5 * time.Minute
	}
	return policy
}

// Called only under recoveryMu after checking CAS identity. Stale reports never
// consume the budget. Successful commits and reservations share the same lock.
func (r *Router) checkRecoveryLocked(platformID, account string, now time.Time) error {
	policy := r.currentRecoveryPolicy()
	if !policy.Enabled {
		return ErrRecoveryDisabled
	}
	if r.recoveryAccounts == nil {
		r.recoveryAccounts = make(map[model.LeaseKey]recoveryAccountHistory)
		r.recoveryPlatforms = make(map[string]*recoveryPlatformHistory)
	}
	for key, state := range r.recoveryAccounts {
		if !now.Before(state.holdUntil) && now.Sub(state.lastRotation) >= recoveryAccountBurstWindow {
			delete(r.recoveryAccounts, key)
		}
	}
	for id, state := range r.recoveryPlatforms {
		for identity, at := range state.recent {
			if now.Sub(at) >= recoveryPlatformWindow {
				delete(state.recent, identity)
			}
		}
		if len(state.recent) == 0 && !now.Before(state.holdUntil) {
			delete(r.recoveryPlatforms, id)
		}
	}
	key := model.LeaseKey{PlatformID: platformID, Account: account}
	if state, ok := r.recoveryAccounts[key]; ok {
		if now.Before(state.holdUntil) || now.Sub(state.lastRotation) < recoveryAccountInterval {
			return ErrRecoveryLimited
		}
	} else if len(r.recoveryAccounts) >= maxRecoveryAccounts {
		// Never evict a live safety bound to make room for a new identity.
		return ErrRecoveryLimited
	}
	state := r.recoveryPlatforms[platformID]
	if state == nil {
		if len(r.recoveryPlatforms) >= maxRecoveryPlatforms {
			return ErrRecoveryLimited
		}
		return nil
	}
	if now.Before(state.holdUntil) {
		return ErrRecoveryLimited
	}
	if _, seen := state.recent[account]; !seen && len(state.recent) >= policy.PlatformAccountLimit {
		state.holdUntil = now.Add(policy.PlatformCooldown)
		return ErrRecoveryLimited
	}
	return nil
}

func (r *Router) recordRecoveryLocked(platformID, account string, now time.Time) {
	key := model.LeaseKey{PlatformID: platformID, Account: account}
	state := r.recoveryAccounts[key]
	if state.burstStarted.IsZero() || now.Sub(state.burstStarted) >= recoveryAccountBurstWindow {
		state.burstStarted, state.burstCount = now, 0
	}
	state.lastRotation = now
	state.burstCount++
	if state.burstCount >= recoveryAccountBurstLimit {
		state.holdUntil = now.Add(recoveryAccountCooldown)
	}
	r.recoveryAccounts[key] = state
	platform := r.recoveryPlatforms[platformID]
	if platform == nil {
		platform = &recoveryPlatformHistory{recent: make(map[string]time.Time)}
		r.recoveryPlatforms[platformID] = platform
	}
	platform.recent[account] = now
}

func (r *Router) recordRecoveryResultLocked(err error, now time.Time) {
	status := "failed"
	switch {
	case err == nil:
		status = "rotated"
		r.recoveryStatus.Rotated++
	case errors.Is(err, ErrRecoveryLimited):
		status = "recovery_limited"
		r.recoveryStatus.Limited++
	case errors.Is(err, ErrRecoveryDisabled):
		status = "disabled"
	case errors.Is(err, ErrNoAvailableNodes):
		status = "no_alternative"
		r.recoveryStatus.NoAlternative++
	case errors.Is(err, ErrLeaseChanged):
		status = "stale_lease"
		r.recoveryStatus.Stale++
	}
	r.recoveryStatus.LastStatus, r.recoveryStatus.LastAt = status, &now
}

func (r *Router) RecoveryStatus() RecoveryStatus {
	r.recoveryMu.RLock()
	defer r.recoveryMu.RUnlock()
	status := r.recoveryStatus
	status.Enabled = r.currentRecoveryPolicy().Enabled
	now := time.Now()
	for _, platform := range r.recoveryPlatforms {
		if now.Before(platform.holdUntil) {
			status.CoolingPlatforms++
		}
	}
	return status
}
