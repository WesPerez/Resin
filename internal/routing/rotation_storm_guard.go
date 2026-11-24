package routing

import (
	"errors"
	"time"
)

var (
	ErrRecoveryLimited  = errors.New("legacy recovery limit status")
	ErrRecoveryDisabled = errors.New("automatic lease recovery is disabled")
)

// These legacy configuration fields are accepted for old clients. Recovery
// is controlled only by Enabled; account/platform time quotas are retired.
type RecoveryPolicy struct {
	Enabled              bool
	PlatformAccountLimit int
	PlatformCooldown     time.Duration
}

func DefaultRecoveryPolicy() RecoveryPolicy { return RecoveryPolicy{Enabled: true} }

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
	if r.recoveryPolicy != nil {
		return r.recoveryPolicy()
	}
	return DefaultRecoveryPolicy()
}
func (r *Router) checkRecoveryLocked(platformID, account string, now time.Time) error {
	if !r.currentRecoveryPolicy().Enabled {
		return ErrRecoveryDisabled
	}
	return nil
}
func (r *Router) recordRecoveryLocked(platformID, account string, now time.Time) {}

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
	return status
}
