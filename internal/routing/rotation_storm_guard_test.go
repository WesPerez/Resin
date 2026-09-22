package routing

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/model"
)

func TestRecoveryGuard_DistinctAccountsAndPlatformIsolation(t *testing.T) {
	r := &Router{recoveryPolicy: func() RecoveryPolicy {
		return RecoveryPolicy{Enabled: true, PlatformAccountLimit: 2, PlatformCooldown: 5 * time.Minute}
	}}
	now := time.Unix(1000000, 0)
	for _, account := range []string{"one", "two"} {
		if err := r.checkRecoveryLocked("p", account, now); err != nil {
			t.Fatal(err)
		}
		r.recordRecoveryLocked("p", account, now)
	}
	// A second generation of the same account is not a third distinct account.
	if err := r.checkRecoveryLocked("p", "one", now.Add(31*time.Second)); err != nil {
		t.Fatal(err)
	}
	r.recordRecoveryLocked("p", "one", now.Add(31*time.Second))
	if err := r.checkRecoveryLocked("p", "three", now.Add(31*time.Second)); !errors.Is(err, ErrRecoveryLimited) {
		t.Fatalf("third account must trip platform guard: %v", err)
	}
	if err := r.checkRecoveryLocked("p", "two", now.Add(2*time.Minute)); !errors.Is(err, ErrRecoveryLimited) {
		t.Fatalf("hold must outlive the counting window: %v", err)
	}
	if err := r.checkRecoveryLocked("other", "three", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := r.checkRecoveryLocked("p", "three", now.Add(6*time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryGuard_AccountIntervalAndBurst(t *testing.T) {
	r := &Router{}
	now := time.Unix(1000000, 0)
	for i := range 3 {
		at := now.Add(time.Duration(i) * 30 * time.Second)
		if err := r.checkRecoveryLocked("p", "one", at); err != nil {
			t.Fatal(err)
		}
		r.recordRecoveryLocked("p", "one", at)
		if err := r.checkRecoveryLocked("p", "one", at.Add(time.Second)); !errors.Is(err, ErrRecoveryLimited) {
			t.Fatalf("rapid repeat was allowed: %v", err)
		}
	}
	if err := r.checkRecoveryLocked("p", "one", now.Add(20*time.Minute)); !errors.Is(err, ErrRecoveryLimited) {
		t.Fatalf("burst cooldown was discarded with old window: %v", err)
	}
	if err := r.checkRecoveryLocked("p", "one", now.Add(61*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := r.checkRecoveryLocked("p", "two", now.Add(20*time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryGuard_BoundedStateDoesNotEvictLiveProtection(t *testing.T) {
	r := &Router{}
	now := time.Unix(1000000, 0)
	if err := r.checkRecoveryLocked("p", "new", now); err != nil {
		t.Fatal(err)
	}
	for i := range maxRecoveryAccounts {
		r.recoveryAccounts[model.LeaseKey{PlatformID: "p", Account: fmt.Sprint(i)}] = recoveryAccountHistory{lastRotation: now, holdUntil: now.Add(time.Hour)}
	}
	if err := r.checkRecoveryLocked("p", "new", now); !errors.Is(err, ErrRecoveryLimited) {
		t.Fatal(err)
	}
	if len(r.recoveryAccounts) != maxRecoveryAccounts {
		t.Fatal("evicted a live guard")
	}
	if err := r.checkRecoveryLocked("p", "new", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(r.recoveryAccounts) != 0 {
		t.Fatal("expired guards were not reclaimed")
	}
	for i := range maxRecoveryPlatforms {
		r.recoveryPlatforms[fmt.Sprint(i)] = &recoveryPlatformHistory{holdUntil: now.Add(2 * time.Hour)}
	}
	if err := r.checkRecoveryLocked("new-platform", "new", now.Add(time.Hour)); !errors.Is(err, ErrRecoveryLimited) {
		t.Fatal(err)
	}
	if len(r.recoveryPlatforms) != maxRecoveryPlatforms {
		t.Fatal("evicted a live platform guard")
	}
}

func TestRecoveryGuard_DisabledAndFailedSelectionDoNotConsumeBudget(t *testing.T) {
	enabled := false
	r := &Router{recoveryPolicy: func() RecoveryPolicy { p := DefaultRecoveryPolicy(); p.Enabled = enabled; return p }}
	now := time.Now()
	if err := r.checkRecoveryLocked("p", "one", now); !errors.Is(err, ErrRecoveryDisabled) {
		t.Fatal(err)
	}
	enabled = true
	for range 100 {
		if err := r.checkRecoveryLocked("p", "one", now); err != nil {
			t.Fatal(err)
		}
		r.recordRecoveryResultLocked(ErrNoAvailableNodes, now)
	}
	if len(r.recoveryAccounts) != 0 || len(r.recoveryPlatforms) != 0 {
		t.Fatal("unsuccessful selection consumed a rotation")
	}
	if got := r.RecoveryStatus(); got.NoAlternative != 100 || got.Rotated != 0 {
		t.Fatalf("status: %+v", got)
	}
}
