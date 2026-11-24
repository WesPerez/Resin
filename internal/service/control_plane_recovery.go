package service

import (
	"errors"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/routing"
)

type AcquireRecoveryLeaseRequest struct {
	TargetHost          string              `json:"target_host"`
	PreferredCandidates []RecoveryCandidate `json:"preferred_candidates"`
}

type RecoveryLeaseResponse struct {
	RecoveryVersion int            `json:"recovery_version"`
	Status          string         `json:"status"`
	Lease           *LeaseResponse `json:"lease,omitempty"`
}

type ReportLeaseFailureRequest struct {
	TargetHost          string              `json:"target_host"`
	ExpectedNodeHash    string              `json:"expected_node_hash"`
	ExpectedCreatedAtNs string              `json:"expected_created_at_ns"`
	Reason              string              `json:"reason"`
	PreferredCandidates []RecoveryCandidate `json:"preferred_candidates"`
}

type RecoveryCandidate struct {
	NodeHash         string `json:"node_hash"`
	ExpectedTargetIP string `json:"expected_target_ip"`
}

func recoveryCandidates(values []RecoveryCandidate) ([]routing.PreferredCandidate, error) {
	result := make([]routing.PreferredCandidate, 0, min(len(values), 60))
	seen := make(map[node.Hash]bool)
	for _, value := range values {
		if len(result) == 60 {
			break
		}
		hash, err := node.ParseHex(value.NodeHash)
		if err != nil || hash.IsZero() || seen[hash] {
			continue
		}
		seen[hash] = true
		// A stale observed IP is advisory; the live pool owns the actual egress.
		result = append(result, routing.PreferredCandidate{NodeHash: hash})
	}
	return result, nil
}

func validateRecoveryIdentity(platformName, account, target string) error {
	if platformName == "" || len(platformName) > 128 || strings.TrimSpace(platformName) != platformName {
		return invalidArg("platform: invalid recovery platform")
	}
	if account == "" || len(account) > 128 || strings.ContainsAny(account, "/\\?#@~ \t\r\n") {
		return invalidArg("account: invalid recovery account")
	}
	if target == "" || len(target) > 253 || strings.ContainsAny(target, "/\\?#@ \t\r\n") {
		return invalidArg("target_host: must be a hostname or host:port")
	}
	if strings.Contains(target, ":") {
		host, port, err := net.SplitHostPort(target)
		p, portErr := strconv.Atoi(port)
		if err != nil || host == "" || portErr != nil || p < 1 || p > 65535 {
			return invalidArg("target_host: invalid host:port")
		}
	}
	return nil
}

// AcquireRecoveryLease creates or snapshots the ordinary account lease. Failure
// hints can request recovery, but cannot make a healthy retained route unavailable.
func (s *ControlPlaneService) AcquireRecoveryLease(platformName, account string, req AcquireRecoveryLeaseRequest) (*RecoveryLeaseResponse, error) {
	if err := validateRecoveryIdentity(platformName, account, req.TargetHost); err != nil {
		return nil, err
	}
	if _, err := recoveryCandidates(req.PreferredCandidates); err != nil {
		return nil, err
	}
	return s.acquireRecoveryLease(platformName, account, req, 2, true)
}

func (s *ControlPlaneService) acquireRecoveryLease(platformName, account string, req AcquireRecoveryLeaseRequest, retries int, allowInitial bool) (*RecoveryLeaseResponse, error) {
	route, err := s.Router.AcquireRecoveryRoute(platformName, account, req.TargetHost)
	if errors.Is(err, routing.ErrPlatformNotFound) {
		return nil, notFound("platform not found")
	}
	if errors.Is(err, routing.ErrLeaseChanged) && retries > 0 {
		return s.acquireRecoveryLease(platformName, account, req, retries-1, false)
	}
	if errors.Is(err, routing.ErrNoAvailableNodes) || errors.Is(err, routing.ErrLeaseChanged) ||
		errors.Is(err, routing.ErrRecoveryLimited) || errors.Is(err, routing.ErrRecoveryDisabled) {
		status := "no_alternative"
		if errors.Is(err, routing.ErrLeaseChanged) {
			status = "stale_lease"
		} else if errors.Is(err, routing.ErrRecoveryLimited) || errors.Is(err, routing.ErrRecoveryDisabled) {
			status = "recovery_limited"
		}
		response := &RecoveryLeaseResponse{RecoveryVersion: 1, Status: status}
		if plat, ok := s.Pool.GetPlatformByName(platformName); ok {
			if current := s.Router.ReadLease(model.LeaseKey{PlatformID: plat.ID, Account: account}); current != nil {
				value := leaseToResponse(*current, s.resolveLeaseNodeTagFromHex(current.NodeHash))
				response.Lease = &value
			}
		}
		return response, nil
	}
	if err != nil {
		return nil, internal("acquire recovery lease", err)
	}
	status := "available"
	if s.Router.TargetCooling(route.PlatformID, account, req.TargetHost, route.NodeHash, route.EgressIP) {
		candidates, _ := recoveryCandidates(req.PreferredCandidates) // Validated before any acquisition.
		_, _, err = s.Router.RecoverLease(route.PlatformID, account, route.NodeHash, route.LeaseCreatedAtNs, req.TargetHost,
			routing.RotateLeaseOptions{PreserveConnections: true, ApplyTargetCooldown: true, PreferredCandidates: candidates, CandidateHints: true})
		if errors.Is(err, routing.ErrNoAvailableNodes) {
			status = "available"
		} else if errors.Is(err, routing.ErrRecoveryLimited) || errors.Is(err, routing.ErrRecoveryDisabled) {
			status = "available"
		} else if errors.Is(err, routing.ErrLeaseChanged) && retries > 0 {
			return s.acquireRecoveryLease(platformName, account, req, retries-1, false)
		} else if errors.Is(err, routing.ErrLeaseChanged) {
			status = "stale_lease"
		} else if err != nil && !errors.Is(err, routing.ErrLeaseChanged) {
			return nil, internal("acquire cooling lease", err)
		}
	}
	lease, err := s.GetLease(route.PlatformID, account)
	if err != nil {
		return nil, err
	}
	return &RecoveryLeaseResponse{RecoveryVersion: 1, Status: status, Lease: lease}, nil
}

// failureClassForReason maps the accepted report reasons to the target-cooldown
// class applied to the observed node. Only explicit transport failures receive
// a shorter TTL. Legacy callers may report challenge pages as invalid_stream;
// that reason cannot distinguish a site response from broken content.
func failureClassForReason(reason string) (routing.FailureClass, bool) {
	switch reason {
	case "transport_error":
		return routing.FailureTransport, true
	case "empty_stream", "invalid_stream":
		return routing.FailureUnclassified, true
	default:
		return routing.FailureUnclassified, false
	}
}

// ReportLeaseFailure changes only the observed account generation, preserving
// active tunnels and excluding its previous exit from the replacement selection.
func (s *ControlPlaneService) ReportLeaseFailure(platformName, account string, req ReportLeaseFailureRequest) (*RecoveryLeaseResponse, error) {
	if err := validateRecoveryIdentity(platformName, account, req.TargetHost); err != nil {
		return nil, err
	}
	candidates, candidateErr := recoveryCandidates(req.PreferredCandidates)
	if candidateErr != nil {
		return nil, candidateErr
	}
	class, ok := failureClassForReason(req.Reason)
	if !ok {
		return nil, invalidArg("reason: unsupported recovery reason")
	}
	hash, err := node.ParseHex(req.ExpectedNodeHash)
	if err != nil || hash.IsZero() {
		return nil, invalidArg("expected_node_hash: invalid node hash")
	}
	created, err := strconv.ParseInt(req.ExpectedCreatedAtNs, 10, 64)
	if err != nil || created <= 0 {
		return nil, invalidArg("expected_created_at_ns: invalid generation")
	}
	plat, ok := s.Pool.GetPlatformByName(platformName)
	if !ok || plat == nil {
		return nil, notFound("platform not found")
	}
	lease, _, err := s.Router.RecoverLease(plat.ID, account, hash, created, req.TargetHost,
		routing.RotateLeaseOptions{
			ExcludeEgressIP: true, PreserveConnections: true, ApplyTargetCooldown: true,
			FailureCooldown: 10 * time.Minute, FailureClass: class, PreferredCandidates: candidates, CandidateHints: true,
		})
	status := "rotated"
	if errors.Is(err, routing.ErrLeaseChanged) {
		status = "stale_lease"
	} else if errors.Is(err, routing.ErrRecoveryLimited) || errors.Is(err, routing.ErrRecoveryDisabled) {
		status = "recovery_limited"
	} else if errors.Is(err, routing.ErrNoAvailableNodes) {
		status = "no_alternative"
	} else if err != nil {
		return nil, internal("report lease failure", err)
	}
	response := &RecoveryLeaseResponse{RecoveryVersion: 1, Status: status}
	if lease != nil {
		value := leaseToResponse(*lease, s.resolveLeaseNodeTagFromHex(lease.NodeHash))
		response.Lease = &value
	} else if current := s.Router.ReadLease(model.LeaseKey{PlatformID: plat.ID, Account: account}); current != nil {
		value := leaseToResponse(*current, s.resolveLeaseNodeTagFromHex(current.NodeHash))
		response.Lease = &value
	}
	slog.Info("proxy lease recovery", "platform", platformName, "account", account, "target_host", req.TargetHost,
		"reason", req.Reason, "observed_node", req.ExpectedNodeHash, "status", status)
	return response, nil
}
