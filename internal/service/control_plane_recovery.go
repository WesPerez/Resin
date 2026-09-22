package service

import (
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/routing"
)

type AcquireRecoveryLeaseRequest struct {
	TargetHost string `json:"target_host"`
}

type RecoveryLeaseResponse struct {
	RecoveryVersion int            `json:"recovery_version"`
	Status          string         `json:"status"`
	Lease           *LeaseResponse `json:"lease,omitempty"`
}

type ReportLeaseFailureRequest struct {
	TargetHost          string `json:"target_host"`
	ExpectedNodeHash    string `json:"expected_node_hash"`
	ExpectedCreatedAtNs string `json:"expected_created_at_ns"`
	Reason              string `json:"reason"`
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

// AcquireRecoveryLease creates or snapshots the ordinary account lease. Cooling
// nodes are changed through CAS rotation, whose no-alternative path is non-destructive.
func (s *ControlPlaneService) AcquireRecoveryLease(platformName, account string, req AcquireRecoveryLeaseRequest) (*RecoveryLeaseResponse, error) {
	if err := validateRecoveryIdentity(platformName, account, req.TargetHost); err != nil {
		return nil, err
	}
	return s.acquireRecoveryLease(platformName, account, req, 2)
}

func (s *ControlPlaneService) acquireRecoveryLease(platformName, account string, req AcquireRecoveryLeaseRequest, retries int) (*RecoveryLeaseResponse, error) {
	route, err := s.Router.AcquireRecoveryRoute(platformName, account, req.TargetHost)
	if errors.Is(err, routing.ErrPlatformNotFound) {
		return nil, notFound("platform not found")
	}
	if errors.Is(err, routing.ErrNoAvailableNodes) {
		response := &RecoveryLeaseResponse{RecoveryVersion: 1, Status: "no_alternative"}
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
		_, _, err = s.Router.RotateLease(route.PlatformID, account, route.NodeHash, route.LeaseCreatedAtNs, req.TargetHost,
			routing.RotateLeaseOptions{PreserveConnections: true, ApplyTargetCooldown: true})
		if errors.Is(err, routing.ErrNoAvailableNodes) {
			status = "no_alternative"
		} else if errors.Is(err, routing.ErrLeaseChanged) && retries > 0 {
			return s.acquireRecoveryLease(platformName, account, req, retries-1)
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
	hash, _ := node.ParseHex(lease.NodeHash)
	ip, _ := netip.ParseAddr(lease.EgressIP)
	if status == "available" && s.Router.TargetCooling(route.PlatformID, account, req.TargetHost, hash, ip) {
		if retries > 0 {
			return s.acquireRecoveryLease(platformName, account, req, retries-1)
		}
		status = "stale_lease"
	}
	return &RecoveryLeaseResponse{RecoveryVersion: 1, Status: status, Lease: lease}, nil
}

// ReportLeaseFailure changes only the observed account generation, preserving
// active tunnels and excluding its previous exit from the replacement selection.
func (s *ControlPlaneService) ReportLeaseFailure(platformName, account string, req ReportLeaseFailureRequest) (*RecoveryLeaseResponse, error) {
	if err := validateRecoveryIdentity(platformName, account, req.TargetHost); err != nil {
		return nil, err
	}
	switch req.Reason {
	case "empty_stream", "invalid_stream", "transport_error":
	default:
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
	lease, _, err := s.Router.RotateLease(plat.ID, account, hash, created, req.TargetHost,
		routing.RotateLeaseOptions{ExcludeEgressIP: true, PreserveConnections: true, ApplyTargetCooldown: true, FailureCooldown: 10 * time.Minute})
	status := "rotated"
	if errors.Is(err, routing.ErrLeaseChanged) {
		status = "stale_lease"
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
