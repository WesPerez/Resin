package service

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/routing"
)

// ------------------------------------------------------------------
// Leases
// ------------------------------------------------------------------

// LeaseResponse is the API response for a lease.
type LeaseResponse struct {
	PlatformID   string `json:"platform_id"`
	Account      string `json:"account"`
	NodeHash     string `json:"node_hash"`
	NodeTag      string `json:"node_tag"`
	EgressIP     string `json:"egress_ip"`
	Expiry       string `json:"expiry"`
	LastAccessed string `json:"last_accessed"`
	CreatedAtNs  string `json:"created_at_ns"`
}

func leaseToResponse(lease model.Lease, nodeTag string) LeaseResponse {
	return LeaseResponse{
		PlatformID:   lease.PlatformID,
		Account:      lease.Account,
		NodeHash:     lease.NodeHash,
		NodeTag:      nodeTag,
		EgressIP:     lease.EgressIP,
		Expiry:       time.Unix(0, lease.ExpiryNs).UTC().Format(time.RFC3339Nano),
		LastAccessed: time.Unix(0, lease.LastAccessedNs).UTC().Format(time.RFC3339Nano),
		CreatedAtNs:  strconv.FormatInt(lease.CreatedAtNs, 10),
	}
}

func (s *ControlPlaneService) resolveLeaseNodeTag(hash node.Hash) string {
	if s == nil || s.Pool == nil {
		return ""
	}
	return s.Pool.ResolveNodeDisplayTag(hash)
}

func (s *ControlPlaneService) resolveLeaseNodeTagFromHex(hashHex string) string {
	hash, err := node.ParseHex(hashHex)
	if err != nil {
		return ""
	}
	return s.resolveLeaseNodeTag(hash)
}

// ListLeases returns all leases for a platform.
func (s *ControlPlaneService) ListLeases(platformID string) ([]LeaseResponse, error) {
	if _, ok := s.Pool.GetPlatform(platformID); !ok {
		return nil, notFound("platform not found")
	}
	var result []LeaseResponse
	s.Router.RangeLeases(platformID, func(account string, lease routing.Lease) bool {
		result = append(result, leaseToResponse(model.Lease{
			PlatformID:     platformID,
			Account:        account,
			NodeHash:       lease.NodeHash.Hex(),
			EgressIP:       lease.EgressIP.String(),
			ExpiryNs:       lease.ExpiryNs,
			LastAccessedNs: lease.LastAccessedNs,
			CreatedAtNs:    lease.CreatedAtNs,
		}, s.resolveLeaseNodeTag(lease.NodeHash)))
		return true
	})
	if result == nil {
		result = []LeaseResponse{}
	}
	return result, nil
}

type RotateLeaseRequest struct {
	ExpectedNodeHash    string `json:"expected_node_hash"`
	ExpectedCreatedAtNs string `json:"expected_created_at_ns"`
	TargetHost          string `json:"target_host"`
	ExcludeEgressIP     bool   `json:"exclude_egress_ip"`
	PreserveConnections bool   `json:"preserve_connections"`
	PreferredNodeHash   string `json:"preferred_node_hash,omitempty"`
	ExpectedTargetIP    string `json:"expected_target_ip,omitempty"`
}

type RotateLeaseResponse struct {
	Status            string         `json:"status"`
	Lease             *LeaseResponse `json:"lease,omitempty"`
	ClosedConnections int            `json:"closed_connections"`
}

func (s *ControlPlaneService) RotateLease(platformID, account string, req RotateLeaseRequest) (*RotateLeaseResponse, error) {
	if _, ok := s.Pool.GetPlatform(platformID); !ok {
		return nil, notFound("platform not found")
	}

	hash, err := node.ParseHex(req.ExpectedNodeHash)
	if err != nil || hash.IsZero() {
		return nil, invalidArg("expected_node_hash: invalid node hash")
	}
	created, err := strconv.ParseInt(req.ExpectedCreatedAtNs, 10, 64)
	if err != nil || created <= 0 {
		return nil, invalidArg("expected_created_at_ns: must be a positive nanosecond timestamp string")
	}
	target := strings.TrimSpace(req.TargetHost)
	if target == "" || len(target) > 253 || strings.ContainsAny(target, "/\\?#@ \t\r\n") {
		return nil, invalidArg("target_host: must be a hostname or host:port")
	}
	if strings.Contains(target, ":") {
		if _, _, err := net.SplitHostPort(target); err != nil {
			return nil, invalidArg("target_host: invalid host:port")
		}
	}
	options := routing.RotateLeaseOptions{
		ExcludeEgressIP: req.ExcludeEgressIP, PreserveConnections: req.PreserveConnections,
	}
	if req.PreferredNodeHash != "" || req.ExpectedTargetIP != "" {
		preferred, err := node.ParseHex(req.PreferredNodeHash)
		if err != nil || preferred.IsZero() {
			return nil, invalidArg("preferred_node_hash: must name a node when expected_target_ip is supplied")
		}
		ip, err := netip.ParseAddr(req.ExpectedTargetIP)
		if err != nil || ip.Zone() != "" || !ip.IsGlobalUnicast() {
			return nil, invalidArg("expected_target_ip: must be an unscoped unicast IP when preferred_node_hash is supplied")
		}
		options.PreferredNode = preferred
		options.ExpectedTargetIP = ip.Unmap()
	}
	lease, closed, err := s.Router.RotateLease(platformID, account, hash, created, target, options)
	if errors.Is(err, routing.ErrLeaseChanged) {
		if s.Router.ReadLease(model.LeaseKey{PlatformID: platformID, Account: account}) == nil {
			return nil, notFound("lease not found")
		}
		return &RotateLeaseResponse{Status: "stale_lease"}, nil
	}
	if errors.Is(err, routing.ErrNoAvailableNodes) {
		return &RotateLeaseResponse{Status: "no_alternative"}, nil
	}
	if errors.Is(err, routing.ErrPlatformNotFound) {
		return nil, notFound("platform not found")
	}
	if err != nil {
		return nil, internal("rotate lease", err)
	}
	response := leaseToResponse(*lease, s.resolveLeaseNodeTagFromHex(lease.NodeHash))
	return &RotateLeaseResponse{Status: "rotated", Lease: &response, ClosedConnections: closed}, nil
}

// GetLease returns a single lease.
func (s *ControlPlaneService) GetLease(platformID, account string) (*LeaseResponse, error) {
	if _, ok := s.Pool.GetPlatform(platformID); !ok {
		return nil, notFound("platform not found")
	}
	ml := s.Router.ReadLease(model.LeaseKey{PlatformID: platformID, Account: account})
	if ml == nil {
		return nil, notFound("lease not found")
	}
	resp := leaseToResponse(*ml, s.resolveLeaseNodeTagFromHex(ml.NodeHash))
	return &resp, nil
}

// InheritLeaseByPlatformName copies a valid parent lease onto newAccount.
func (s *ControlPlaneService) InheritLeaseByPlatformName(platformName, parentAccount, newAccount string) error {
	platformName = strings.TrimSpace(platformName)
	if platformName == "" {
		return invalidArg("platform: must be non-empty")
	}
	parentAccount = strings.TrimSpace(parentAccount)
	if parentAccount == "" {
		return invalidArg("parent_account: must be non-empty")
	}
	newAccount = strings.TrimSpace(newAccount)
	if newAccount == "" {
		return invalidArg("new_account: must be non-empty")
	}
	if parentAccount == newAccount {
		return invalidArg("new_account: must differ from parent_account")
	}

	plat, ok := s.Pool.GetPlatformByName(platformName)
	if !ok || plat == nil {
		return notFound("platform not found")
	}

	parentLease := s.Router.ReadLease(model.LeaseKey{
		PlatformID: plat.ID,
		Account:    parentAccount,
	})
	nowNs := time.Now().UnixNano()
	if parentLease == nil || parentLease.ExpiryNs < nowNs {
		return notFound("parent lease not found")
	}

	next := *parentLease
	next.Account = newAccount
	if err := s.Router.UpsertLease(next); err != nil {
		return internal("inherit lease", err)
	}

	return nil
}

// DeleteLease removes a single lease.
func (s *ControlPlaneService) DeleteLease(platformID, account string) error {
	if _, ok := s.Pool.GetPlatform(platformID); !ok {
		return notFound("platform not found")
	}
	if !s.Router.DeleteLease(platformID, account) {
		return notFound("lease not found")
	}
	return nil
}

// DeleteAllLeases removes all leases for a platform.
func (s *ControlPlaneService) DeleteAllLeases(platformID string) error {
	if _, ok := s.Pool.GetPlatform(platformID); !ok {
		return notFound("platform not found")
	}
	s.Router.DeleteAllLeases(platformID)
	return nil
}

// IPLoadEntry is the API response for IP load stats.
type IPLoadEntry struct {
	EgressIP   string `json:"egress_ip"`
	LeaseCount int64  `json:"lease_count"`
}

// GetIPLoad returns IP load stats for a platform.
func (s *ControlPlaneService) GetIPLoad(platformID string) ([]IPLoadEntry, error) {
	if _, ok := s.Pool.GetPlatform(platformID); !ok {
		return nil, notFound("platform not found")
	}
	snapshot := s.Router.SnapshotIPLoad(platformID)
	result := make([]IPLoadEntry, 0, len(snapshot))
	for ip, count := range snapshot {
		result = append(result, IPLoadEntry{
			EgressIP:   ip.String(),
			LeaseCount: count,
		})
	}
	return result, nil
}
