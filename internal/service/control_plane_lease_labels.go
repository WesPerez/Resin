package service

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/routing"
	"github.com/Resinat/Resin/internal/state"
)

type SetLeaseDisplayNameRequest struct {
	DisplayName         *string `json:"display_name"`
	IfEmpty             bool    `json:"if_empty,omitempty"`
	ExpectedNodeHash    string  `json:"expected_node_hash,omitempty"`
	ExpectedEgressIP    string  `json:"expected_egress_ip,omitempty"`
	ExpectedCreatedAtNs string  `json:"expected_created_at_ns,omitempty"`
}

func (s *ControlPlaneService) leaseDisplayNames(platformID string) (map[string]string, error) {
	if s.Engine == nil {
		return nil, nil
	}
	names, err := s.Engine.LeaseDisplayNames(platformID)
	if err != nil {
		return nil, internal("read lease display names", err)
	}
	return names, nil
}

// SetLeaseDisplayName leaves identity, node, expiry, connections and allocation
// untouched. It cannot inherit, rotate, recreate or overwrite another lease.
func (s *ControlPlaneService) SetLeaseDisplayName(platformID, account string, req SetLeaseDisplayNameRequest) (*LeaseResponse, error) {
	return s.SetLeaseDisplayNameContext(context.Background(), platformID, account, req)
}

func (s *ControlPlaneService) SetLeaseDisplayNameContext(ctx context.Context, platformID, account string, req SetLeaseDisplayNameRequest) (*LeaseResponse, error) {
	if req.DisplayName == nil {
		return nil, invalidArg("display_name: required (empty clears the name)")
	}
	name := strings.TrimSpace(*req.DisplayName)
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) > 128 || strings.IndexFunc(name, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) >= 0 {
		return nil, invalidArg("display_name: at most 128 characters without control characters")
	}
	if req.IfEmpty {
		return s.setLeaseDisplayNameIfEmpty(ctx, platformID, account, name, req)
	}
	if req.ExpectedNodeHash != "" || req.ExpectedEgressIP != "" || req.ExpectedCreatedAtNs != "" {
		return nil, invalidArg("expected lease fields require if_empty")
	}
	lease, err := s.GetLease(platformID, account)
	if err != nil {
		return nil, err
	}
	if s.Engine == nil {
		return nil, internal("lease display name storage unavailable", nil)
	}
	if err := s.Engine.SetLeaseDisplayName(platformID, account, name); err != nil {
		return nil, internal("save lease display name", err)
	}
	lease.DisplayName = name
	lease.DisplayNameUnavailable = false
	return lease, nil
}

func (s *ControlPlaneService) setLeaseDisplayNameIfEmpty(ctx context.Context, platformID, account, name string, req SetLeaseDisplayNameRequest) (*LeaseResponse, error) {
	hash, hashErr := node.ParseHex(req.ExpectedNodeHash)
	ip, ipErr := netip.ParseAddr(req.ExpectedEgressIP)
	created, createdErr := strconv.ParseInt(req.ExpectedCreatedAtNs, 10, 64)
	if name == "" || hashErr != nil || hash.IsZero() || ipErr != nil || createdErr != nil || created <= 0 || strconv.FormatInt(created, 10) != req.ExpectedCreatedAtNs {
		return nil, invalidArg("if_empty requires a name and exact node hash, egress IP and created_at_ns")
	}
	if s.Pool == nil || s.Router == nil || s.Engine == nil {
		return nil, internal("lease display name storage unavailable", nil)
	}
	if _, ok := s.Pool.GetPlatform(platformID); !ok {
		return nil, notFound("platform not found")
	}
	// This is a cancellation budget, not a hard wall-clock guarantee for
	// operating-system/SQLite I/O. A lost response must be read back, not
	// interpreted as proof of rollback. Retrying if_empty is idempotent.
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	var stored string
	lease, matched, err := s.Router.WithLeaseGeneration(platformID, account, routing.LeaseGeneration{
		NodeHash: hash, EgressIP: ip, CreatedAtNs: created,
	}, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		var err error
		stored, err = s.Engine.SetLeaseDisplayNameIfEmpty(ctx, platformID, account, name)
		return err
	})
	if errors.Is(err, routing.ErrLeaseMetadataBusy) || errors.Is(err, state.ErrLeaseDisplayNameBusy) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return nil, &ServiceError{Code: "UNAVAILABLE", Message: "lease display name busy; read back before retrying", Err: err}
	}
	if err != nil {
		return nil, internal("save lease display name", err)
	}
	if !matched {
		return nil, conflict("lease_changed")
	}
	if stored != name {
		return nil, conflict("display_name_conflict")
	}
	response := leaseToResponse(lease, s.resolveLeaseNodeTagFromHex(lease.NodeHash))
	response.DisplayName = stored
	return &response, nil
}
