package service

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

type SetLeaseDisplayNameRequest struct {
	DisplayName *string `json:"display_name"`
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
	if req.DisplayName == nil {
		return nil, invalidArg("display_name: required (empty clears the name)")
	}
	name := strings.TrimSpace(*req.DisplayName)
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) > 128 || strings.IndexFunc(name, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) >= 0 {
		return nil, invalidArg("display_name: at most 128 characters without control characters")
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
	return lease, nil
}
