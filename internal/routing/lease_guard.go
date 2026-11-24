package routing

import "strings"

// Legacy clients append a route snapshot. Accept it as an account alias;
// metadata must not pin or expire normal proxy-pool routing.
const LeaseGuardMarker = "~r1~"
const LeaseGuardVersion = 1 // legacy username format remains supported

func CanonicalAccount(account string) string {
	base, _, legacy := strings.Cut(account, LeaseGuardMarker)
	if legacy && base != "" {
		return base
	}
	return account
}
