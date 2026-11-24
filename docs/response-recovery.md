# Application Response Recovery

Authenticated proxy clients can use `POST /proxy-api/v1/{platform}/leases/{account}/actions/acquire`
and `report-failure`. Authentication, one JSON value and the configured body size
limit apply. Additional preference metadata is ignored for forward compatibility.

Acquire uses the ordinary platform/account pool. Failure reports compare the
observed node and decimal-string `expected_created_at_ns` before changing a lease,
so a late response cannot rotate another request's replacement. Existing sockets
can complete on the route they dialed. Resin does not replay business requests.

`preferred_candidates` and the administrator's single preferred node are hints,
not an allowlist. Invalid, duplicate or unavailable hints are skipped, stale IP
observations do not constrain the live egress, and exhausted hints fall back to
normal healthy platform selection. Empty candidate lists do not deny recovery.

Statuses remain `available`, `rotated`, `stale_lease`, `no_alternative` and
`recovery_limited` for existing clients. Automatic recovery can be disabled, but
there are no per-account or per-platform time quotas. Target failure observations
do not make a healthy retained lease unavailable when no alternative exists.

Legacy `~r1~` proxy usernames resolve to their base account. Node, IP, generation
and deadline metadata no longer gate proxy routing. `lease_guard_version: 1`
continues to advertise acceptance of this legacy username format; it does not
promise an immutable exit. Callers own any business-specific IP requirement.
