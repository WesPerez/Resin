# Application Response Recovery

TLS tunnel success does not prove that an application received a valid response.
An authorized client that parses the response can report repeated empty or broken
streams without changing shared node health or replaying a business request.

On a proxy-enabled endpoint, use `Authorization: Bearer <proxy-token>` with:

- `POST /proxy-api/v1/{platform}/leases/{account}/actions/acquire`
- `POST /proxy-api/v1/{platform}/leases/{account}/actions/report-failure`

This is proxy-token authentication, not admin authentication. Empty configured
tokens disable these actions. Tokens must not be placed in URLs. Like SOCKS
authentication, HTTP access to this endpoint is restricted to a trusted local
network; it does not add transport encryption.

Acquire accepts `{"target_host":"example.com:443"}` and returns
`recovery_version: 1`, a status and the account's ordinary lease. Report also
requires `expected_node_hash`, `expected_created_at_ns` (a decimal string, never
a floating-point number), and one of `empty_stream`, `invalid_stream`, or
`transport_error`. The application owns the failure threshold and must not
report client cancellation, quota exhaustion, or an unread response as failure.

Report uses node plus generation CAS. A matching report cools the observed node
and exit IP for ten minutes for this platform/account/target domain, then
selects an alternative outside all matching cooldowns. The lease is still
account-global: a replacement is used by subsequent requests from the account.
Other accounts, target cooldowns, and global node health are unaffected.

Statuses are `available` (acquire), `rotated` (report), `stale_lease`,
`no_alternative`, and `recovery_limited`. A recovery limit or disabled automatic
recovery preserves the current lease and active tunnels; clients must continue
observing the returned lease, use bounded per-lease backoff, and must not treat
this status as a control-plane outage or a successful rotation.
No alternative preserves the old lease and active tunnels,
but retains the cooldown so a later acquire can use a newly available node.
Cooldown memory is bounded to 4096 entries and is not persisted across restart.
Existing tunnels are preserved on recovery; clients must retire their idle
connections and key new connection pools by the returned lease generation.
All same-IP node replacements also advance the generation, including A-B-A.

Roll out Resin first, verify the capability using an isolated synthetic account,
then enable the client integration. Older Resin returns no capability; the
client must retain its existing proxy path and avoid guessing a generation.


## Optional bounded preferred pool (2026-11-16)

Both proxy-token `acquire` and `report-failure` accept `preferred_candidates`:

```json
{"target_host":"example.com:443","preferred_candidates":[{"node_hash":"11111111111111111111111111111111","expected_target_ip":"198.51.100.1"}]}
```

`report-failure` still requires its original expected node/generation and reason.
The list has at most 60 unique node hashes and unscoped unicast expected IPs.
All entries are validated before acquisition, cooling or recovery. Missing/null
keeps the existing client contract. An explicit `[]` means no replacement is
allowed; it must never be silently dropped by a client after an HTTP error.

For an existing cooling lease, acquire uses the same list as report-failure.
Selection checks each entry in order inside one recovery lock/CAS and respects
platform membership, health, current IP, old exit exclusions and target cooling.
Exhaustion returns `no_alternative`, retaining the original lease and active
connections even when an unrelated routable node exists. Successful replacement
consumes one shared rotation budget; stale/limited responses retain their old
meaning. Initial creation of a missing lease still follows the normal platform
allocation contract; this option constrains replacement of existing leases.

Clients first authenticate a read-only `GET /proxy-api/v1/capabilities` on the
same proxy endpoint. The response explicitly declares
`{"recovery_version":1,"preferred_candidates_version":1}`; the existing recovery
version alone does not imply support for candidate lists. This endpoint requires
the proxy token, works without management access and does not allocate a lease.

Metapi sends the field only after that declaration. With an older or unknown
service, existing accounts read their fixed lease through the same registered
management service, and failure reports do not rotate. Only a new precredential
workflow that has confirmed a missing lease and saved its acquisition intent may
request a single legacy initial allocation; lost outcomes require reconciliation.
An unsupported POST is never retried after stripping the candidate field.

The candidate artifact must also preserve the production schema and native
maintenance/handoff contract before deployment. The current running source
`40f5204951cddad4cfb34d9a628c84be46094516` is not an ancestor of this candidate;
CI success alone does not authorize replacing that production version. The
capability gate permits a safe Metapi rollout while candidate recovery remains
disabled on the older Resin. These candidates are application hints, not proof
that business HTTP requests are safe to replay. Request journals remain authoritative.
