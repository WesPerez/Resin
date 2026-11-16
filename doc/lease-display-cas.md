# Automatic display names

Applications may name their own stable account keys without reallocating a
lease. A GET lease response advertises `display_name_cas_version: 1` when the
server supports the following optional PATCH to the existing `/display-name`
endpoint:

```json
{
  "display_name": "hub-16",
  "if_empty": true,
  "expected_node_hash": "0123456789abcdef0123456789abcdef",
  "expected_egress_ip": "192.0.2.1",
  "expected_created_at_ns": "1791943875282397170"
}
```

The platform and account come from the URL. All expected fields are mandatory;
nanoseconds are a decimal string. The router compares the exact generation
while serializing with replacement/deletion of that account's lease, then the
state repository inserts the name only if it is absent. Existing names are
never replaced by automatic synchronization. The same name is idempotent;
a different existing name or changed lease returns 409. Missing platforms and
leases never cause allocation. Old servers reject the new fields, and clients
must require the advertised capability before writing.

Display names continue to describe a stable application key across lease
expiry, renewal and node rotation. Manual PATCH without `if_empty` retains
the existing overwrite/clear semantics. Applications must not reuse a stable
key for a different account or infer ownership from an ambiguous legacy prefix.
Automatic naming changes no routing key, node, IP, timestamps, connection,
credential, platform policy or lease event.

Lock order is recovery read lock, lease map key, then a nonblocking attempt to
lock the state repository. The single-row SQLite statement uses the request
context with a 250 ms cancellation budget. This is not a hard operating-system
I/O bound. Recovery or repository contention returns 503. After any timeout or
lost response, read the label and current generation again; do not infer that
the write rolled back, and never fall back to an unconditional PATCH.

This candidate does not change the production deployment algorithm. The old
Resin's dirty-cache handoff remains a separate prerequisite for deployment.
