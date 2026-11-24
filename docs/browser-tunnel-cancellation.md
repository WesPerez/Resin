# Browser tunnel cancellation and node health

Browser navigation can close several CONNECT tunnels before the upstream sends
its first byte. Watchdeck's October 8 investigation found bursts of zero-ingress
EOF results immediately before `LEASE_GUARD_FAILED` bursts. The passive failure
threshold and timing support unintended circuit breaking; historical logs do
not record the circuit transition, so they cannot establish every occurrence's
cause. Legacy route metadata does not pin the proxy connection.

The relay now observes which source ends first, before forwarding shutdown to
the other side. When the client ends first, no upstream byte was delivered, no
first-byte timeout fired, and no hard upstream read error occurred, the result
does not update passive node health or invalidate the lease. It does not report
success in place of failure: existing failure counts are preserved and request logs keep the
actual failed exchange, error category, and byte counts.

An orderly upstream-first EOF without response bytes also retains the failed
request without penalizing the node or replacing the account lease. A target
can refuse a speculative CONNECT or challenge connection while the same node
still serves the main site. Counting this as a node failure can switch every
later request from an already authenticated account to a different exit.
Hard upstream errors and first-byte timeouts still fail node health and recover
the lease.
Client half-close still propagates `CloseWrite` and waits for the upstream reply;
a successful response remains a successful health sample. Forward CONNECT and
SOCKS5 share the classification. Active probes, platform configuration, leases,
and the circuit breaker threshold are unchanged.
Existing successful SOCKS5 one-way/empty exchanges retain their success accounting.

Close order is conservative evidence, not proof of intent. A client that gives
up early on a truly silent upstream also supplies no conclusive health sample;
the failed request remains logged and independent probes continue to operate.
No broad rule treats all EOFs or all empty tunnels as healthy.

Remote CI covers a client closing an unused CONNECT, FIN/reset after sending
data, neutral upstream-first EOF, genuine first-byte timeout, and delayed replies after
client half-close, plus existing proxy/routing regressions and race tests.
Release uses the normal immutable candidate image and blue/green deployment.

## Legacy route usernames

The `~r1~` suffix is accepted for existing clients and stripped to the original
account. Its node, generation, IP and timestamp fields no longer constrain
routing or socket lifetime. Normal platform selection, dial retries, cancellation,
health feedback and half-close behavior apply to these connections as well.
