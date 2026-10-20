# Normal shutdown persistence barrier (candidate, not a cutover protocol)

The normal (non-preserve) shutdown returns failures from endpoint drain,
retired endpoint workers, proxy feedback and the final cache transaction to
`run()`. Database close errors are also returned. A failed drain is **not** a
successful snapshot boundary: the failure is returned even if the remaining
sources eventually quiesce and their final cache transaction succeeds.

Ordering: stop listeners and join handlers (including post-hijack work and
already retired endpoints); stop lease/ephemeral cleaners and subscription
scheduler; stop GeoIP updates (retaining its reader); seal and join proxy
health/latency feedback; stop probes; close the GeoIP reader;
stop observability and outbounds; stop the periodic cache writer and perform
an error-returning final transaction. Timeout-triggered tunnel lease recovery
is joined before the owning tunnel handler returns. Feedback registration
occurs before asynchronous dispatch, never inside an untracked outer goroutine.

`HealthFeedbackBarrier.StopAndWait(ctx)` rejects and reports late feedback. It
does not stop handlers itself: its owner must first prove source quiescence.
`CacheFlushWorker.StopAndFlush()` likewise requires quiescent mutation sources;
it serializes with the periodic writer and Discard, reports SQL failure and
nonzero remaining dirty work, and never overrides a discarded slot. These
are component barriers, not a cross-process or global router write fence.

## Unchanged and explicitly unsupported

- `RESIN_SHUTDOWN_PRESERVE_CONNECTIONS=1` still means the old blue/green
  retirement contract: Discard before drain. No final authoritative flush is
  certified in that mode. The existing drain receipt is informational only.
- No maintenance API, NAT behavior, offline snapshot, schema, lease identity,
  allocation policy, running production process or deployment script changes.
- The currently running `40f5204` has none of these new barriers. Deploying this
  candidate through the old online-snapshot path cannot prove a lossless first
  upgrade. Do not deploy until a separately reviewed bootstrap/cold-handoff
  protocol and seven-field lease verification exist.
- Component feedback and endpoint waits report context expiry and retain pending
  source ownership. App shutdown then safety-joins those sources before closing
  their sinks and databases; it never closes a DB underneath a live handler.
  The SQL flush API is not context-cancellable, and background-source Stop calls
  remain synchronous. Consequently app shutdown is **not a hard wall-clock
  bound**: an uncooperative source may keep the process alive until an external
  owner chooses a force exit (which is not a successful drain).
- A timeout failure is preserved even if a later safety join succeeds. It must
  not issue a snapshot acknowledgement or be presented as a successful drain.

Hosted tests cover final SQL error/retained dirty work, seven-field roundtrip,
late dirty marks, periodic/final serialization, discarded-slot exclusion,
asynchronous feedback registration/stop races, timer recovery joins, retired
endpoint joins, and post-hijack handler lifetime. No production requests are
used to manufacture these tests.
