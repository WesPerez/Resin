# Shutdown and opt-in maintenance barriers (candidate, not a cutover protocol)

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
- The candidate additionally implements an opt-in cold maintenance entry below.
  NAT behavior, offline snapshot/deployment orchestration, schema, lease identity,
  allocation policy and the running production process remain unchanged.
- The currently running `40f5204` has none of these new barriers. Deploying this
  candidate through the old online-snapshot path cannot prove a lossless first
  upgrade. Do not deploy until a separately reviewed bootstrap/cold-handoff
  protocol and seven-field lease verification exist.
- Component feedback and endpoint waits report context expiry and retain pending
  source ownership. App shutdown returns a retained-ownership failure within its deadline;
  run parks behind closed admission with DBs open. It never closes a DB
  underneath a live handler.
  The SQL flush API is not context-cancellable, and background-source Stop calls
  remain synchronous inside one owned worker. The owner wait is bounded,
  but the process intentionally remains parked on failure until explicit owner
  recovery/force-stop. This is not a successful drain or hard process-exit bound.
- A timeout failure is preserved even if an owned source later finishes. It must
  not issue a snapshot acknowledgement or be presented as a successful drain.

Hosted tests cover final SQL error/retained dirty work, seven-field roundtrip,
late dirty marks, periodic/final serialization, discarded-slot exclusion,
asynchronous feedback registration/stop races, timer recovery joins, retired
endpoint joins, and post-hijack handler lifetime. No production requests are
used to manufacture these tests.

## Opt-in maintenance-to-stop candidate (not deployed; exact final hosted required)

`RESIN_MAINTENANCE_ENABLED=1` enables authenticated GET/POST
`/api/v1/system/maintenance` using the nonempty admin Bearer token. A POST
fsyncs a private `stateDir/maintenance-handoff.json` requested record before
closing shared HTTP/SOCKS admission. The POST's 202 means **requested only**.
Existing admitted handlers keep their complete lifetime (including post-CAS
memory effects, hijacks and entered timer recovery); the endpoint manager joins
them with preserve=true **without Discard**. All background sources are then
stopped/joined. Unlike legacy drain-only, this is a maintenance pause that ends
in process stop, not an old slot serving tunnels concurrently with a new writer.

The previously bare `go Scheduler.UpdateSubscription` is now registered under
scheduler lifecycle ownership before dispatch. Stop rejects new registrations
and joins accepted updates. Strong state has **no asynchronous persistence
queue**: all fourteen mutation entrypoints hold StateRepo.mu through their SQL
statement/transaction commit. A terminal seal joins/rejects these writes after
handler side effects finish. Weak seal retains a late dirty mark for recovery
but latches an error; the late source cannot earn a handoff certificate.

Maintenance then performs the error-returning final cache transaction, checks
both write seals, FULL WAL checkpoints (busy/partial is failure), and compares
the complete sorted router/cache lease sets over all seven fields (missing,
extra, duplicate and 1ns drift reject). After DB Close succeeds, both database
files/directories are fsynced, nonempty WAL rejects, and an immutable read-only
SQLite quick_check plus file SHA256/size binds the closed two-DB group. Only a still-valid, within-deadline result writes
`complete`. requestlog/metrics close failures are logged separately and do not
prevent the authority flush; lease/config/flush/checkpoint/close/marker failures
prevent success. The receipt retains a transfer nonce, process instance, source
SHA and exact lease set digest/count. It does not bind Docker identity itself;
any deployer must independently bind exact container/image/StartedAt and source
mounts before using it.

**A retained marker of any shape/phase blocks run() before DB opens, migrations
or consistency repair.** Unknown/symlink/corrupt records fail closed. No API or
automatic startup removes the marker. Even `complete` needs explicit owner
recovery or a separately validated deployment transaction. On timeout the app returns retained-ownership failure and
parks with open DB handles; it does not continue on a Background safety join.
Partial HTTP headers/keepalives have 15s/30s timeouts; active tunnels still need
the owner deadline and no-live-writer close rule. systemd SIGKILL cannot turn requested/draining/failed
into complete. Persisted SQLite data remains recoverable; unflushed weak state
can be lost under force kill, so zero-loss under forced interruption is **not**
claimed. A checkpoint/receipt is not a stopped two-DB snapshot.

## Still-required orchestrator and first installation

The actual deployer is
`/root/server-scheduled-tasks/tasks/resin-bluegreen-deploy/bluegreen.py`:
its snapshot requires Running, deploy snapshots before preparing journal, and
reconcile/recover_pending can restore NAT unconditionally. It must not consume
this cold receipt through its unchanged online path. A separately reviewed
phase journal must precede admission/NAT changes; maintenance NAT ownership must
survive every reconcile/reentry. Failed/unknown phases retain maintenance, not
start an already sealed source. Offline snapshots must be sealed as one config
(state.db)/cache.db recovery group, with file digests and the seven-field set
checked before/after candidate bootstrap (including consistency repair).

The first source is old 40f5204, which has neither this entry nor the final
barrier. Socket=0, stable export twice and successful candidate tests do not
prove that old handlers/timers/async feedback have stopped or dirty is durable.
First bootstrap still needs separately evidenced external isolation/handler
join and recoverable authoritative state, or an explicitly authorized bounded
cold-loss/data-repair protocol. No such authorization or proof exists here.
Production Resin switching remains prohibited. No protection hash, global
circuit policy, historical lease or normal node is changed by this candidate.

## Final close/certificate decisions (candidate correction)

The actual run() close decision now rejects retained-owner/deadline/final-flush
failures before evaluating any barrier or closer, including ordinary shutdown.
It parks with dirty state and DBs owned; a private failed restart fence is
attempted. Barrier reads use TryLock and context short-circuit. The timeout
marker writer is joined before finalization. Feedback/scheduler registration,
strong SQL and weak dirty gates cover the complete durability acknowledgement
in that lock order; refused late calls synchronously invalidate the marker.
Failed invalidation retains ownership rather than returning success. These
latches supplement, never replace, the proven source joins.

Closed DB confirmation uses context-aware quick_check and a second hash/stat,
rejects unsafe/nonempty WAL, rollback journal and shared-memory sidecars. File
sync/hash/driver calls can still be stalled by the kernel; the deadline does
not guarantee a hard exit. A forced kill retains a failed/unknown marker and
committed SQLite recovery, not the unflushed weak memory. Hosted subprocess
fixtures kill a failed parked owner and verify startup rejection/read-only
SQLite integrity; they are not a production systemd interruption proof.

A versioned shared vector is validated using actual Go model.Lease encoding
and consumed byte-for-byte by the bluegreen Python fixtures. Invalid UTF-8
is rejected rather than silently normalized. No candidate bootstrap/cutover
has been authorized for the old 40f source.

Normal flush failure deliberately uses the same presence-only restart fence
with no transfer nonce; this record is never consumable as maintenance complete.
A finalizer tracks entry counters/epochs before lock acquisition as well as
source seals: an entry overlapping durability acknowledgement rejects success.
A call after the final linearization boundary invalidates before that refused
call returns; this does not promise that arbitrary future untracked goroutines
can be joined. Actual source lifecycle joins remain a prerequisite. Consumers
must bind a clean stopped exit (not just file phase) and exact Docker instance.
