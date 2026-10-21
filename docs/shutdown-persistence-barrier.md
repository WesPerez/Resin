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

## Candidate-copy preflight (subsequent candidate; not activation)

`resin preflight --snapshot-dir DIR --output-dir NEW_DIR --state-sha256 HEX
--cache-sha256 HEX --lease-sha256 HEX --lease-count N` accepts a separately
proven stopped snapshot. It compares both immutable source files against fixed
hashes, reads the complete seven-field set, and creates a unique 0700 copy with
0600 DBs. Source files never pass to PersistenceBootstrap. The real migrations,
consistency repair, default prelude, topology restore and Router.RestoreLeases
run on the copy without network, outbounds, listeners, observability, cleaners
or scheduler. Platform rebuild's local workers are joined. Every restored lease
is marked and flushed through the real final writer, checkpointed, closed and
file-bound; complete router/cache/source lease sets must agree. All user schema
objects and typed rows in state.db must remain logically identical, including
labels/config/rules, or preflight refuses (it does not silently accept defaults
or repair). Latency trimming can affect the candidate weak cache; this is not
zero-change validation of all weak node telemetry.

The receipt includes the sorted seven fields, source/candidate file identities,
strong-state digest and explicit `outbound_validated=false` and
`authority_activated=false`. Store stdout privately; account names may be
sensitive. CLI errors do not print settings, source data or credentials. Failed
stdout publication invalidates its candidate marker and returns nonzero; even
`validated` never authorizes startup. A marker in the candidate state directory
blocks normal run before migration regardless of phase. Partial copies remain
for owner recovery; the tool neither removes markers nor deletes source/copy.

When using the packaged image, bypass the normal Docker entrypoint explicitly:
its recursive chown is a normal runtime prelude, not a read-only verifier.
Mount snapshot read-only and a separate candidate workspace read-write; use
`--network none`, read-only root and a private namespace, never the live slot's
volumes. The future orchestrator must fix image digest/SHA, Docker instance,
source config and mounts, journal before container create/start, and consume a
successful clean exit plus private receipt, hashes and marker. These Docker
steps are not yet an implemented production command. CLI context checks bound
normal work, not uninterruptible kernel/driver I/O; a force-killed preflight is
failed/unknown and its generation cannot be activated.

A receipt proves candidate persistence/topology survival on its private copy;
it cannot prove that old 40f produced a causally final snapshot. No source-stop,
traffic routing, authority-commit or rollback permission follows from it.
