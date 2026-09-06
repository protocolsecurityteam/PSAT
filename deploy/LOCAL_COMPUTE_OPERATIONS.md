# Local production compute: activation and recovery

**NOT EXECUTED.** This runbook describes a future, separately authorized live
rollout. The implementation was verified using disposable local resources only.
The production Monitor tab is the submission and recovery interface. The
workstation runs no API, UI, submission command, indexer, or monitor daemon.

## Rollout order

1. Review the local implementation commits and the implementation report. Size
   the migration window: the additive migration backfills the populated jobs
   table and holds DDL locks before building the two indexes concurrently.
   A failed concurrent-index build needs normal Alembic/index recovery before
   proceeding. Validate backup/recovery procedures separately.
2. Apply the additive migrations through `d9e7a31c402f`. Retain both routing
   server defaults. Keep `PSAT_LOCAL_COMPUTE_ROUTING_ENABLED=0` during rollout.
3. Deploy the same full Git SHA to every production compute worker. Old workers
   must be drained/stopped before routing is enabled: old claim code cannot
   distinguish local work and old writers do not fence output.
4. On the four new cloud compute workers set `PSAT_LOCAL_COMPUTE_PREPARE=1`,
   `GIT_SHA` to the actual deployed full SHA, and a non-secret
   `PSAT_RPC_ROUTING_IDENTITY`. Supply complete object-storage configuration.
   Their normal startup publishes the versioned runtime contract and a unique
   storage sentinel to the configured production namespace. No extra process
   is added. All four stage attestations must match before capability readiness
   succeeds. A changed fingerprint requires all four attestations to refresh.
5. Independently verify the deployed process inventory and that every legacy
   worker is gone. Attestations record configured worker startup; they are not
   proof that no older machine remains alive. Only then enable routing in the
   API and cloud workers. Keep the same analysis/toolchain settings everywhere.
6. Prepare an isolated workstation checkout at that exact SHA with a clean Git
   status, the lockfile environment, and matching forge/anvil/solc, solc-select,
   crytic-compile, and Slither versions. Use dedicated, revocable credentials
   scoped to the application database and its artifact namespace. Verify TLS,
   pool capacity, RPC access, and storage permissions under separate live
   authorization.
7. Copy `deploy/local_compute.env.example` to the ignored `.env.compute`, owned
   by the operator with mode `600`. Fill it using authorized configuration
   management. Do not use a development `.env`. Set routing enabled only after
   step 5. Match every analysis flag, supported chain configuration, RPC identity,
   and storage endpoint/bucket/prefix. The contract stores flag digests for
   comparison; it cannot supply the original configuration values.
8. In the production **Monitor → New Analysis** form, select **Local workstation**
   and submit an address or company. Run `deploy/start_local_compute.sh` in the
   foreground on the workstation. It accepts no arguments and starts exactly
   static, resolution, policy, and effects workers. A singleton file lock and
   effects/Anvil port check reject conflicts. Logs are in
   `logs/local-compute-<worker>.log`.
9. Observe one controlled live run, with separate authorization: production
   discovery/selection, local descendants and dependency waits, cloud coverage,
   completion, enrollment, index catch-up, scoring, and monitoring reanalysis.
   Verify both effects-enabled and effects-disabled behavior and a controlled
   cancellation/recovery before wider use.

The launcher disables dotenv loading and never runs migrations. Preflight fails
on a dirty checkout, SHA/schema/analyzer/flag/chain/RPC/toolchain mismatch,
missing stage attestation, TLS omission for a remote database, incomplete
storage configuration, missing/corrupt sentinel, or failed unique storage probe.
Loopback preflight is permitted only for the disposable `psat_test` database.

## Operating and recovering a run

Cloud is the default. Only static/resolution/policy/effects claims honor the
selected target. Children inherit the immediate producing job's group and
current target. Existing queued/processing providers keep their own assignment;
the depender waits through the existing dependency edge. Completed sufficient
providers remain historical. Indexer reactivation and monitoring roots run in
cloud. The handoff to coverage and completion clear local affinity atomically.

Use Ctrl-C/SIGTERM on the foreground launcher to stop. Workers stop renewing
cancelled attempts and cancel their compiler subprocess groups. A cancelled
attempt cannot publish another database transaction; immutable uploads cannot
overwrite another attempt's object. Cleanup rolls back before conditionally
releasing the lease. If a process cannot unwind or a database release fails,
lease expiry and the production stale-job sweep remain the fallback. The
launcher holds its singleton lock while workers are still exiting. Investigate
hung processes; never bypass this by editing leases or starting a second copy.

In the production Monitor detail panel, use **Move local run to cloud** after
attempts have settled. The server locks and re-queries the entire compute group
and refuses while any row is processing or retains a lease. Retry after normal
expiry/recovery if the workstation is offline. The action preserves job IDs,
stages, retry schedules, artifacts, and dependencies. It does not force-steal
work. Pending monitoring generations remain durable while local work is parked
and enqueue one cloud follow-up when the deployment becomes idle.

Immutable publication leaves superseded objects available for historical/cache
references. Storage growth and orphan retention need normal operator monitoring;
this feature intentionally does not delete historical bodies during recovery.

## Operational rollback

**NOT EXECUTED.** Disable new local submissions, stop the workstation launcher,
and let every local attempt stop or expire. While the new target-aware API and
workers are still installed, move each remaining local group to cloud through
Monitor and verify there are no local rows left. Drain all new worker attempts
before reverting binaries. Retain the additive columns, server defaults,
indexes, monitoring markers, and receipts; do not run Alembic downgrade as an
operational rollback. Resume durable pending-trigger reconciliation on a
compatible version before relying on those markers again. Revoke the dedicated
workstation credentials when access is no longer needed.

Rolling-schema compatibility does not make overlapping old/new attempts safe.
The offline tests exercise the actual old binary's inserts against the upgraded
schema; they do not authorize old workers to overlap local routing.
