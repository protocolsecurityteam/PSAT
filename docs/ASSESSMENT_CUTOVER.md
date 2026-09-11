# Assessment cutover

Status: maintenance procedure for the temporal cutover. It is not authorization
to run the production migration. The [temporal implementation plan](ASSESSMENT_IMPLEMENTATION_PLAN.md)
defines the remaining release gates.

This is a single architectural and product cutover, not a rolling compatibility
period. Assessment is the canonical row ledger. Static inputs are evidence;
policy, principal, function, and graph rows are derived indexes.

Principal-history behavior is retained through temporal evidence and claims.
Reports that lack block hashes remain explicitly `reported`; hash-anchored
grant/revoke events can establish ordered bounded intervals.

The public wire has no schema-version tag. The company-discovery live
integration requires a fresh preview inventory: a warm inventory can have no
eligible new candidates and therefore cannot exercise discovery-to-analysis
traversal. Resetting remains an explicit operator action through the scoped
`/reset-db` PR comment command; ordinary reruns retain the preview database.

## Existing production database

Migration `f6a1c2d3e4b5` expands the database with temporal tables. The importer
archives each complete legacy source body, records its digest and source locator,
publishes and reconstructs it, and removes the mutable legacy row only after
equality succeeds. Migration `a8c2d4e6f901` removes the old physical columns. It refuses an ordinary
upgrade of an existing database unless the maintenance cutover is explicitly
acknowledged. The preceding expansion migration does not make dropping columns
safe while old processes run. Fresh databases can migrate normally.

Use the **Main deploy** workflow's manual dispatch on `main`, supplying
`ASSESSMENT CUTOVER` and a verified database backup/snapshot reference. This
dispatch shares the ordinary deployment's concurrency group and runs CI first.
It builds and pushes the target image before downtime, validates the machine
inventory, then removes every old stateless web, worker, browser, and monitor
machine. Removing them prevents autostart from reviving old code. Persistent
volumes and unexpected process groups cause a refusal before any removal.

Only after confirming that no old machines remain does the temporary release
command run expansion, `python -m services.assessment.migrate`, and finally
`alembic -x assessment_cutover=stopped upgrade head`. It restores the previous process counts
and runs the standard health, SHA, and read-only smoke checks. The ordinary
push deployment never supplies the acknowledgement.

Migration `e27a490bc381` preserves the progress of existing restaking event
cursors under their distinct enrollment basis. Predicate enrollment also
promotes an existing tracking-plan cursor without resetting its scan history.

This causes downtime and discards old machines' ephemeral disks. Durable data
must be in PostgreSQL/object storage, and the backup must be recoverable before
dispatch. Other clients of the same database must also be stopped; the workflow
can enforce the process inventory of the `psat` app only.

There is no automatic old-image rollback after this dispatch: the old image
requires deleted columns. If migration or smoke checks fail, keep old processes
off and fix forward, or restore the database backup before deploying old code.
The contraction's downgrade deliberately refuses to fabricate deleted data.

## Restored-copy rehearsal

Before scheduling maintenance, rehearse against a separately named empty
scratch database. The command refuses a non-empty target, keeps database
credentials out of subprocess arguments, archives a custom-format dump and its
SHA-256 digest, and reconciles every legacy analytical artifact with an import
manifest before contraction:

```bash
uv run --no-sync python -m deploy.assessment_rehearsal \
  --source-url "$SOURCE_DATABASE_URL" \
  --scratch-url "$SCRATCH_DATABASE_URL" \
  --backup-file /secure/path/assessment-rehearsal.dump \
  --confirm "ISOLATED SCRATCH DATABASE"
```

Success requires expansion, exact projection comparison, zero remaining legacy
Assessment/principal-history rows, one source manifest per imported row,
contraction to `a8c2d4e6f901`, and a clean `alembic check`. The rehearsal does
not authorize the production cutover.

Private PR previews use the same loss-preserving order through
`deploy.preview.assessment_release`. The workflow stops only that preview app's
old stateless machines before the release command. A preview already containing
the contraction uses an ordinary `alembic upgrade head`; it is not reset on
reruns.

## Review scope

The cache timing assertion is retained alongside cache reuse and source checks.
The forced-cold run must finish after the cached run, and Assessment cache
restore must be at least 25% faster than the fresh static-facts work it replaces.
Fresh dependency discovery is excluded from that ratio because deployed
dependencies can change. Company-discovery-to-guarded-descendant and
capability/principal consistency checks are retained through Assessment. The
new membership-strength labels are deferred until standing membership witnesses
are refreshed consistently.
