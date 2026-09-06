# Local production compute implementation report

## Delivery and boundaries

Branch: `feat/local-production-compute`.
BASE_SHA: `50f3bcb74f25f797e450e94b74a193ad82bb25df`.
Implementation commit: `fc89d1a8d80bcca360edcc74e275a6fe87d18aee`.
The documentation commit containing this report is the branch's final commit;
resolve its exact hash with `git log -1 --format=%H -- LOCAL_PRODUCTION_COMPUTE_IMPLEMENTATION_REPORT.md`.

Local implementation and offline verification only. **Activation and rollback
have NOT been executed. No production certification is claimed.** No push, PR,
remote Git fetch, deployment, live API/RPC/provider call, live database/storage
access, or production credential access was performed. Ordinary `.env` and
`.env.live` were not read, sourced, modified, or copied. Python execution used
`PYTHON_DOTENV_DISABLED=1`; test runs used an isolated environment and the
repository's offline socket guard. No application server was manually started.
Browser tests owned and terminated their loopback-only Vite server.

The pre-existing local Docker context was `default`, using
`unix:///var/run/docker.sock`. Tests used disposable `psat_test` / `psat_test_gwN`
databases on localhost:5433 and test buckets on localhost:9000. Migration tests
created and dropped only unique `psat_test_compute_<uuid>` databases. No
containers or unrelated resources were started, stopped, reset, or removed.
Unrelated tracked, untracked, and ignored workspace files were preserved.

## Implementation

- `db/models/jobs.py`, the two new migrations, and request/response schemas add
  typed target/group routing, cloud/UUID server defaults, a target constraint,
  claim/recovery indexes, and durable monitoring generations/receipts. Existing
  rows backfill to cloud with group=id. Concurrent indexes are built after the
  additive DDL/backfill transaction.
- `db/attempts.py`, `db/queue/jobs.py`, and `workers/base.py` bind immutable
  claim-time authority to each worker and helper session. Lifecycle transitions
  are conditional UPDATE/RETURNING on job ID, processing status, and lease.
  Every bound Session commit locks and validates that attempt, including
  normalized replacement transactions and separate-session publishers. Bound
  authority persists across rollback. The job dispatcher passes the original
  claim token rather than accepting a freshly loaded replacement token.
- `db/storage.py`, artifact storage, and contract materializations use unique
  attempt/publication keys. A losing artifact/source writer deletes only its
  own key. Existing keys remain readable, including cache references. Local
  mode rejects inline-storage fallback.
- Shared context-aware executors propagate authority into RPC/discovery fan-outs.
  Worker subprocess tracking includes forge, Anvil, solc, and compiler-library
  Popen calls. Lease loss and signals cancel the shared attempt and its subprocess
  groups. Shutdown stops heartbeats, cancels authority, rolls back, and only then
  conditionally releases the lease. Failed releases fall back to expiry. Direct
  completion paths prepare timing/errors/dependencies before clearing the lease.
- `db/compute.py` supplies canonical group advisory locks, row-locked terminal
  reactivation, parent-routing validation, and all-or-nothing group recovery.
  Child creation verifies the immediate parent's attempt. Proxy adoption and
  indexer reactivation recheck state/group membership under locks; indexer
  batches acquire all candidate group locks in sorted order. Orphan contract
  relinking occurs only after reactivation wins. An active standalone job or
  another proxy's winning adoption cannot substitute for this proxy's storage
  context: the caller creates a separate deployment child without retargeting
  that independent run. A Postgres race covers two competing proxy contexts.
- All job producers declare parent inheritance or cloud-root intent. Four
  expensive-stage claims filter by target. Discovery/selection and coverage
  ignore target; custom claims mint real leases and retain readiness, retry,
  and dependency gates. Coverage handoff and completion normalize to cloud.
- Monitoring scanner/poller loops reconcile durable coalesced deployment
  generations. The marker lock, active-work check, non-committing cloud-job
  insert, unique receipt, score invalidation, and exact-generation acknowledgment
  share one transaction. A parked local job cannot erase a monitoring trigger.
- `services/compute/`, the fixed launcher, and its example configuration implement
  the default-off rollout gate, four cloud-stage runtime attestations, exact
  code/schema/analyzer/config/chain/RPC/toolchain/namespace parity, namespace
  sentinel verification, and a unique storage write/read/delete probe. Startup
  checks the singleton lock, Anvil port, clean checkout, and remote DB TLS.
- The existing production Monitor form has an admin-only Cloud/Local selector;
  Cloud remains the default. Jobs display affinity/group, and the narrow
  move-to-cloud action refuses active leases without clearing pipeline state.
  The workstation has no new API, GUI, job CLI, or background production daemon.

The implementation commit contains 108 explicitly staged task files; its
complete file inventory is available with `git show --stat fc89d1a8`.

The executable publisher census lives in
`tests/local_compute/publisher_census.json`. It covers commit, job creation,
claim/lifecycle-related publication, reactivation, thread, and subprocess sites
across application packages and tracked scripts. New producers must explicitly
choose a parent or cloud root. Application-wide commit guards cover artifact,
source/cache, normalized controller/graph/effective-function/materialization,
dependency, timing/error, enrollment, and other attempt-originated writes;
system consumers remain outside an attempt context.

## Verification commands and results

Installed `.venv` and `site/node_modules` were used. No live test marker or
`PSAT_DIFF_COVER` was enabled. The latter can fetch remote Git refs and was
explicitly avoided. The runner itself is a pre-existing local helper, not part
of these commits.

Backend command prefix:

```bash
env -i PATH="$PATH" PYTHON_DOTENV_DISABLED=1 PSAT_XDIST_N=4 ./run_tests_fast.sh
```

Frontend command prefix, from `site/`:

```bash
env -i PATH="$PATH" NPM_CONFIG_USERCONFIG=/dev/null \
  NPM_CONFIG_GLOBALCONFIG=/tmp/psat-compute-empty-global.npmrc \
  NPM_CONFIG_OFFLINE=true
```

The global npm configuration path is an empty disposable file. Browser config
uses a dead loopback proxy for external browser requests, disables Vite dotenv
loading, removes remote font links, routes unmatched APIs only to loopback port
1, and forbids server reuse. Existing tests that omit API mocks therefore emit
local ECONNREFUSED warnings rather than contacting any application endpoint.

| Check | Result |
| --- | --- |
| Initial `tests/workers/test_base_worker.py` baseline | 23 passed |
| First full offline run during fixture migration | 206 failed, 8,310 passed, 4 xfailed, 3 errors |
| Second full offline run | 59 failed, 8,480 passed, 4 xfailed |
| Focused worker/static/discovery/crawler run | 2,418 passed; four outdated stubs fixed afterward |
| Next full offline run | 8 failed, 8,536 passed, 4 xfailed; seven unit stubs fixed, one unrelated workspace audit finding retained |
| Focused local-compute/policy/selection/enrollment run | 97 passed; remaining fan-out unit stub fixed |
| Final focused command below | 1,243 passed; no socket-guard external connection attempts |
| Final proxy/storage-context regression command below | 1,325 passed, 2 xfailed |
| Final full coverage command below | 8,555 passed, 4 xfailed; one unrelated ignored-script JSONB audit failure; 8 warnings |
| `ruff check db workers services routers schemas tests` | Passed |
| `ruff format --check db workers services routers schemas tests` | 936 files already formatted |
| Full `.venv/bin/pyright` | Two errors in pre-existing ignored `scripts/scrub_unwitnessed_events.py`; no task-code errors |
| Scoped pyright command below | 0 errors, 0 warnings |
| Explicit local Alembic upgrade/check below | Passed; no new upgrade operations detected |
| `bash -n deploy/start_local_compute.sh` | Passed |
| `shellcheck` | Unavailable; not installed, not claimed as passed |
| `npm test` | 68 files, 1,001 tests passed |
| `npm run build` | Passed; existing large-chunk advisory remains |
| `npm exec playwright test -- --config playwright.offline.config.js --grep-invert 'visual baseline'` | 24 passed |
| Full offline Playwright configuration | 25 passed, three screenshot mismatches |
| Same four screenshot tests at BASE_SHA with identical offline configuration | One passed, the same three mismatches |

Final focused invocation:

```bash
env -i PATH="$PATH" PYTHON_DOTENV_DISABLED=1 PSAT_XDIST_N=4 ./run_tests_fast.sh \
  tests/local_compute tests/workers tests/crawlers tests/discovery \
  tests/policy/test_policy_worker_integration.py \
  tests/resolution/test_deferred_resolution_reconcile.py tests/meta/test_log_level_contract.py
```

Final proxy/storage-context regression invocation:

```bash
env -i PATH="$PATH" PYTHON_DOTENV_DISABLED=1 PSAT_XDIST_N=4 ./run_tests_fast.sh \
  tests/local_compute tests/resolution/test_deployment_scoping.py \
  tests/chains/test_chain_dedup_sql.py tests/static
```

Final complete coverage invocation:

```bash
env -i PATH="$PATH" PYTHON_DOTENV_DISABLED=1 PSAT_COVERAGE=1 PSAT_XDIST_N=4 ./run_tests_fast.sh
```

Static/database checks:

```bash
env -i PATH="$PATH" PYTHON_DOTENV_DISABLED=1 .venv/bin/ruff check db workers services routers schemas tests
env -i PATH="$PATH" PYTHON_DOTENV_DISABLED=1 .venv/bin/ruff format --check db workers services routers schemas tests
env -i PATH="$PATH" PYTHON_DOTENV_DISABLED=1 .venv/bin/pyright
env -i PATH="$PATH" PYTHON_DOTENV_DISABLED=1 .venv/bin/pyright db workers services routers schemas tests scripts/reconcile_materializations.py
env -i PATH="$PATH" PYTHON_DOTENV_DISABLED=1 DATABASE_URL=postgresql://psat:psat@localhost:5433/psat_test .venv/bin/alembic upgrade head
env -i PATH="$PATH" PYTHON_DOTENV_DISABLED=1 DATABASE_URL=postgresql://psat:psat@localhost:5433/psat_test .venv/bin/alembic check
```

Overall coverage: 90.33% (54,200 / 60,003 executable lines). Changed executable application lines:
536 / 600 (89.33%; diff-cover displays 89%). The runner's coverage profile includes `api`, `workers`, `services`, `db`, and
`utils`; it does not separately measure `routers`/`schemas` or migrations, though
their tests and type checks ran. These are offline measurements, not assurance
of live latency, failure recovery time, or provider correctness.

Changed-line coverage used the installed tool directly, without the runner's
remote-fetch option:

```bash
env -i PATH="$PATH" PYTHON_DOTENV_DISABLED=1 .venv/bin/diff-cover coverage.xml \
  --compare-branch=50f3bcb74f25f797e450e94b74a193ad82bb25df --fail-under=70
```

Delivery logs remain in `/tmp/psat-compute-delivery-coverage.log`,
`/tmp/psat-compute-diff-coverage.log`, `/tmp/psat-compute-types-complete.log`,
`/tmp/psat-compute-delivery-ruff.log`, `/tmp/psat-compute-delivery-format.log`,
`/tmp/psat-compute-alembic.log`, `/tmp/psat-compute-delivery-vitest.log`,
`/tmp/psat-compute-build2.log`, and `/tmp/psat-compute-playwright-verified.log`.
They are disposable local logs, not required runtime assets.

An earlier coverage run was invalidated when later worker modules loaded after
source edits while BaseWorker had already been imported. Its missing-method
failures are not final results; the full run was repeated with source fixed.
Other intermediate failures exposed missing explicit leases in test doubles,
old queued-provider mutation expectations, old deterministic object-key
expectations, missing context in a dispatcher, and obsolete early-release
shutdown assertions. The tests now exercise the revised ownership contract.
No permissive lease fallback was restored to make tests pass.

Warnings: requests dependency-version compatibility, websockets legacy API
deprecation, the optional newer-pyright notification, and the Vite chunk-size
advisory. Existing expected failures remain reported as xfails, not passes.

## Compatibility and concurrency evidence

The migration test archives the actual BASE_SHA into a disposable directory,
executes its unmodified `create_job` and monitoring code against the old schema,
upgrades a populated local database, then executes old root/child/background/
repair-shaped inserts twice against the new schema (rolling overlap and
operational rollback shape). All twelve rows retain cloud defaults and valid
unique groups; legacy groups equal job IDs. Alembic schema drift also passes.
Operational rollback retains the additive schema.

Real Postgres tests cover target isolation, simultaneous SKIP LOCKED claims,
cached/stale lifecycle tokens, missing authority, parent-identity mismatch,
artifact/source/normalized/dependency/child/timing/error commit fencing,
destructive replacement rollback, and a commit lock that prevents concurrent
lease replacement. Group tests interleave claim/recovery and pause child
creation before the shared lock so a recovered group cannot gain an escaped
local child. Terminal reactivation rejects stale cached state, and existing
proxy/indexer tests exercise the shared helper's paths.

Real MinIO races pause the losing writer after PUT, replace its lease, publish
the winner, then resume the loser. Distinct immutable keys preserve the winner's
body and metadata while loser cleanup deletes only its own artifact/source.
Monitoring tests cover parked local work, repeated coalesced triggers,
concurrent reconcilers, rollback/replay, acknowledgment commit, and a trigger
arriving while acknowledgment is blocked.

Runtime tests cover matching attestations/sentinel/probe, mismatched flags/RPC/
SHA/schema/sentinel, missing worker attestation, partial storage, dirty checkout,
real subprocess cancellation, launcher singleton/no-arguments, exact four-process
supervision, and conflicting Anvil port. The lifecycle simulation uses real
queue, BaseWorker, Postgres and MinIO, with analyzer work stubbed; it exercises
both effects flag settings through cloud coverage and pending monitoring
reconciliation. Existing real company-selection and policy-enrollment tests
also run with local affinity. This is a composition of offline simulations and
stage tests, not a live company analysis or a real-provider compiler run.

## Known workspace and visual check limitations

The JSONB source audit reports `scripts/audit/diff.py:194` (`cv.value IS NULL`).
This is a pre-existing ignored workspace script (excluded by `.git/info/exclude`),
not a tracked change or a BASE_SHA file. The clean BASE_SHA archive has no such
finding. The full type check similarly reports optional `splitlines` and
`Result.rowcount` at lines 80/112 of ignored
`scripts/scrub_unwitnessed_events.py`. Both scripts predate this task and were
left untouched. A scoped type check covers application packages, tests, and the
tracked repair script changed here.

The existing home, company-overview, and pipeline-dashboard screenshot baselines
fail with remote fonts removed. The same three fail at the untouched base
revision under the same offline setup. The pipeline actual image is byte-for-byte
identical at base and implementation (SHA-256
`6f7106bf8b2f73b5325214c56adde7d64011a6819e18253dca1d8c57777ffff1`).
The expected images were not replaced to conceal the environmental mismatch.
Behavioral tests, including the Monitor selector and recovery component, pass.

## Remaining live-only checks

Follow [the operator runbook](deploy/LOCAL_COMPUTE_OPERATIONS.md), which is clearly
marked NOT EXECUTED. Before activation, authorize and verify the migration
window, all-old-worker drain, exact deployed image SHA and four attestations,
dedicated credential permissions/revocation, TLS/database pool behavior, actual
RPC and storage namespace access, one controlled company/dependency run, and
one graceful/abrupt workstation recovery. Production indexing, coverage,
enrollment, scoring and monitoring must continue without the workstation.

Local tests cannot establish those remote facts. Additional operational risks
are migration lock duration, workstation sleep/network partitions, compiler
shutdown latency, and growth of immutable superseded/orphan objects. No force
steal, live activation, deployment, or rollback was performed.
