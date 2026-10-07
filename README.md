# PSAT

Protocol Security Assessment Tool.

The repo fetches verified contract source, runs static analysis, resolves current control state, reconstructs authority policy when available, and exposes the results through a FastAPI + Vite demo site.

## Service Packages

Backend code is now grouped by domain:

- [`services/discovery/`](services/discovery/)
- [`services/static/`](services/static/)
- [`services/resolution/`](services/resolution/)
- [`services/policy/`](services/policy/)

The codebase now lives under the split service packages in `services/`.

## Main Outputs

Pipeline results are written to Postgres (contract, summary, permission,
graph, and upgrade tables) with artifact bodies stored in object storage
(MinIO locally, Fly Tigris in prod). Scaffolded source trees are staged
under `contracts/<name>/` while a job is running so that Slither has
files on disk, but the DB is the authoritative store.

## Local Development

### Python setup

1. Install dependencies:
   ```bash
   uv sync
   ```
2. Create env file:
   ```bash
   cp .env.example .env
   ```
3. Set the keys you need in `.env`.

Common env vars:

- `ETHERSCAN_API_KEY`
- `ETH_RPC` — Ethereum JSON-RPC endpoint
- `ENVIO_API_TOKEN` — for HyperSync policy backfill
- `DATABASE_URL` — PostgreSQL connection string
- `TAVILY_API_KEY`
- `OPEN_ROUTER_KEY`

### Backend

Run the FastAPI demo server:

```bash
uv run python serve.py
```

Backend/API URL:

```text
http://127.0.0.1:8000
```

### Frontend

The site lives in `site/`.

Install frontend deps once:

```bash
cd site
npm install
```

Run the Vite dev server:

```bash
cd site
npm run dev -- --host 127.0.0.1 --port 5173
```

Frontend URL:

```text
http://127.0.0.1:5173
```

The Vite app proxies `/api` to the FastAPI backend.

For the full local pipeline, including workers, audit extraction, and score inputs,
configure `.env` for the local Postgres and MinIO services and run:

```bash
bash deploy/start_local.sh
```

This launcher enables `PSAT_EFFECTS_STAGE` by default and verifies an object-storage
write/read/delete cycle before starting workers. Object storage is required for
audit extraction; the API's inline Postgres artifact fallback does not cover that
stage. Keep the frontend running separately as described above.

## URL Routing

The site supports deep links by address and tab.

Examples:

- `http://127.0.0.1:5173/address/0x08c6F91e2B681FaF5e17227F2a44C307b3C1364C/summary`
- `http://127.0.0.1:5173/address/0x08c6F91e2B681FaF5e17227F2a44C307b3C1364C/graph`
- `http://127.0.0.1:5173/runs/BoringVault_08c6F91e/graph`

Tabs:

- `summary`
- `permissions`
- `principals`
- `graph`
- `raw`

## Running The Pipeline

Submit an address via the API (`POST /api/analyze` with `{"address": "0x..."}`)
or a protocol via `POST /api/protocols/{name}/discover`. The API enqueues
a job in Postgres; the worker pool (see `deploy/start_workers.sh`) advances it
through the stages defined in `db.models.JobStage`:

1. `discovery` — fetch verified source, scaffold Foundry project, seed dependency graph
2. `static` — Slither + `contract_analysis.json` structured analysis
3. `resolution` — `control_tracking_plan.json`, `control_snapshot.json`, `resolved_control_graph.json`
4. `policy` — HyperSync policy backfill, `effective_permissions.json`, `principal_labels.json`
5. `coverage` — link contracts to their audit reports
6. `done`

The unified protocol monitor (`workers.protocol_monitor`) runs separately
and drives live upgrade / event / TVL tracking.

Static analysis preserves the verified compiler version and standard JSON settings,
including `viaIR`, optimizer details, and the EVM target. Solidity versions are cached
per version through `solc-select` (existing `~/.svm` binaries are also accepted);
Vyper versions use isolated `uv` tool environments. The first use of an uncached
compiler needs network access. `PSAT_COMPILATION_TIMEOUT_S` defaults to 300 seconds.
Vyper 0.4 remains unsupported and produces an explicit analysis error.

Provenance analysis bounds expanding origin sets and recursive member paths. When
it exceeds a budget or cannot converge, that value becomes unknown; it must not
establish a precise authority or destination. Discovery can analyze code-proven
nominations within `analyze_limit` to gather membership evidence, while keeping
them separate from confirmed protocol members.

RPC requests now use a shared Postgres admission gate (`ops_kv`). Workers connected
to the same database share `PSAT_RPC_RPS=5`, `PSAT_RPC_BURST=10`, and
`PSAT_RPC_HOURLY_LIMIT=20000`. Each stage has `PSAT_RPC_STAGE_LIMIT=1000`; jobs in
one discovery cascade share `PSAT_RPC_RUN_LIMIT=20000`. These are conservative
request-count defaults, not a promise about a provider's compute-unit allowance.
Separate databases or other clients need an additional account-wide eRPC limit.

Company discovery retains grouped deployments and official registry entries across
reruns, keeping chain identities and source links. Selection resumes bounded
membership-probe passes automatically before ranking; follow-up selection passes
keep the original analysis and RPC budgets. Provider cooldowns and hourly limits
schedule retries. Exhausting a stage or total run allowance remains an explicit
failure, rather than silently increasing the allowance. A new company run retries
failed analysis and refreshes completed results from older analyzer versions.
The requested `analyze_limit` still bounds selection; missing source or unproven
membership/audit coverage remains unknown rather than being manually admitted.
Check the actual provider allowance before increasing these settings.

Batch members and retries each consume allowance. HTTP or wrapped JSON-RPC rate
limits open a shared cooldown (at least 30 seconds, increasing to 5 minutes and
honoring longer `Retry-After` values). Database/admission failure stops requests.
Stage/run budget exhaustion does not automatically retry. Anvil fork reads pass
through a bounded, read-only loopback gateway and consume the same limits.
`PSAT_RPC_LIMITER_MODE=off` is an explicit test/standalone escape hatch; do not use
it for a protocol run. Logs include `rpc_calls_sent` and stage-specific user agents.

Audit reports stay visible before deployment matching succeeds. Public GitHub
source reads are anonymous first, with credentials used only when needed; fetch
failures remain distinct from a missing commit or a source mismatch.

Single-provider quotes above `PSAT_MAX_UNCORROBORATED_UNIT_PRICE_USD=1000000`
or `PSAT_MAX_UNCORROBORATED_HOLDING_USD=1000000000000000` are quarantined as
unpriced, including previously stored quotes read by scoring. These configurable
limits do not declare an asset worthless or establish a fair price. Special
addresses are not treated as ordinary signing accounts or EOA balance subjects.

## Docker

The monorepo can be run with separate `api` and `site` containers.

```bash
docker compose up --build api site
```


## Tests

Run the non-live suite:

```bash
uv run pytest -k "not live"
```
