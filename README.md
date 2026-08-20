# PSAT

Protocol Security Assessment Tool.

The repo fetches verified contract source, runs static analysis, resolves current control state, reconstructs authority policy when available, and exposes the results through a FastAPI + Vite demo site.

## Service Packages

Backend code is now grouped by domain:

- [`services/discovery/`](/home/gnome2/asu/capstone/PSAT/services/discovery)
- [`services/static/`](/home/gnome2/asu/capstone/PSAT/services/static)
- [`services/resolution/`](/home/gnome2/asu/capstone/PSAT/services/resolution)
- [`services/policy/`](/home/gnome2/asu/capstone/PSAT/services/policy)

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
