"""Clean re-analysis of the REAL etherfi contract set (the surgical fix).

Wipes all protocol-1 analysis-derived data + every etherfi job + the keccak
materialization cache, then requeues ONLY the genuinely-analyzable contracts —
EXCLUDING ``upgrade_history`` anchor rows — under one shared ``root_job_id`` so
the proxy->impl cascade dedupe collapses (each contract runs exactly once).

WHY THE EXCLUSION (the bug this fixes)
--------------------------------------
Rows whose ``discovery_sources`` contains ``'upgrade_history'`` are historical
*implementation versions* backfilled only to anchor audit-coverage matching —
not live contracts. The production pipeline
(``routers/jobs.py::analyze_remaining``) deliberately excludes them from
analysis, which is exactly why cold PR environments are clean. A plain
``WHERE protocol_id=1`` requeue does NOT exclude them, so those ~82 anchors
(15 of them named ``LiquidityPool``) get analysis jobs and render as a pile of
bogus duplicate nodes on the surface. They must stay as bare rows
(``job_id`` NULL, no derived data) — the intended anchor state.

For etherfi today: 217 protocol-1 rows = 82 ``upgrade_history`` anchors + 135
real contracts. This requeues the 135.

KEEPS: contracts (addresses + inventory provenance), audit_reports (+ LLM
extraction), protocols, monitoring config, and the discovery/Tavily/Exa
caches. DELETES: per-contract derived analysis data, all etherfi jobs
(artifacts/source_files cascade), contract_materializations. Recoverable —
only derived data is removed; it regenerates on the requeue.

Usage::

    uv run python -m scripts.etherfi_clean_requeue              # dry-run: counts only
    uv run python -m scripts.etherfi_clean_requeue --execute --yes
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("etherfi_clean_requeue")

PROTOCOL_ID = 1
COMPANY = "etherfi"
EXPECTED_DB_HOST = "ep-snowy-sound-any45i43"  # Neon prod; safety guard
SNAP_DIR = Path(__file__).resolve().parent / "baseline_snapshots"

_P1 = "(SELECT id FROM contracts WHERE protocol_id=:pid)"
_P1_ADDRS = "(SELECT lower(address) FROM contracts WHERE protocol_id=:pid)"

# Anchor rows are audit-coverage-only *superseded* historical impls; the
# production pipeline excludes them from analysis. The requeue MUST match or
# they render as bogus duplicate surface nodes. A proxy's CURRENT live impl
# also appears in its Upgraded events but carries 'current_implementation' and
# must NOT be excluded — it's where the real functions live. Mirrors
# services/discovery/ranking.not_superseded_impl_clause.
ANCHOR_EXCL = (
    "(discovery_sources IS NULL "
    "OR NOT ('upgrade_history' = ANY(discovery_sources)) "
    "OR 'current_implementation' = ANY(discovery_sources))"
)

# (table, WHERE) for the wipe, children-before-parents. All scoped to the KEPT
# protocol-1 contract rows (these FK to contracts, which we keep, so no cascade
# fires — they must be deleted explicitly). This also clears the derived rows
# for any anchors a prior buggy requeue wrongly analyzed.
WIPE: list[tuple[str, str]] = [
    ("function_principals", f"function_id IN (SELECT ef.id FROM effective_functions ef WHERE ef.contract_id IN {_P1})"),
    ("effective_functions", f"contract_id IN {_P1}"),
    ("controller_values", f"contract_id IN {_P1}"),
    ("control_graph_edges", f"contract_id IN {_P1}"),
    ("control_graph_nodes", f"contract_id IN {_P1}"),
    ("principal_labels", f"contract_id IN {_P1}"),
    ("contract_dependencies", f"contract_id IN {_P1}"),
    ("role_definitions", f"contract_id IN {_P1}"),
    ("upgrade_events", f"contract_id IN {_P1}"),
    ("audit_contract_coverage", f"contract_id IN {_P1}"),
    ("contract_summaries", f"contract_id IN {_P1}"),
    ("contract_materializations", f"lower(address) IN {_P1_ADDRS}"),
    # jobs last — cascades artifacts/source_files/job_dependencies/dapp_interactions,
    # and SET NULLs contracts.job_id (→ requeue-ready).
    ("jobs", f"protocol_id=:pid OR company=:company OR lower(address) IN {_P1_ADDRS}"),
]

# Idempotent: keep one contract row per address (prefer explicit 'ethereum',
# else lowest id). No-op once the known same-address dups are gone.
DEDUP_SQL = """
DELETE FROM contracts WHERE id IN (
  SELECT id FROM (
    SELECT id, row_number() OVER (
      PARTITION BY lower(address) ORDER BY (chain='ethereum') DESC NULLS LAST, id
    ) rn FROM contracts WHERE protocol_id=:pid
  ) t WHERE rn > 1
)
"""


def _load_env_live() -> None:
    env_live = Path(__file__).resolve().parent.parent / ".env.live"
    if not env_live.exists():
        return
    for raw in env_live.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip("'").strip('"')
        if key and key != "DATABASE_URL" and key not in os.environ:  # never trust .env.live's stale DATABASE_URL
            os.environ[key] = val


def derive_prod_db(args: argparse.Namespace) -> str:
    if args.prod_db:
        return args.prod_db.strip()
    if os.getenv("PSAT_PROD_DB"):
        return os.environ["PSAT_PROD_DB"].strip()
    _load_env_live()
    token = os.getenv("FLY_PROD_API_TOKEN") or os.getenv("FLY_API_TOKEN")
    if not token:
        raise SystemExit("No FLY_PROD_API_TOKEN/FLY_API_TOKEN in .env.live and no --prod-db given.")
    logger.info("Deriving prod DATABASE_URL via `fly ssh console -a psat` …")
    out = subprocess.run(
        ["fly", "ssh", "console", "-a", "psat", "-C", "printenv DATABASE_URL"],
        capture_output=True,
        text=True,
        env={**os.environ, "FLY_ACCESS_TOKEN": token},
        timeout=120,
    )
    for tok in out.stdout.replace("\r", " ").split():
        if tok.startswith("postgres://") or tok.startswith("postgresql://"):
            return tok.strip()
    raise SystemExit(f"Could not derive prod DB URL:\n{out.stdout}\n{out.stderr}")


def assert_prod_host(url: str, allow_any: bool) -> None:
    if EXPECTED_DB_HOST in url or allow_any:
        return
    raise SystemExit(f"Refusing: DB host does not contain '{EXPECTED_DB_HOST}'. Use --allow-any-host to override.")


def _scalar(session: Any, sql: str, params: dict) -> int:
    from sqlalchemy import text

    return int(session.execute(text(sql), params).scalar() or 0)


def main() -> int:
    ap = argparse.ArgumentParser(description="Wipe etherfi analysis data + requeue ONLY real contracts (no anchors).")
    ap.add_argument("--execute", action="store_true", help="Actually wipe + requeue (default: dry-run).")
    ap.add_argument("--yes", action="store_true", help="Required with --execute to confirm the destructive wipe.")
    ap.add_argument("--prod-db", default=None, help="Explicit prod DATABASE_URL (skips fly derivation).")
    ap.add_argument("--allow-any-host", action="store_true", help="Bypass the prod-host safety guard.")
    args = ap.parse_args()

    prod_db = derive_prod_db(args)
    assert_prod_host(prod_db, args.allow_any_host)
    os.environ["DATABASE_URL"] = prod_db
    logger.info("Target prod DB: …@%s", prod_db.split("@")[-1])

    from sqlalchemy import text  # noqa: E402

    from db.models import Job, JobStage, JobStatus, SessionLocal  # noqa: E402

    params = {"pid": PROTOCOL_ID, "company": COMPANY}

    # ---- Preview (read-only) -------------------------------------------
    with SessionLocal() as s:
        s.execute(text("SET TRANSACTION READ ONLY"))
        logger.info("=== WIPE preview (rows that WILL be deleted) ===")
        for table, where in WIPE:
            logger.info("  %-24s %d", table, _scalar(s, f"SELECT count(*) FROM {table} WHERE {where}", params))
        total = _scalar(s, "SELECT count(*) FROM contracts WHERE protocol_id=:pid", params)
        real = _scalar(s, f"SELECT count(*) FROM contracts WHERE protocol_id=:pid AND {ANCHOR_EXCL}", params)
        distinct = _scalar(s, "SELECT count(DISTINCT lower(address)) FROM contracts WHERE protocol_id=:pid", params)
        audits = _scalar(s, "SELECT count(*) FROM audit_reports WHERE protocol_id=:pid", params)
        logger.info(
            "  contracts: %d rows (%d distinct, %d dup), %d upgrade_history ANCHORS kept-but-not-requeued",
            total,
            distinct,
            total - distinct,
            total - real,
        )
        logger.info("  audit_reports KEPT: %d", audits)
        logger.info("=> would requeue %d REAL contracts (anchors excluded) under one root", real)

    if not args.execute:
        logger.info("DRY-RUN. Re-run with --execute --yes to wipe + requeue.")
        return 0
    if not args.yes:
        logger.error("Refusing destructive wipe without --yes.")
        return 3

    # ---- WIPE + DEDUP (one transaction) --------------------------------
    deleted: dict[str, int] = {}
    with SessionLocal() as s:
        for table, where in WIPE:
            res = s.execute(text(f"DELETE FROM {table} WHERE {where}"), params)
            deleted[table] = int(getattr(res, "rowcount", 0) or 0)
        res = s.execute(text(DEDUP_SQL), params)
        deleted["contracts(dedup)"] = int(getattr(res, "rowcount", 0) or 0)
        s.commit()
    logger.info("WIPE complete: %s", deleted)

    # ---- REQUEUE only the real set under ONE shared root ---------------
    run_trace = uuid.uuid4().hex[:16]
    run_root = str(uuid.uuid4())
    with SessionLocal() as s:
        rows = s.execute(
            text(
                f"SELECT lower(address) address, chain, contract_name FROM contracts "
                f"WHERE protocol_id=:pid AND {ANCHOR_EXCL} ORDER BY 1"
            ),
            params,
        ).all()
        for address, chain, contract_name in rows:
            req = {
                "address": address,
                "name": contract_name or address,
                "company": COMPANY,
                "protocol_id": PROTOCOL_ID,
                "chain": chain,
                "force": True,
                "root_job_id": run_root,
                "clean_requeue_trace": run_trace,
            }
            s.add(
                Job(
                    address=address,
                    company=COMPANY,
                    name=req["name"],
                    status=JobStatus.queued,
                    stage=JobStage.discovery,
                    detail="clean requeue: real contracts only (no upgrade_history anchors)",
                    request=req,
                    protocol_id=PROTOCOL_ID,
                    trace_id=run_trace,
                )
            )
        n = len(rows)
        s.flush()
        s.commit()
    logger.info("REQUEUED %d real contracts under run_trace=%s root=%s", n, run_trace, run_root)

    # ---- Verify --------------------------------------------------------
    with SessionLocal() as s:
        s.execute(text("SET TRANSACTION READ ONLY"))
        c_rows = _scalar(s, "SELECT count(*) FROM contracts WHERE protocol_id=:pid", params)
        c_dist = _scalar(s, "SELECT count(DISTINCT lower(address)) FROM contracts WHERE protocol_id=:pid", params)
        leftover_ef = _scalar(s, f"SELECT count(*) FROM effective_functions WHERE contract_id IN {_P1}", params)
        anchors_with_job = _scalar(
            s,
            "SELECT count(*) FROM jobs j JOIN contracts c ON lower(c.address)=lower(j.address) "
            "WHERE j.trace_id=:t AND 'upgrade_history' = ANY(c.discovery_sources)",
            {"t": run_trace},
        )
        queued = _scalar(s, "SELECT count(*) FROM jobs WHERE trace_id=:t", {"t": run_trace})
    logger.info(
        "VERIFY: contracts=%d (distinct=%d, dups=%d), leftover effective_functions=%d, "
        "anchors_requeued=%d (want 0), queued jobs=%d",
        c_rows,
        c_dist,
        c_rows - c_dist,
        leftover_ef,
        anchors_with_job,
        queued,
    )
    if anchors_with_job:
        logger.error("BUG: %d anchors were requeued — exclusion failed.", anchors_with_job)
    if leftover_ef:
        logger.warning(
            "Stale effective_functions remain (%d) — will be wholesale-replaced as the requeue runs.", leftover_ef
        )

    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    (SNAP_DIR / f"clean_requeue_{run_trace[:8]}.json").write_text(
        json.dumps(
            {
                "run_trace": run_trace,
                "run_root": run_root,
                "requeued_real": n,
                "wiped": deleted,
                "started_at": datetime.now(timezone.utc).isoformat(),
            },
            indent=2,
            default=str,
        )
    )
    logger.info("Done. Fleet will rebuild %d real contracts (~1-2h). Monitor: jobs WHERE trace_id='%s'.", n, run_trace)
    logger.info("Expect a tail of failed jobs (external deps / cold builds) — normal.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
