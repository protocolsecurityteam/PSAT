"""add chain_id to jobs (expand-contract, invariants 1 & 9)

Revision ID: f3a9c1d47b02
Revises: d5e7f9a1b3c5
Create Date: 2026-07-14 12:00:00.000000

First-class chain identity for the analysis deployment (invariant 1). This is
the *expand* half of an expand-contract sequence (invariant 9): add a nullable
column, backfill from the existing ``request->>'chain'`` string, verify, then
land a CHECK constraint (NOT a ``SET NOT NULL`` — company/root jobs with
``address IS NULL`` legitimately keep ``chain_id`` NULL). Reads still come from
``request["chain"]`` until the M0.2 Item-2 dedup flip; nothing here changes
mainnet behaviour.

Backfill rules (normative, from MULTICHAIN_INVARIANTS.md M0.2 Item 1):
  - ``address IS NULL``            → keep NULL (company/root jobs)
  - chain absent / NULL / empty    → 1 (mainnet edge default)
  - ``"ethereum"`` / ``"mainnet"`` → 1 (registry canonicalization)
  - ``"unknown"`` sentinel         → 1 (not registry-resolvable → fallback)
  - other recognized chain name    → its registry id
  - unrecognized non-sentinel name → 1, with a loud warning (historical rows
    are made valid first, per invariant 6's ordering constraint)

Safety checklist:
  - Adding a nullable column is metadata-only in Postgres 11+ (no table
    rewrite); safe inside the default lock_timeout=10s.
  - Backfill runs over the connection (no ORM model imports — house style,
    cf. 67bd81b64faa), grouped by the small set of DISTINCT chain strings so it
    is a handful of set-based UPDATEs regardless of prod row count.
  - The verify step raises before the CHECK lands if any address-scoped row is
    still NULL, so the constraint can never fail its own validation on
    populated data.
  - Downgrade is supported: drop the constraint, the index, then the column.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# Ensure the project root is importable when alembic runs from the repo root
# (usual case) or from a differing CI working directory — mirrors 67bd81b64faa.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from utils.chains import UnknownChainError, chain_by_name  # noqa: E402

revision: str = "f3a9c1d47b02"
down_revision: Union[str, Sequence[str], None] = "d5e7f9a1b3c5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.runtime.migration")

_CONSTRAINT = "ck_jobs_chain_id_required_for_address"
_INDEX = "ix_jobs_lower_address_chain_id"


def _resolve_chain_id(raw: str | None) -> tuple[int, str]:
    """Map a legacy ``request->>'chain'`` string to a chain id + a reason label.

    Never raises: absent/unknown/unrecognized values fall back to mainnet (1),
    which is the whole point of the pre-fail-loud backfill.
    """
    if raw is None or not raw.strip():
        return 1, "absent->mainnet"
    try:
        return chain_by_name(raw).chain_id, "registry"
    except UnknownChainError:
        # ``"unknown"`` sentinel raises here too; distinguish it from a genuine
        # typo only for the log label — both are made valid as mainnet.
        if raw.strip().lower() == "unknown":
            return 1, "unknown-sentinel->mainnet"
        return 1, "unrecognized->mainnet"


def upgrade() -> None:
    bind = op.get_bind()

    op.add_column("jobs", sa.Column("chain_id", sa.Integer(), nullable=True))

    _backfill(bind)
    _verify(bind)

    op.create_index(_INDEX, "jobs", [sa.text("lower(address)"), "chain_id"])
    op.create_check_constraint(
        _CONSTRAINT,
        "jobs",
        "address IS NULL OR chain_id IS NOT NULL",
    )


def _backfill(bind: sa.engine.Connection) -> None:
    # Operate on the (small) set of DISTINCT chain strings among address-scoped
    # rows, not per-row: one set-based UPDATE per distinct value keeps the
    # backfill cheap on a populated prod table. ``request->>'chain'`` is NULL
    # both when ``request`` itself is NULL and when the key is absent; a single
    # NULL distinct value covers both and maps to mainnet.
    distinct = bind.execute(
        sa.text("SELECT DISTINCT request->>'chain' AS chain FROM jobs WHERE address IS NOT NULL")
    ).fetchall()
    total = 0
    for row in distinct:
        raw = row.chain
        chain_id, reason = _resolve_chain_id(raw)
        # IS NOT DISTINCT FROM so the NULL bucket (absent chain) matches too.
        result = bind.execute(
            sa.text(
                "UPDATE jobs SET chain_id = :cid "
                "WHERE address IS NOT NULL AND request->>'chain' IS NOT DISTINCT FROM :raw"
            ),
            {"cid": chain_id, "raw": raw},
        )
        count = result.rowcount or 0
        total += count
        log = logger.warning if reason == "unrecognized->mainnet" else logger.info
        log("backfill jobs.chain_id: chain=%r -> %d (%s), %d row(s)", raw, chain_id, reason, count)
    logger.info("backfill jobs.chain_id: %d address-scoped row(s) total", total)


def _verify(bind: sa.engine.Connection) -> None:
    missing = bind.execute(sa.text("SELECT COUNT(*) FROM jobs WHERE address IS NOT NULL AND chain_id IS NULL")).scalar()
    if missing:
        raise RuntimeError(
            f"chain_id backfill left {missing} address-scoped job(s) with NULL chain_id; "
            "refusing to apply the CHECK constraint on inconsistent data"
        )


def downgrade() -> None:
    op.drop_constraint(_CONSTRAINT, "jobs", type_="check")
    op.drop_index(_INDEX, table_name="jobs")
    op.drop_column("jobs", "chain_id")
