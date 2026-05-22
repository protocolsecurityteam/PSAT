"""apply utils.secrets.sanitize_* to jobs and inline artifact rows

Revision ID: 67bd81b64faa
Revises: 4d72e9b1f035
Create Date: 2026-05-21 16:00:00.000000

Routes existing ``jobs.request`` (JSONB), ``jobs.error`` (Text), and
inline ``artifacts.data`` (JSONB, for ``dependencies`` /
``dynamic_dependencies`` / ``stage_errors``) through the same helpers
the application uses on its output paths. Storage-backed artifact
bodies are handled out-of-band by
``scripts/sanitize_storage_artifacts.py``.

Idempotent. Downgrade is a no-op.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# Ensure the project root is on sys.path so ``utils`` resolves when
# alembic is run from the project root (the usual case) and from CI
# where the working directory may differ.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from utils.secrets import sanitize_obj, sanitize_string  # noqa: E402

revision: str = "67bd81b64faa"
down_revision: Union[str, Sequence[str], None] = "4d72e9b1f035"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.runtime.migration")


# Artifact ``name`` values whose inline ``data`` JSONB is scrubbed.
_TARGET_ARTIFACT_NAMES = (
    "dependencies",
    "static_dependencies",
    "dynamic_dependencies",
    "classifications",
    "contract_flags",
    "dependency_errors",
    "stage_errors",
)

# Artifact names whose bodies historically carried a top-level ``rpc`` key.
_DROP_RPC_KEY_NAMES = frozenset({"dependencies", "static_dependencies", "dynamic_dependencies", "classifications"})


def upgrade() -> None:
    bind = op.get_bind()

    _scrub_jobs_request(bind)
    _scrub_jobs_error(bind)
    _scrub_inline_artifacts(bind)


def downgrade() -> None:
    # Forward-only data scrub.
    pass


def _scrub_jobs_request(bind: sa.engine.Connection) -> None:
    rows = bind.execute(sa.text("SELECT id, request FROM jobs WHERE request IS NOT NULL")).fetchall()
    scrubbed = 0
    for row in rows:
        original = row.request
        cleaned = sanitize_obj(original)
        if cleaned == original:
            continue
        bind.execute(
            sa.text("UPDATE jobs SET request = CAST(:r AS JSONB) WHERE id = :id"),
            {"r": json.dumps(cleaned), "id": row.id},
        )
        scrubbed += 1
    logger.info("sanitize_existing_rows: jobs.request rewrote %d row(s)", scrubbed)


def _scrub_jobs_error(bind: sa.engine.Connection) -> None:
    rows = bind.execute(sa.text("SELECT id, error FROM jobs WHERE error IS NOT NULL AND error LIKE '%://%'")).fetchall()
    scrubbed = 0
    for row in rows:
        cleaned = sanitize_string(row.error)
        if cleaned == row.error:
            continue
        bind.execute(
            sa.text("UPDATE jobs SET error = :e WHERE id = :id"),
            {"e": cleaned, "id": row.id},
        )
        scrubbed += 1
    logger.info("sanitize_existing_rows: jobs.error rewrote %d row(s)", scrubbed)


def _scrub_inline_artifacts(bind: sa.engine.Connection) -> None:
    # Only inline JSONB bodies. ``storage_key IS NOT NULL`` rows are
    # handled by the companion script.
    rows = bind.execute(
        sa.text(
            "SELECT id, name, data FROM artifacts "
            "WHERE data IS NOT NULL "
            "  AND storage_key IS NULL "
            "  AND name = ANY(:names)"
        ),
        {"names": list(_TARGET_ARTIFACT_NAMES)},
    ).fetchall()
    scrubbed = 0
    for row in rows:
        original = row.data
        cleaned = sanitize_obj(original)
        if isinstance(cleaned, dict) and row.name in _DROP_RPC_KEY_NAMES:
            cleaned.pop("rpc", None)
        if cleaned == original:
            continue
        bind.execute(
            sa.text("UPDATE artifacts SET data = CAST(:d AS JSONB) WHERE id = :id"),
            {"d": json.dumps(cleaned), "id": row.id},
        )
        scrubbed += 1
    logger.info(
        "sanitize_existing_rows: artifacts.data rewrote %d inline row(s)",
        scrubbed,
    )
