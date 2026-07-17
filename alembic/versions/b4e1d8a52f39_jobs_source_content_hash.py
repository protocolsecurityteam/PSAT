"""jobs.source_content_hash + analysis_schema_version (cross-chain static-cache reuse)

Revision ID: b4e1d8a52f39
Revises: a3f7c9d21e08
Create Date: 2026-07-17 13:00:00.000000

Expand-contract (invariant 9): add two nullable columns to ``jobs`` so the
job-level static cache can reuse a completed job's code-plane analysis for a new
``(chain, address)`` deployment of the same verified source (invariant 1 — the
"lookup-before-analyze step in the static path" for job ROOTS, the analog of the
``contract_materializations`` reuse for nested contracts).

  * ``source_content_hash`` — the ``services/discovery/fetch.py`` content hash of
    this job's verified-source set. Indexed for the fallback lookup.
  * ``analysis_schema_version`` — the analyzer schema version the job was analyzed
    under, so a bumped analyzer misses stale donors instead of reusing a
    differently-shaped bundle (mirrors ``contract_materializations``).

**No backfill.** Both are written only when a job fetches its own source
(``workers/discovery.py``); a cache-hit job never fetches, and legacy rows stay
NULL and so are never selected as a reuse donor — they simply fall through to a
normal analysis. Adding nullable columns is metadata-only in Postgres 11+, safe
inside the default ``lock_timeout``. Downgrade drops the index and both columns.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "b4e1d8a52f39"
down_revision: Union[str, Sequence[str], None] = "a3f7c9d21e08"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_INDEX = "ix_jobs_source_content_hash"


def upgrade() -> None:
    op.add_column("jobs", sa.Column("source_content_hash", sa.String(length=66), nullable=True))
    op.add_column("jobs", sa.Column("analysis_schema_version", sa.Integer(), nullable=True))
    op.create_index(_INDEX, "jobs", ["source_content_hash"])


def downgrade() -> None:
    op.drop_index(_INDEX, table_name="jobs")
    op.drop_column("jobs", "analysis_schema_version")
    op.drop_column("jobs", "source_content_hash")
