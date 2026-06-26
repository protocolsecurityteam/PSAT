"""add analysis_schema_version to contract_materializations

Revision ID: f1a2b3c4d5e6
Revises: d4e8f1a9c2b7
Create Date: 2026-06-25 12:00:00.000000

Adds an analyzer/pipeline schema-version dimension to the materialization
cache. ``db.contract_materializations`` only serves a row whose
``analysis_schema_version`` equals the current ``ANALYSIS_SCHEMA_VERSION``
module constant, so bumping that constant by hand makes existing rows read
as a miss and rebuild. The dimension is deliberately a manually-bumped
constant rather than a git-SHA tie, which would cold-rebuild every multi-MB
forge+Slither bundle on unrelated deploys (frontend, docs, workers).

Existing rows are backfilled — via the column ``server_default`` — to
version 1, the value of ``ANALYSIS_SCHEMA_VERSION`` at the time this column
was added, so the deploy shipping this migration does not invalidate the
whole cache at once. The default is kept on the column (matching the table's
other NOT NULL columns) as a safety net; the write paths stamp the version
explicitly.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "f1a2b3c4d5e6"
down_revision: Union[str, Sequence[str], None] = "d4e8f1a9c2b7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "contract_materializations",
        sa.Column(
            "analysis_schema_version",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )


def downgrade() -> None:
    op.drop_column("contract_materializations", "analysis_schema_version")
