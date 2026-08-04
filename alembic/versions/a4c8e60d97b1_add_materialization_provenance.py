"""Add contract_materializations.provenance

A materialization row says "this bundle is the current analysis of this
contract". Until now nothing on the row said WHO established it or FROM WHAT —
the recursion was the only writer, so the answer was implicit. Once the main
pipeline and the promotion sweep also write rows, the producer and its source
job are facts a reader cannot reconstruct, and invariant 7 requires the source
job to be recorded before a per-job artifact may enter the versioned store.

Nullable on purpose: a row written before this column existed carries no
provenance, and NULL is that third state — not a claim that some default
producer wrote it.

Revision ID: a4c8e60d97b1
Revises: c7f4a1e9b035
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "a4c8e60d97b1"
down_revision = "c7f4a1e9b035"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "contract_materializations",
        sa.Column("provenance", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("contract_materializations", "provenance")
