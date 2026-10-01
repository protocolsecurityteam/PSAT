"""indexer paged engine: cursor advance time and page density, lossless non-aligned log data

Revision ID: ea1a393444b5
Revises: eabc0b2e7078

None of these is a watched trigger column. ``data_hex`` is a nullable ADD COLUMN, a catalog-only change.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "ea1a393444b5"
down_revision: Union[str, Sequence[str], None] = "eabc0b2e7078"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("indexed_event_cursors", sa.Column("last_advanced_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("indexed_event_cursors", sa.Column("recent_logs_per_block", sa.Float(), nullable=True))
    op.add_column("indexed_event_logs", sa.Column("data_hex", sa.Text(), nullable=True))
    # Seeded cursors start at their witnessed first block, so a later position (or completion) means the scan moved.
    op.execute(
        "UPDATE indexed_event_cursors SET last_advanced_at = last_run_at "
        "WHERE backfill_complete OR last_indexed_block > coalesce(first_indexed_block, 0)"
    )


def downgrade() -> None:
    op.drop_column("indexed_event_logs", "data_hex")
    op.drop_column("indexed_event_cursors", "recent_logs_per_block")
    op.drop_column("indexed_event_cursors", "last_advanced_at")
