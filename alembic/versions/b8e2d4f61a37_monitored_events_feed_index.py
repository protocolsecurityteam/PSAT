"""Composite index for the account events feed's keyset paging.

Revision ID: b8e2d4f61a37
Revises: c3d9e5a1f7b2

``GET /api/me/events`` orders and pages on ``(detected_at, block_number, id)``; with only ``detected_at`` indexed, the
many rows one scan pass stamps with the same ``now()`` had to be re-sorted on every page. Built inline: the table is
modest at rollout.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "b8e2d4f61a37"
down_revision: Union[str, Sequence[str], None] = "c3d9e5a1f7b2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index("ix_monitored_events_feed", "monitored_events", ["detected_at", "block_number", "id"])


def downgrade() -> None:
    op.drop_index("ix_monitored_events_feed", table_name="monitored_events")
