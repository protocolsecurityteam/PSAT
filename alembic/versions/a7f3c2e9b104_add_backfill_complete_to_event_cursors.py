"""add backfill_complete to indexed_event_cursors

Revision ID: a7f3c2e9b104
Revises: b2e7c1a9f4d3
Create Date: 2026-05-28

A cursor's ``last_indexed_block`` is now seeded from the event address's
*creation block* rather than block 0 (so a freshly-enrolled RolesAuthority
no longer rescans ~20M empty pre-deployment blocks). That makes the old
"cursor > 0 ⟹ indexed" proxy wrong: a seeded-but-unscanned cursor is at a
positive block yet has indexed nothing. ``backfill_complete`` is the explicit
"the historical backfill has reached head at least once" signal the Solmate
canCall resolver consults before trusting the durable index — until it flips
True, resolution falls back to an inline fetch instead of folding a partial
index.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "a7f3c2e9b104"
down_revision: Union[str, Sequence[str], None] = "b2e7c1a9f4d3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "indexed_event_cursors",
        sa.Column("backfill_complete", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )


def downgrade() -> None:
    op.drop_column("indexed_event_cursors", "backfill_complete")
