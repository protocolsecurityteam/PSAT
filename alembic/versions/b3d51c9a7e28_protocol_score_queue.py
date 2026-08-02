"""Protocol-score dirty queue.

The invalidation half of the scorer planes. ``protocol_scores`` records what a
fold concluded; this table records that a protocol's inputs changed since the
last one. It is separate from ``a7e2f04c9b31`` because it is a different
concern — that migration pinned the two data planes the fold reads and writes,
this one pins how the fold learns it has work.

One row per protocol, keyed on the protocol so N marks between two passes cost
one fold. ``dirty_at`` is both the sweep's ordering cursor and the loop's
clearing predicate: the loop deletes only rows at or before the instant it read
the population, so a mark that arrives mid-fold is not cleared by a fold that
never saw it.

Revision ID: b3d51c9a7e28
Revises: a7e2f04c9b31
Create Date: 2026-08-01
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "b3d51c9a7e28"
down_revision: Union[str, Sequence[str], None] = "a7e2f04c9b31"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "protocol_score_queue",
        sa.Column("protocol_id", sa.Integer(), nullable=False),
        sa.Column("dirty_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("reason", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(["protocol_id"], ["protocols.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("protocol_id"),
    )


def downgrade() -> None:
    op.drop_table("protocol_score_queue")
