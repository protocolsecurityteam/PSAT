"""floor witness retry state, and the seed each cursor was enrolled at

Revision ID: aa9f6ba5b7df
Revises: ea1a393444b5

Existing witness rows: a proven floor becomes ``proven`` at its own block; a ``not_determined`` row can only have come
from witnessed cursors disagreeing, so it becomes ``cursor_conflict`` and is due for a retry now. None of the new
columns is a watched trigger column.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "aa9f6ba5b7df"
down_revision: Union[str, Sequence[str], None] = "ea1a393444b5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "address_floor_witnesses"


def upgrade() -> None:
    op.add_column(_TABLE, sa.Column("outcome", sa.String(length=24), nullable=True))
    op.add_column(_TABLE, sa.Column("seed_block", sa.BigInteger(), nullable=True))
    op.add_column(_TABLE, sa.Column("attempts", sa.Integer(), server_default="0", nullable=False))
    op.add_column(_TABLE, sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True))
    op.execute(
        f"UPDATE {_TABLE} SET outcome = 'proven', seed_block = first_indexed_block "
        "WHERE basis = 'creation_block_minus_one'"
    )
    op.execute(
        f"UPDATE {_TABLE} SET outcome = 'cursor_conflict', next_attempt_at = now() WHERE basis = 'not_determined'"
    )
    op.alter_column(_TABLE, "outcome", nullable=False)
    op.create_check_constraint(
        "ck_address_floor_witnesses_outcome",
        _TABLE,
        "outcome IN ('proven', 'prior_incarnation', 'failed', 'cursor_conflict')",
    )
    op.create_check_constraint(
        "ck_address_floor_witnesses_proven_iff_creation",
        _TABLE,
        "(outcome = 'proven') = (basis = 'creation_block_minus_one')",
    )
    op.create_check_constraint(
        "ck_address_floor_witnesses_retry_iff_undecided",
        _TABLE,
        "(outcome IN ('failed', 'cursor_conflict')) = (next_attempt_at IS NOT NULL)",
    )
    op.add_column("indexed_event_cursors", sa.Column("enrolled_seed_block", sa.BigInteger(), nullable=True))


def downgrade() -> None:
    op.drop_column("indexed_event_cursors", "enrolled_seed_block")
    op.drop_constraint("ck_address_floor_witnesses_retry_iff_undecided", _TABLE, type_="check")
    op.drop_constraint("ck_address_floor_witnesses_proven_iff_creation", _TABLE, type_="check")
    op.drop_constraint("ck_address_floor_witnesses_outcome", _TABLE, type_="check")
    op.drop_column(_TABLE, "next_attempt_at")
    op.drop_column(_TABLE, "attempts")
    op.drop_column(_TABLE, "seed_block")
    op.drop_column(_TABLE, "outcome")
