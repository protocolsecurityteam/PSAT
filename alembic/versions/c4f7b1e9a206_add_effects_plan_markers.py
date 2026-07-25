"""add effects_plan_markers

Revision ID: c4f7b1e9a206
Revises: b6e2d4a91c53
Create Date: 2026-07-24 00:00:00.000000

Records that a contract's effect candidates were planned and produced no plans.
Without it such a contract leaves no trace at all — no verdict, and no
``stage_timing_effects`` artifact when it has no job of its own — so effects
selection re-sweeps it from every subsequent job in the protocol.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision: str = "c4f7b1e9a206"
down_revision: Union[str, Sequence[str], None] = "b6e2d4a91c53"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "effects_plan_markers",
        sa.Column("contract_id", sa.Integer(), nullable=False),
        sa.Column("job_id", UUID(as_uuid=True), nullable=True),
        sa.Column("candidates_planned", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("planned_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.ForeignKeyConstraint(["contract_id"], ["contracts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("contract_id"),
    )


def downgrade() -> None:
    op.drop_table("effects_plan_markers")
