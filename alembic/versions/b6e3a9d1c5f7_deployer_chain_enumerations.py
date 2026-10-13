"""deployer_chain_enumerations: the last creation enumeration of an EOA per chain, reused until new evidence.

Revision ID: b6e3a9d1c5f7
Revises: a4d2f8c6e1b9
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "b6e3a9d1c5f7"
down_revision: Union[str, Sequence[str], None] = "a4d2f8c6e1b9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "deployer_chain_enumerations",
        sa.Column("chain_id", sa.Integer(), nullable=False),
        sa.Column("deployer", sa.String(length=42), nullable=False),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("creations", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("observed_count", sa.Integer(), nullable=True),
        sa.Column("settled_through_block", sa.BigInteger(), nullable=True),
        sa.Column("enumerated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "outcome IN ('complete', 'internal_budget_exceeded', 'cap_reached')",
            name="ck_deployer_chain_enumerations_outcome",
        ),
        sa.CheckConstraint(
            "(outcome = 'complete') = (creations IS NOT NULL)",
            name="ck_deployer_chain_enumerations_creations_complete",
        ),
        sa.CheckConstraint(
            "outcome NOT IN ('internal_budget_exceeded', 'cap_reached') OR observed_count IS NOT NULL",
            name="ck_deployer_chain_enumerations_limit_count",
        ),
        sa.PrimaryKeyConstraint("chain_id", "deployer"),
    )


def downgrade() -> None:
    op.drop_table("deployer_chain_enumerations")
