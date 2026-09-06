"""Persist coalesced monitoring generations and idempotent receipts."""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "d9e7a31c402f"
down_revision = "c8a6f20d913e"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "monitoring_reanalysis",
        sa.Column("chain_id", sa.Integer(), primary_key=True),
        sa.Column("address", sa.String(42), primary_key=True),
        sa.Column("generation", sa.BigInteger(), nullable=False, server_default="1"),
        sa.Column("acknowledged_generation", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("request", postgresql.JSONB(), nullable=False),
        sa.Column("triggered_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "monitoring_reanalysis_receipts",
        sa.Column("chain_id", sa.Integer(), primary_key=True),
        sa.Column("address", sa.String(42), primary_key=True),
        sa.Column("generation", sa.BigInteger(), primary_key=True),
        sa.Column("job_id", postgresql.UUID(), sa.ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False),
    )


def downgrade():
    op.drop_table("monitoring_reanalysis_receipts")
    op.drop_table("monitoring_reanalysis")
