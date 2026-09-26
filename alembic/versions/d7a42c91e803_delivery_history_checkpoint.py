"""Anchor delivery aggregates to the block history they measured."""

import sqlalchemy as sa

from alembic import op

revision = "d7a42c91e803"
down_revision = "c6a10d82e5b7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("token_delivery_evidence", sa.Column("measured_through_hash", sa.String(66), nullable=True))


def downgrade() -> None:
    op.drop_column("token_delivery_evidence", "measured_through_hash")
