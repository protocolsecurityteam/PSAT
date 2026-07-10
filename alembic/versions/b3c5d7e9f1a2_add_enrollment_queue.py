"""add monitoring_enrollment_queue and protocols.last_enrollment_reconcile_at

Revision ID: b3c5d7e9f1a2
Revises: b2c3d4e5f6a7
Create Date: 2026-07-08

Dirty-flag enrollment queue + slow-sweep cursor for the monitoring restructure
(design §2.3 / Stage 5). ``monitoring_enrollment_queue`` holds one row per
protocol that needs its ``monitored_contracts`` reconciled; the drainer claims
due rows with a lease and deletes the row it claimed on success.
``protocols.last_enrollment_reconcile_at`` is the K-per-tick slow-sweep cursor.
Additive; no backfill.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "b3c5d7e9f1a2"
down_revision: Union[str, Sequence[str], None] = "b2c3d4e5f6a7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "monitoring_enrollment_queue",
        sa.Column("protocol_id", sa.Integer(), nullable=False),
        sa.Column("dirty_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("reason", sa.String(length=64), nullable=True),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("lease_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["protocol_id"], ["protocols.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("protocol_id"),
    )
    op.add_column(
        "protocols",
        sa.Column("last_enrollment_reconcile_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("protocols", "last_enrollment_reconcile_at")
    op.drop_table("monitoring_enrollment_queue")
