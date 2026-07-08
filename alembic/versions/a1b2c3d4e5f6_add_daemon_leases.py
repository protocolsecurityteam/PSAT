"""add daemon_leases table

Revision ID: a1b2c3d4e5f6
Revises: c7d1e9a4b2f8
Create Date: 2026-07-08

Layer-1 singleton primitive for the monitoring restructure (design §2.4): a
named, TTL'd row lease that gates each scan/poll daemon pass. Row-based rather
than a pg advisory lock so it survives per-window commits and pgbouncer
transaction pooling. Additive; no backfill.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, Sequence[str], None] = "c7d1e9a4b2f8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "daemon_leases",
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("holder", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("name"),
    )


def downgrade() -> None:
    op.drop_table("daemon_leases")
