"""add worker_heartbeats table

Revision ID: b2e7c1a9f4d3
Revises: 67bd81b64faa
Create Date: 2026-05-28 12:00:00.000000

Liveness rows for the background daemons that drain their own tables
instead of the ``jobs`` queue (coverage-verify, audit text/scope
extraction, event-log indexer, enrollment reconciler). Each daemon
upserts its row every loop tick via ``db.queue.record_heartbeat`` so the
``/api/fleet`` endpoint can distinguish 'idle' from 'dead' — a work-row
timestamp can't, because an idle drainer has no recent rows to point at.

One row per logical process name (PK). Downgrade drops the table.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "b2e7c1a9f4d3"
down_revision: Union[str, Sequence[str], None] = "67bd81b64faa"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "worker_heartbeats",
        sa.Column("process", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="running", nullable=False),
        sa.Column("detail", postgresql.JSONB(), nullable=True),
        sa.Column(
            "beat_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("process"),
    )


def downgrade() -> None:
    op.drop_table("worker_heartbeats")
