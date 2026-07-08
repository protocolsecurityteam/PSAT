"""add monitored_contracts.last_polled_at

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-07-08

Poller rotation cursor (design §2.2): the driver selects the least-recently-
polled ``needs_polling`` slice (``ORDER BY last_polled_at ASC NULLS FIRST``) and
stamps this column per chunk-commit. Additive, nullable; existing rows sort
first until their first poll.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "b2c3d4e5f6a7"
down_revision: Union[str, Sequence[str], None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "monitored_contracts",
        sa.Column("last_polled_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("monitored_contracts", "last_polled_at")
