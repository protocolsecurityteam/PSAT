"""use chain_ids for protocol chain identity

Revision ID: 7a2b3c4d5e6f
Revises: 6f1a2b3c4d5e
Create Date: 2026-06-08 00:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "7a2b3c4d5e6f"
down_revision: Union[str, Sequence[str], None] = "6f1a2b3c4d5e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        sa.text(
            """
            DO $$
            BEGIN
              IF EXISTS (
                SELECT 1
                FROM protocols
                WHERE chains IS NOT NULL
                  AND array_length(chains, 1) IS NOT NULL
                  AND array_length(chains, 1) > 0
              ) THEN
                RAISE EXCEPTION 'protocols.chains is unsupported; write numeric chain_ids instead';
              END IF;
            END $$;
            """
        )
    )
    op.add_column(
        "protocols",
        sa.Column(
            "chain_ids",
            postgresql.ARRAY(sa.Integer()),
            nullable=False,
            server_default=sa.text("'{}'::integer[]"),
        ),
    )
    op.drop_column("protocols", "chains")


def downgrade() -> None:
    raise NotImplementedError("Downgrade from numeric protocol chain identity is unsupported.")
