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


def _chain_label_sql(expr: str) -> str:
    return f"""
    CASE {expr}
      WHEN 1 THEN 'ethereum'
      WHEN 42161 THEN 'arbitrum'
      WHEN 10 THEN 'optimism'
      WHEN 8453 THEN 'base'
      WHEN 137 THEN 'polygon'
      WHEN 43114 THEN 'avalanche'
      WHEN 56 THEN 'bsc'
      WHEN 59144 THEN 'linea'
      WHEN 534352 THEN 'scroll'
      WHEN 324 THEN 'zksync'
      WHEN 81457 THEN 'blast'
      WHEN 34443 THEN 'mode'
      WHEN 80094 THEN 'berachain'
      ELSE NULL
    END
    """


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
                RAISE EXCEPTION 'protocols.chains legacy labels are not migrated; write numeric chain_ids instead';
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
    op.add_column(
        "protocols",
        sa.Column(
            "chains",
            postgresql.ARRAY(sa.String(length=100)),
            nullable=True,
            server_default=sa.text("'{}'::varchar[]"),
        ),
    )
    op.execute(
        sa.text(
            f"""
            UPDATE protocols
            SET chains = (
              SELECT COALESCE(array_agg(DISTINCT label), ARRAY[]::varchar[])
              FROM unnest(chain_ids) AS chain_item(raw_chain_id)
              CROSS JOIN LATERAL (
                SELECT {_chain_label_sql("chain_item.raw_chain_id")} AS label
              ) AS mapped
              WHERE label IS NOT NULL
            )
            WHERE chain_ids IS NOT NULL
            """
        )
    )
    op.drop_column("protocols", "chain_ids")
