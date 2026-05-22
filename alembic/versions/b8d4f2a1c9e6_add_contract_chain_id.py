"""add contract chain_id

Revision ID: b8d4f2a1c9e6
Revises: 67bd81b64faa
Create Date: 2026-05-20 02:15:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "b8d4f2a1c9e6"
down_revision: Union[str, Sequence[str], None] = "67bd81b64faa"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("contracts", sa.Column("chain_id", sa.Integer(), nullable=True))
    op.create_index("ix_contracts_chain_id", "contracts", ["chain_id"], unique=False)
    op.execute(
        """
        UPDATE contracts
        SET chain_id = CASE lower(chain)
            WHEN 'ethereum' THEN 1
            WHEN 'mainnet' THEN 1
            WHEN 'eth' THEN 1
            WHEN 'ethereum mainnet' THEN 1
            WHEN 'arbitrum' THEN 42161
            WHEN 'arbitrum one' THEN 42161
            WHEN 'optimism' THEN 10
            WHEN 'optimistic ethereum' THEN 10
            WHEN 'polygon' THEN 137
            WHEN 'polygon pos' THEN 137
            WHEN 'matic' THEN 137
            WHEN 'base' THEN 8453
            WHEN 'base mainnet' THEN 8453
            WHEN 'avalanche' THEN 43114
            WHEN 'avalanche c-chain' THEN 43114
            WHEN 'avax' THEN 43114
            WHEN 'bsc' THEN 56
            WHEN 'bnb' THEN 56
            WHEN 'bnb chain' THEN 56
            WHEN 'binance smart chain' THEN 56
            WHEN 'linea' THEN 59144
            WHEN 'scroll' THEN 534352
            WHEN 'zksync' THEN 324
            WHEN 'zk sync' THEN 324
            WHEN 'blast' THEN 81457
            WHEN 'mode' THEN 34443
            WHEN 'bera' THEN 80094
            WHEN 'berachain' THEN 80094
            ELSE chain_id
        END
        WHERE chain_id IS NULL
        """
    )


def downgrade() -> None:
    op.drop_index("ix_contracts_chain_id", table_name="contracts")
    op.drop_column("contracts", "chain_id")
