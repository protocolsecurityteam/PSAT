"""add bytecode_cache

Revision ID: ccfe335ed565
Revises: 95ccb994b48c
Create Date: 2026-05-01 21:00:00.000000

Cross-process eth_getCode cache. Bytecode is effectively immutable per
(chain_id, address) — no TTL column. Writers in services/clients/rpc.py keep the
existing in-memory dict layered on top.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "ccfe335ed565"
down_revision: Union[str, Sequence[str], None] = "95ccb994b48c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "bytecode_cache",
        sa.Column("chain_id", sa.Integer(), nullable=False),
        sa.Column("address", sa.String(length=42), nullable=False),
        sa.Column("bytecode", sa.Text(), nullable=False),
        sa.Column("code_keccak", sa.String(length=66), nullable=False),
        sa.Column("cached_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("selfdestructed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("chain_id", "address"),
    )
    op.create_index("ix_bytecode_cache_cached_at", "bytecode_cache", ["cached_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_bytecode_cache_cached_at", table_name="bytecode_cache")
    op.drop_table("bytecode_cache")
