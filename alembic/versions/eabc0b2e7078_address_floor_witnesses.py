"""address_floor_witnesses: per-address deploy-floor witness, seeded from witnessed cursors

Revision ID: eabc0b2e7078
Revises: d839b5eca4fa

One row per (chain, address) from cursors whose ``first_indexed_block_basis`` is ``creation_block_minus_one``. When
those cursors disagree on the block, the row is ``not_determined``: disagreement is evidence against every candidate,
so none is chosen.
"""

from __future__ import annotations

import logging
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "eabc0b2e7078"
down_revision: Union[str, Sequence[str], None] = "d839b5eca4fa"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.runtime.migration")

_WITNESSED = """
    SELECT chain_id, lower(event_address) AS address,
           count(DISTINCT first_indexed_block) AS distinct_blocks,
           min(first_indexed_block) AS first_block,
           max(first_indexed_block) AS last_block
    FROM indexed_event_cursors
    WHERE first_indexed_block_basis = 'creation_block_minus_one' AND first_indexed_block IS NOT NULL
    GROUP BY chain_id, lower(event_address)
"""


def upgrade() -> None:
    op.create_table(
        "address_floor_witnesses",
        sa.Column("chain_id", sa.Integer(), nullable=False),
        sa.Column("address", sa.String(length=42), nullable=False),
        sa.Column("first_indexed_block", sa.BigInteger(), nullable=True),
        sa.Column("basis", sa.String(length=32), nullable=False),
        sa.Column("witnessed_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "basis IN ('creation_block_minus_one', 'not_determined')", name="ck_address_floor_witnesses_basis"
        ),
        sa.CheckConstraint(
            "(basis = 'creation_block_minus_one') = (first_indexed_block IS NOT NULL)",
            name="ck_address_floor_witnesses_block_iff_proven",
        ),
        sa.CheckConstraint("address = lower(address)", name="ck_address_floor_witnesses_address_lower"),
        sa.PrimaryKeyConstraint("chain_id", "address"),
    )
    bind = op.get_bind()
    for chain_id, address, _distinct, first_block, last_block in bind.execute(
        sa.text(f"SELECT * FROM ({_WITNESSED}) w WHERE distinct_blocks > 1 ORDER BY chain_id, address")
    ):
        logger.warning(
            "address_floor_witnesses backfill: witnessed cursors disagree; recording not_determined "
            "chain_id=%s address=%s first_indexed_block range=[%s, %s]",
            chain_id,
            address,
            first_block,
            last_block,
        )
    op.execute(f"""
        INSERT INTO address_floor_witnesses (chain_id, address, first_indexed_block, basis)
        SELECT chain_id, address,
               CASE WHEN distinct_blocks = 1 THEN first_block END,
               CASE WHEN distinct_blocks = 1 THEN 'creation_block_minus_one' ELSE 'not_determined' END
        FROM ({_WITNESSED}) w
    """)


def downgrade() -> None:
    op.drop_table("address_floor_witnesses")
