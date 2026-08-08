"""Typed-asset evidence and the scan's union extent.

Two columns, both for the same reason: an incremental scan's window is not the
claim, and a fact seen in an earlier window has to survive into the fetch record
that is current.

``typed_assets`` is the evidence for a WITHHELD completeness claim. An
ERC-721/1155 receipt whose current holding has no readable ``balanceOf(address)``
answer is why a swept asset set may not be published as complete or as empty.
Recorded only in the cycle that saw it, that refusal lasted exactly one cycle:
the next incremental window named no typed receipt, the set looked complete, and
the earned negative the earlier scan refused got published anyway. The column
carries the receipts forward so every later cycle re-reads them and the refusal
persists until the evidence resolves.

``swept_from_block`` is the first block of the UNION of the scans behind the
current asset set. Without it an incremental fetch's basis string named its own
63-block window while claiming a full history — and the basis string is what
scopes the published claim.

Revision ID: c3a9f21b7d48
Revises: b2f7c0e14a35
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "c3a9f21b7d48"
down_revision = "b2f7c0e14a35"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "contract_balance_fetches",
        sa.Column("typed_assets", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column("contract_balance_fetches", sa.Column("swept_from_block", sa.BigInteger(), nullable=True))
    # No backfill. A row written before this column existed carries no statement
    # about typed receipts, and NULL is that third state — writing ``[]`` would
    # assert a scan found none, which is exactly the false completeness this
    # column exists to prevent.


def downgrade() -> None:
    op.drop_column("contract_balance_fetches", "swept_from_block")
    op.drop_column("contract_balance_fetches", "typed_assets")
