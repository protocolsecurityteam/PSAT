"""add contracts.secondary_implementations

Revision ID: d8b2f4a1c6e3
Revises: a7f3c2e9b104
Create Date: 2026-05-30 00:00:00.000000

Records the extra logic contracts a proxy delegates to beyond the EIP-1967
slot implementation — the split-proxy / admin-impl pattern (e.g. ether.fi
LRTSquared's ``adminImpl``). NULL for the overwhelming majority of contracts;
populated only for proxies whose primary impl forwards via a state-var
delegatecall. See services/discovery/secondary_impl.py.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "d8b2f4a1c6e3"
down_revision: Union[str, Sequence[str], None] = "a7f3c2e9b104"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "contracts",
        sa.Column("secondary_implementations", sa.ARRAY(sa.String(length=42)), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("contracts", "secondary_implementations")
