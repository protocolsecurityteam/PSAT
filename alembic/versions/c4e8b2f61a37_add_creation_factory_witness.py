"""add creation_factory to contract_creation_witnesses

Revision ID: c4e8b2f61a37
Revises: b7d3e9a02c51
Create Date: 2026-08-25 12:00:00.000000

Stores ``getcontractcreation``'s ``contractFactory`` alongside the creation
tx: the member-factory mapping rule (membership gate §3.3 deviation) needs a
STORED factory attribution, never a wire read inside a gate check. Nullable —
NULL is "no factory attribution recorded", never "created directly by an EOA";
existing rows are not backfilled (the next probe of an address records it).
"""

import sqlalchemy as sa

from alembic import op

revision = "c4e8b2f61a37"
down_revision = "b7d3e9a02c51"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("contract_creation_witnesses", sa.Column("creation_factory", sa.String(42), nullable=True))


def downgrade() -> None:
    op.drop_column("contract_creation_witnesses", "creation_factory")
