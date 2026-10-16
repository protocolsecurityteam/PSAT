"""contracts.via_ir: the verified viaIR setting, carried to the static build.

Revision ID: d5e8a2c4f1b6
Revises: c3d9e5a1f7b2
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "d5e8a2c4f1b6"
down_revision: Union[str, Sequence[str], None] = "c3d9e5a1f7b2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("contracts", sa.Column("via_ir", sa.Boolean(), nullable=True))


def downgrade() -> None:
    op.drop_column("contracts", "via_ir")
