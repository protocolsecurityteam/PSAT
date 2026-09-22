"""Add the canonical Assessment payload to contract materializations.

Revision ID: a8f2c61d4e90
Revises: c6a10d82e5b7
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "a8f2c61d4e90"
down_revision: Union[str, Sequence[str], None] = "c6a10d82e5b7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("contract_materializations", sa.Column("assessment", postgresql.JSONB(), nullable=True))
    op.add_column("contract_materializations", sa.Column("assessment_blob_key", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("contract_materializations", "assessment_blob_key")
    op.drop_column("contract_materializations", "assessment")
