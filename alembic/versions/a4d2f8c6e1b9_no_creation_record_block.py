"""contract_creation_witnesses.no_creation_record_block: a code-less address Etherscan has no creation record for.

Revision ID: a4d2f8c6e1b9
Revises: f1a7c3e9d2b4
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "a4d2f8c6e1b9"
down_revision: Union[str, Sequence[str], None] = "f1a7c3e9d2b4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("contract_creation_witnesses", sa.Column("no_creation_record_block", sa.BigInteger(), nullable=True))


def downgrade() -> None:
    op.drop_column("contract_creation_witnesses", "no_creation_record_block")
