"""contract_materializations.deterministic_failure.

Revision ID: e6f9b3d5a2c7
Revises: d5e8a2c4f1b6

Marks a failed build that rebuilding the same source under the same analyzer would repeat, so nested builds stop
retrying it.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "e6f9b3d5a2c7"
down_revision: Union[str, Sequence[str], None] = "d5e8a2c4f1b6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "contract_materializations",
        sa.Column("deterministic_failure", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("contract_materializations", "deterministic_failure")
