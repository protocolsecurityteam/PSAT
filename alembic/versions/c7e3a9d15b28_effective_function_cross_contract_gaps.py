"""effective_functions.cross_contract_gaps: body calls whose cross-contract claims are not determined

Revision ID: c7e3a9d15b28
Revises: aa9f6ba5b7df

Existing rows stay NULL (not evaluated) until their job's next policy run.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "c7e3a9d15b28"
down_revision: Union[str, Sequence[str], None] = "aa9f6ba5b7df"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "effective_functions",
        sa.Column(
            "cross_contract_gaps",
            postgresql.JSONB(),
            nullable=True,
            comment=(
                "Body calls whose callee resolves to an address with no readable facts, so their cross-contract "
                "claims are not determined: [{sink_id, selector, callee, reason, callee_job_id}]. SQL NULL = not "
                "evaluated; [] = every resolved callee had facts."
            ),
        ),
    )


def downgrade() -> None:
    op.drop_column("effective_functions", "cross_contract_gaps")
