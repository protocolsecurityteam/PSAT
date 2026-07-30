"""drop contract_summaries.risk_level — the detector pass that fed it is gone

Revision ID: a7e4c2b81f05
Revises: c4b81e2a90fd
Create Date: 2026-07-28

``risk_level`` was derived from the Slither CLI **detector** pass. That
subprocess was removed from the pipeline in Apr 2026 when vulnerability-detector
triage was split out of PSAT; the reader that loaded ``slither_results.json``
survived the removal and kept publishing a value for a pass that never ran
(``unknown`` on 92/92 local rows — the same value a clean run would have
produced). The reader is now deleted, so nothing writes this column and no
consumer reads it.

The column carries no recoverable signal: every stored value was produced by
the vestigial reader, not by a detector run. Dropping it removes the last place
a reader could mistake "never analysed" for "analysed, nothing found".

``downgrade`` re-adds it nullable and empty — the values are not restorable
because the producer no longer exists.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "a7e4c2b81f05"
down_revision: Union[str, Sequence[str], None] = "c4b81e2a90fd"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_column("contract_summaries", "risk_level")


def downgrade() -> None:
    op.add_column("contract_summaries", sa.Column("risk_level", sa.String(length=20), nullable=True))
