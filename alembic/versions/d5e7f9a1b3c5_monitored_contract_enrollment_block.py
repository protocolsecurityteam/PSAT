"""monitored_contracts.enrollment_block — pre-enrollment notification floor

Revision ID: d5e7f9a1b3c5
Revises: c4d6e8f0a1b3
Create Date: 2026-07-09

``enrollment_block`` is a stable per-contract floor — seeded once at enrollment,
never advanced — below which the scanner records an event as history without
notifying or reanalyzing. A cohort scans from its MIN member cursor, so a
low-cursor cohort-mate can drag the getLogs window below a high-cursor
contract's own frontier; the floor keeps those pre-watch events from surfacing
as fresh detections.

Additive. Existing rows are backfilled from ``last_scanned_block`` (the scan
frontier): everything below that has either already been processed or predates
where the contract had been scanned, so suppressing a re-detection below it is
correct, while the frontier and beyond keep notifying. A NULL floor disables
suppression (notify), so the change can never suppress a real event on a row it
couldn't stamp.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "d5e7f9a1b3c5"
down_revision: Union[str, Sequence[str], None] = "c4d6e8f0a1b3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("monitored_contracts", sa.Column("enrollment_block", sa.BigInteger(), nullable=True))
    op.execute("UPDATE monitored_contracts SET enrollment_block = last_scanned_block WHERE enrollment_block IS NULL")


def downgrade() -> None:
    op.drop_column("monitored_contracts", "enrollment_block")
