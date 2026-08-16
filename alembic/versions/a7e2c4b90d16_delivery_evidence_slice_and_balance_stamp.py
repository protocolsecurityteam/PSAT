"""Two columns that let the delivery scan skip a pair and resume a slice.

``observed_balance_raw`` is the holder's raw balance of the token as the cycle
that last scanned the pair read it. It is a SKIP key, never evidence: an unmoved
balance is what lets the next cycle leave the pair's extent where it is, because
a new delivery necessarily moves the balance the monitor already reads. NULL is
deliberately NOT "unchanged" — a legacy row was never stamped, so it is scanned
once more and stamped then.

``caught_up`` is false when the writing pass stopped at a slice boundary below
the chain head. A range-capped chain (optimism serves 10,000 blocks per
``eth_getLogs``) cannot reach the tip inside one cycle's request budget, so the
scan now records the slice it did prove and resumes above it next cycle; the row
says which of the two it is, and a sliced row keeps being scanned forward
whatever its balance does. Legacy rows default TRUE because every pass that
wrote them ran through its own cycle's head.

Neither column moves a verdict. ``delivery_shape`` stays the all-quantifier over
``scanned_from_block..measured_through_block``, which is the row's own extent.

Revision ID: a7e2c4b90d16
Revises: d4f1a7c62b90
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "a7e2c4b90d16"
down_revision = "d4f1a7c62b90"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("token_delivery_evidence", sa.Column("observed_balance_raw", sa.Text(), nullable=True))
    op.add_column(
        "token_delivery_evidence",
        sa.Column("caught_up", sa.Boolean(), nullable=False, server_default=sa.text("true")),
    )


def downgrade() -> None:
    op.drop_column("token_delivery_evidence", "caught_up")
    op.drop_column("token_delivery_evidence", "observed_balance_raw")
