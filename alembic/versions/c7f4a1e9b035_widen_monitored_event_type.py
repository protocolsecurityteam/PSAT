"""Widen monitored_events.event_type to 100 chars

The witness taxonomy mints ``value_changed:<controller_id>`` and
``member_changed:<mapping_var>``. A real controller id already overflows the
old 50-char column — ``value_changed:state_variable:accountantState.
payoutAddress`` is 57 — and a truncated controller id names a DIFFERENT slot,
so the column has to hold the whole identity rather than the code trimming it.

``uq_monitored_events_identity`` (partial, ``WHERE log_index IS NOT NULL``)
covers this column; Postgres rebuilds the dependent index as part of the type
change, so no explicit drop/recreate is needed.

Revision ID: c7f4a1e9b035
Revises: b3d51c9a7e28
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "c7f4a1e9b035"
down_revision = "b3d51c9a7e28"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "monitored_events",
        "event_type",
        existing_type=sa.String(length=50),
        type_=sa.String(length=100),
        existing_nullable=False,
    )


def downgrade() -> None:
    # Narrowing would truncate any minted long type, so drop the rows that
    # cannot survive the old width rather than silently rewrite their identity.
    op.execute("DELETE FROM monitored_events WHERE length(event_type) > 50")
    op.alter_column(
        "monitored_events",
        "event_type",
        existing_type=sa.String(length=100),
        type_=sa.String(length=50),
        existing_nullable=False,
    )
