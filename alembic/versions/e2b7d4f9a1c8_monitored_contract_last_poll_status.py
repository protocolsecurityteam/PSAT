"""monitored_contracts.last_poll_status — per-entry poll outcome map

Revision ID: e2b7d4f9a1c8
Revises: d3f1a86c204b
Create Date: 2026-07-29

``last_poll_status`` records, per polling-plan ``field``, how that entry's
most recent dispatched poll call ended: ``"ok"`` (the RPC call returned a
result) or ``"error"`` (the call carried a per-call JSON-RPC error, e.g. a
revert). A field absent from the map was not polled. This keeps the three
states apart on the served surface — before it, a reverting entry was
indistinguishable from one that had never been polled, because
``last_known_state`` only ever holds successfully decoded values.

Additive; NULL means no poll pass has run against the row since the column
landed.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "e2b7d4f9a1c8"
down_revision: Union[str, Sequence[str], None] = "d3f1a86c204b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "monitored_contracts",
        sa.Column(
            "last_poll_status",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("monitored_contracts", "last_poll_status")
