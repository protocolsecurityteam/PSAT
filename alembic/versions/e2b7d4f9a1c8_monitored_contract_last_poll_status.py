"""monitored_contracts.last_poll_status — per-entry poll outcome map

Revision ID: e2b7d4f9a1c8
Revises: d3f1a86c204b
Create Date: 2026-07-29

``last_poll_status`` records, per polling-plan ``field``, how that entry's
most recent ANSWERED poll call ended: ``"ok"`` (the result parsed as the
entry's declared type — including the type's conventional empty such as
the zero address; only non-empty values reach ``last_known_state``),
``"error"`` (the node answered this call with a per-call JSON-RPC error,
e.g. a revert), or ``"no_value"`` (the call answered without error but
returned nothing that parses as the declared type — empty ``0x`` / short
body). A field absent from the map was not polled. The map is
written only from batches the node actually answered — a wholesale
transport failure publishes nothing and leaves the row unstamped — so it
never reports liveness the poller did not observe. This keeps the states
apart on the served surface: before it, a dead entry was indistinguishable
from one that had never been polled, because ``last_known_state`` only ever
holds successfully decoded values.

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
