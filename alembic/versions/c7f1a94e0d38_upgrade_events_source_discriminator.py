"""upgrade_events.source — which writer produced the row

Revision ID: c7f1a94e0d38
Revises: b6d21f5c8a03
Create Date: 2026-07-27

``upgrade_events`` has three writers — the upgrade-history artifact projection,
the log scanner, and the storage-slot poller — and until now no column said
which one wrote a row. That collapsed a distinction that matters on two
columns at once:

* ``old_impl`` is NULL on 189/189 rows because the backfiller hardcodes it,
  while the watcher populates it. NULL therefore means both "this writer does
  not record predecessors" and "there was no predecessor".
* ``timestamp`` is an on-chain block timestamp for artifact/log rows, and a
  detection time for poll rows (no block is knowable there). Same column, two
  readings, previously indistinguishable.

Additive and deliberately **not** backfilled. The 189 existing rows were
almost certainly written by the artifact projection, but "almost certainly" is
not a witness: NULL is the honest third state for a row whose writer this
migration cannot prove. Consumers must treat NULL as unknown, not as a synonym
for any of the three values.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "c7f1a94e0d38"
down_revision: Union[str, Sequence[str], None] = "b6d21f5c8a03"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("upgrade_events", sa.Column("source", sa.String(length=20), nullable=True))


def downgrade() -> None:
    op.drop_column("upgrade_events", "source")
