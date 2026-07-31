"""indexed_event_cursors: lower bound, enrollment basis, per-window page stats

Revision ID: a3e7c1d9b840
Revises: b6d5e1c07a94
Create Date: 2026-07-30

``backfill_complete`` bounds a cursor from ABOVE. Nothing bounded it from below,
and nothing recorded whether the pages it folded came back whole, so "this event
has never fired" rested on two unproven assumptions. Six additive nullable
columns record what was actually witnessed:

* ``first_indexed_block`` / ``first_indexed_block_basis`` — the covered range's
  lower bound and its proof.
* ``enrollment_basis`` — whether the row was minted from a static writer hint
  (variable-attributed) or asserted from a monitoring tracking plan (not).
* ``max_window_log_count`` / ``window_stats_cap`` / ``window_stats_basis`` — the
  largest page accepted, the result cap in force at the time, and whether the
  record runs continuously from the lower bound.

Additive, and deliberately WITHOUT a backfill of the first three: a value
recovered now from a cache is not a value that was witnessed then, so every
pre-existing row keeps NULL and reads as "lower bound unknown" / "enrollment
basis unknown". The one UPDATE stamps ``window_stats_basis`` with
``unmeasured_legacy``, which moves those rows toward not_determined (their
windows were fetched before any count was recorded and can never be promoted),
never toward a claim.

Wave-2 migration chain position 3: it follows the upgrade-executor-fold
revision (``c4f8a1d92b07``) and precedes the restaking-position revision.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "a3e7c1d9b840"
down_revision: Union[str, Sequence[str], None] = "c4f8a1d92b07"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("indexed_event_cursors", sa.Column("first_indexed_block", sa.BigInteger(), nullable=True))
    op.add_column("indexed_event_cursors", sa.Column("first_indexed_block_basis", sa.String(length=32), nullable=True))
    op.add_column("indexed_event_cursors", sa.Column("enrollment_basis", sa.String(length=32), nullable=True))
    op.add_column("indexed_event_cursors", sa.Column("max_window_log_count", sa.BigInteger(), nullable=True))
    op.add_column("indexed_event_cursors", sa.Column("window_stats_cap", sa.BigInteger(), nullable=True))
    op.add_column("indexed_event_cursors", sa.Column("window_stats_basis", sa.String(length=48), nullable=True))
    # Existing rows folded their windows before any page count was recorded, so
    # no re-fold can ever reconstruct them: mark them never-measured rather than
    # leaving NULL, which the writer path uses for "not yet stamped this pass".
    # ``max_window_log_count`` and ``window_stats_cap`` stay NULL — there is no
    # measurement to record and a zero would read as a measured empty page.
    op.execute("UPDATE indexed_event_cursors SET window_stats_basis = 'unmeasured_legacy'")


def downgrade() -> None:
    op.drop_column("indexed_event_cursors", "window_stats_basis")
    op.drop_column("indexed_event_cursors", "window_stats_cap")
    op.drop_column("indexed_event_cursors", "max_window_log_count")
    op.drop_column("indexed_event_cursors", "enrollment_basis")
    op.drop_column("indexed_event_cursors", "first_indexed_block_basis")
    op.drop_column("indexed_event_cursors", "first_indexed_block")
