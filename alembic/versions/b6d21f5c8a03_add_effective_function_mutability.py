"""Persist the state-mutability witness on effective_functions

``effective_functions`` had no view/pure/nonpayable column at all, so the only
way to ask "does this function write state" was ``effect_targets``, which
concatenates state-write variable names with dotted external-call heads. On this
database 501 of the 1642 rows with a populated ``effect_targets`` carry only
dotted heads — the column asserts a state write on 30.5% of them where none was
ever proven.

The effects stage already computes all four facts per function
(``effects.py`` ``EffectInfo``: ``sinks``, ``state_writes``, ``state_changing``,
``writer_selectors``) and all four are present on 2415/2415 function records
across the 107 stored ``effects`` artifacts. They were discarded at the DB
boundary. These columns stop discarding them.

All four are NULLABLE on purpose. NULL means NOT DETERMINED, and it is a
different fact from ``state_writes=[]`` / ``state_changing=false``, which mean
the effects stage looked and proved none. Three shapes reach it, all measured
against the same 2415 records (see ``_mutability_fields``):

* no effects record covered the signature — what the one production caller
  produces whenever the effects artifact is absent (0 such jobs here, but the
  branch is live: ``policy_worker`` logs ``missing_semantic_inputs`` and
  continues);
* ``fallback`` / ``receive`` — 36 records, 15 of them carrying a proven state
  write. Their ``state_changing=false`` means "no selector", not "proven
  non-mutating": WETH9's ``fallback()`` writes ``balanceOf``;
* a view/pure entry point whose derived writes contradict the compiler — 100
  records, e.g. ``paused()`` "writing" ``PausableStorageLocation``.

Existing rows stay NULL: they were written by a pipeline that did not record the
field, and backfilling them with a default would manufacture exactly the
proven-absent claim this column exists to stop.

Revision ID: b6d21f5c8a03
Revises: a17c4e90b3d2
Create Date: 2026-07-27

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "b6d21f5c8a03"
down_revision: str | Sequence[str] | None = "a17c4e90b3d2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("effective_functions", sa.Column("state_changing", sa.Boolean(), nullable=True))
    op.add_column("effective_functions", sa.Column("state_writes", postgresql.JSONB(), nullable=True))
    op.add_column("effective_functions", sa.Column("sinks", postgresql.JSONB(), nullable=True))
    op.add_column(
        "effective_functions",
        sa.Column("writer_selectors", postgresql.ARRAY(sa.String(length=10)), nullable=True),
    )
    for column, comment in (
        (
            "state_changing",
            "ABI mutability of a selector-bearing external/public entry point: true when "
            "non-view and non-pure. SQL NULL = not determined and is NOT the same fact as "
            "false; fallback/receive are always NULL here because they have no selector, "
            "which is a different reason from being proven non-mutating.",
        ),
        (
            "state_writes",
            "Proven state writes, richer than the state_write sinks (member path, "
            "granularity, hygiene class). SQL NULL = not determined; [] = the effects "
            "stage looked and proved none.",
        ),
        (
            "sinks",
            "Kind-tagged sinks (state_write | external_call | delegatecall | "
            "contract_creation | selfdestruct) with body/guard origin. Kept alongside "
            "state_writes because a function can be a proven actor with zero state "
            "writes -- EtherFiRedemptionManager.sweepDust moves tokens under a role gate "
            "with state_writes=[]. SQL NULL = not determined; [] = proven none.",
        ),
        (
            "writer_selectors",
            "Selectors to replay when attributing the state writes of this function; empty "
            "when it writes no state. SQL NULL = not determined.",
        ),
    ):
        escaped = comment.replace("'", "''")
        op.execute(f"COMMENT ON COLUMN effective_functions.{column} IS '{escaped}'")


def downgrade() -> None:
    op.drop_column("effective_functions", "writer_selectors")
    op.drop_column("effective_functions", "sinks")
    op.drop_column("effective_functions", "state_writes")
    op.drop_column("effective_functions", "state_changing")
