"""controller_values.authority_provenance — gate vs callee

Revision ID: a1f7c30b62d9
Revises: c7f1a94e0d38
Create Date: 2026-07-27

``build_controller_tracking`` unioned two different facts into one set:

    authority_state_vars = _collect_authority_state_vars(predicate_trees)
                           | external_contract_vars_from_effects

The left side means *the caller is checked against this address*; the right
side means *this address gets called*. Both were then typed
``external_contract``, so ``eETH``, ``lido``, ``stETH`` and ``liquidityPool``
were published as controllers of the contracts that merely call them.

This column carries the distinction onto the row: ``caller_gate`` (a predicate
leaf gates on it, or delegates its authority check to it) vs ``call_target``
(an ``external_call`` sink invokes it and no gate was proven).

Additive and deliberately **not** backfilled. Existing rows were written by a
build that never computed the distinction, so NULL is the honest third state —
"not determined" — and consumers must not read it as either value. Rows
acquire a value on the next analysis run of their contract.

No chain predicate is needed or wanted: this column is a property of the
subject contract's source, reached through ``contract_id`` (chain-scoped via
``contracts.chain``). It carries no address of its own.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "a1f7c30b62d9"
down_revision: Union[str, Sequence[str], None] = "c7f1a94e0d38"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("controller_values", sa.Column("authority_provenance", sa.String(length=32), nullable=True))


def downgrade() -> None:
    op.drop_column("controller_values", "authority_provenance")
