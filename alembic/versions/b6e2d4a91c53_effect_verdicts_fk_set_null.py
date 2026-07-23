"""effect_verdicts.function_id FK: CASCADE -> SET NULL

Revision ID: b6e2d4a91c53
Revises: d8f3a1c02e47
Create Date: 2026-07-22 00:00:00.000000

Effect verdicts are durable state-plane residue keyed on the deployment
coordinates ``(chain_id, contract_address, selector, effect_class)``;
``function_id`` is a convenience join to the current ``effective_functions``
row. Policy's row replace (delete+recreate) must therefore unlink verdicts,
not destroy them — CASCADE silently erased proven witnesses on every policy
re-run and left carried ``behavioral_observed`` claims pointing at deleted
verdict rows. The column is already nullable, so this is a constraint swap
only.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "b6e2d4a91c53"
down_revision: Union[str, Sequence[str], None] = "d8f3a1c02e47"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_FK = "effect_verdicts_function_id_fkey"


def upgrade() -> None:
    op.drop_constraint(_FK, "effect_verdicts", type_="foreignkey")
    op.create_foreign_key(
        _FK,
        "effect_verdicts",
        "effective_functions",
        ["function_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(_FK, "effect_verdicts", type_="foreignkey")
    op.create_foreign_key(
        _FK,
        "effect_verdicts",
        "effective_functions",
        ["function_id"],
        ["id"],
        ondelete="CASCADE",
    )
