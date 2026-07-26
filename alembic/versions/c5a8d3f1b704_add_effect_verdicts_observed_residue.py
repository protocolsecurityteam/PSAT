"""add effect_verdicts.observed_residue

State-plane observation residue that has no dedicated column: the §5b downstream
value-reach figures (holder addresses + their USD) and the bookkeeping that
bounds the hit-path residue re-probe.

These lived in ``ObservedEffect.details`` and therefore in
``effect_behavior_cache.details`` — a CROSS-DEPLOYMENT code-plane row (inv. 3),
so one contract's holder addresses and USD were re-published as another's on
every cache hit. They belong here, beside ``concrete_destination``, keyed on the
deployment coordinates.

Revision ID: c5a8d3f1b704
Revises: c4f7b1e9a206
"""

from collections.abc import Sequence
from typing import Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "c5a8d3f1b704"
down_revision: Union[str, Sequence[str], None] = "c4f7b1e9a206"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "effect_verdicts",
        sa.Column("observed_residue", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("effect_verdicts", "observed_residue")
