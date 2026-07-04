"""add claims JSONB to effective_functions

Revision ID: c7d1e9a4b2f8
Revises: f1a2b3c4d5e6
Create Date: 2026-07-03

Plane-1 of the effect-labels redesign: the semantic vocabulary reborn as typed
claim objects ``{claim_id, tier, witness}``, dual-written alongside the legacy
``effect_labels`` array so consumers migrate on their own schedule. NULL by
default; rows written before the claims plane read as "no claims", and the next
protocol run recomputes them.

Schema-only. The producer (``services/static/claims``) and the dual-write in
``services/policy/effective_permissions.py`` land with this migration.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "c7d1e9a4b2f8"
down_revision: Union[str, Sequence[str], None] = "f1a2b3c4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "effective_functions",
        sa.Column("claims", postgresql.JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("effective_functions", "claims")
