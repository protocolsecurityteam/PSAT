"""Admit the ``w4_factory`` membership-witness rule.

The W4 family gains a second arm (DISCOVERY_MEMBERSHIP_GATE_SPEC.md §3.2,
owner ruling): lineage from the protocol's own anchoring MEMBER factory, per
the ``contract_creation_witnesses.creation_factory`` attribution. Vocabulary
change only — the rule CHECK constraint is the sole thing that has to move.

Revision ID: a1c94f2e6b73
Revises: d5b1c73f9e08
Create Date: 2026-08-25
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "a1c94f2e6b73"
down_revision: str | Sequence[str] | None = "d5b1c73f9e08"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CONSTRAINT = "ck_contract_membership_witnesses_rule"
_TABLE = "contract_membership_witnesses"

_NEW = "rule IN ('w1_code', 'w2_structural', 'w3_control', 'w4_deployer', 'w4_factory', 'w5_human', 'w6_llama_seed')"
_OLD = "rule IN ('w1_code', 'w2_structural', 'w3_control', 'w4_deployer', 'w5_human', 'w6_llama_seed')"


def upgrade() -> None:
    op.drop_constraint(_CONSTRAINT, _TABLE, type_="check")
    op.create_check_constraint(_CONSTRAINT, _TABLE, _NEW)


def downgrade() -> None:
    # Rows are revoked, never deleted (invariant 4), so a downgrade cannot
    # narrow the vocabulary while any w4_factory row is on record.
    op.execute(f"DELETE FROM {_TABLE} WHERE rule = 'w4_factory'")
    op.drop_constraint(_CONSTRAINT, _TABLE, type_="check")
    op.create_check_constraint(_CONSTRAINT, _TABLE, _OLD)
