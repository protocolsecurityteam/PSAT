"""W4-H heuristic deployer lineage: trust class H, witness rule, challenges.

DEPLOYER_HEURISTIC_SPEC.md §8. Three schema deltas in one migration: the
``protocol_deployers.trust_class`` vocabulary gains ``'H'``, the
``contract_membership_witnesses.rule`` vocabulary gains
``'w4h_deployer_affinity'``, and ``deployer_affinity_challenges`` (§5) is
created — one row per observed foreign anchor, from which the H row's
active/frozen/suspended/revoked state is derived.

Revision ID: b3d7e1f05a92
Revises: a1c94f2e6b73
Create Date: 2026-08-25
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b3d7e1f05a92"
down_revision: str | Sequence[str] | None = "a1c94f2e6b73"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_RULE_CONSTRAINT = "ck_contract_membership_witnesses_rule"
_RULE_TABLE = "contract_membership_witnesses"
_RULE_NEW = (
    "rule IN ('w1_code', 'w2_structural', 'w3_control', 'w4_deployer', 'w4_factory', "
    "'w4h_deployer_affinity', 'w5_human', 'w6_llama_seed')"
)
_RULE_OLD = (
    "rule IN ('w1_code', 'w2_structural', 'w3_control', 'w4_deployer', 'w4_factory', 'w5_human', 'w6_llama_seed')"
)

_CLASS_CONSTRAINT = "ck_protocol_deployers_trust_class"
_CLASS_TABLE = "protocol_deployers"


def upgrade() -> None:
    op.drop_constraint(_CLASS_CONSTRAINT, _CLASS_TABLE, type_="check")
    op.create_check_constraint(_CLASS_CONSTRAINT, _CLASS_TABLE, "trust_class IN ('A', 'B', 'H')")

    op.drop_constraint(_RULE_CONSTRAINT, _RULE_TABLE, type_="check")
    op.create_check_constraint(_RULE_CONSTRAINT, _RULE_TABLE, _RULE_NEW)

    op.create_table(
        "deployer_affinity_challenges",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("protocol_deployer_id", sa.Integer(), nullable=False),
        sa.Column("contract_id", sa.Integer(), nullable=False),
        sa.Column("foreign_protocol_id", sa.Integer(), nullable=False),
        sa.Column("foreign_witness_id", sa.Integer(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["protocol_deployer_id"], ["protocol_deployers.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["contract_id"], ["contracts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["foreign_protocol_id"], ["protocols.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["foreign_witness_id"], ["contract_membership_witnesses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "protocol_deployer_id",
            "contract_id",
            "foreign_witness_id",
            name="uq_deployer_affinity_challenge_observation",
        ),
    )
    op.create_index(
        "ix_deployer_affinity_challenges_deployer", "deployer_affinity_challenges", ["protocol_deployer_id"]
    )
    op.create_index("ix_deployer_affinity_challenges_witness", "deployer_affinity_challenges", ["foreign_witness_id"])


def downgrade() -> None:
    op.drop_index("ix_deployer_affinity_challenges_witness", table_name="deployer_affinity_challenges")
    op.drop_index("ix_deployer_affinity_challenges_deployer", table_name="deployer_affinity_challenges")
    op.drop_table("deployer_affinity_challenges")

    # The vocabulary narrows only after nothing rests on it: heuristic-derived
    # W2 rows and memberships whose only admission was heuristic are unwound
    # first, so no surviving row can present heuristic evidence as proven.
    op.execute(f"DELETE FROM {_RULE_TABLE} WHERE rule = 'w2_structural' AND evidence->>'heuristic_via' = 'true'")
    op.execute(
        "UPDATE contracts c SET protocol_id = NULL "
        "WHERE c.protocol_id IS NOT NULL "
        "  AND NOT EXISTS ("
        f"    SELECT 1 FROM {_RULE_TABLE} w"
        "     WHERE w.contract_id = c.id"
        "       AND w.protocol_id = c.protocol_id"
        "       AND w.revoked_at IS NULL"
        "       AND w.rule IN ('w2_structural', 'w3_control', 'w4_deployer', "
        "'w4_factory', 'w5_human', 'w6_llama_seed')"
        ")"
    )

    # Rows are revoked, never deleted (gate invariant 4), so the vocabulary can
    # only narrow once the heuristic layer's rows are gone.
    op.execute(f"DELETE FROM {_RULE_TABLE} WHERE rule = 'w4h_deployer_affinity'")
    op.drop_constraint(_RULE_CONSTRAINT, _RULE_TABLE, type_="check")
    op.create_check_constraint(_RULE_CONSTRAINT, _RULE_TABLE, _RULE_OLD)

    op.execute(f"DELETE FROM {_CLASS_TABLE} WHERE trust_class = 'H'")
    op.drop_constraint(_CLASS_CONSTRAINT, _CLASS_TABLE, type_="check")
    op.create_check_constraint(_CLASS_CONSTRAINT, _CLASS_TABLE, "trust_class IN ('A', 'B')")
