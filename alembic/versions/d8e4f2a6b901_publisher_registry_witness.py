"""Add an explicit publisher-registry membership witness.

Revision ID: d8e4f2a6b901
Revises: c3d9e5a1f7b2
"""

from alembic import op

revision = "d8e4f2a6b901"
down_revision = "c3d9e5a1f7b2"
branch_labels = None
depends_on = None

_EXISTING = "'w1_code', 'w2_structural', 'w3_control', 'w4_deployer', 'w4_factory', 'w4h_deployer_affinity', 'w5_human', 'w6_llama_seed'"
_CONSTRAINT = "ck_contract_membership_witnesses_rule"


def upgrade():
    op.drop_constraint(_CONSTRAINT, "contract_membership_witnesses", type_="check")
    op.create_check_constraint(
        _CONSTRAINT, "contract_membership_witnesses", f"rule IN ({_EXISTING}, 'w7_publisher_registry')"
    )
    # The previous classifier inferred this label from an unmatched report-wide fix SHA,
    # without proving ancestry or finding relevance. Keep the source match, withdraw the claim.
    op.execute("UPDATE audit_contract_coverage SET proof_kind = 'unclassified' WHERE proof_kind = 'pre_fix_unpatched'")


def downgrade():
    # Refuse to erase membership provenance on downgrade. Remove W7 through explicit
    # membership reconciliation first; the old constraint then verifies the database.
    op.drop_constraint(_CONSTRAINT, "contract_membership_witnesses", type_="check")
    op.create_check_constraint(_CONSTRAINT, "contract_membership_witnesses", f"rule IN ({_EXISTING})")
