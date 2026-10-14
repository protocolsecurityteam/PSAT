"""Withdraw unsupported unpatched labels without erasing source equivalence.

Revision ID: d8e4f2a6b901
Revises: c3d9e5a1f7b2
"""

from alembic import op

revision = "d8e4f2a6b901"
down_revision = "c3d9e5a1f7b2"
branch_labels = None
depends_on = None


def upgrade():
    # An unmatched report-wide fix SHA did not prove ancestry or finding relevance.
    op.execute("UPDATE audit_contract_coverage SET proof_kind = 'unclassified' WHERE proof_kind = 'pre_fix_unpatched'")


def downgrade():
    # Unsupported claims cannot be reconstructed as facts.
    pass
