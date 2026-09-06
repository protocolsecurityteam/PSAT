"""Add rolling-compatible local compute routing.

Revision ID: c8a6f20d913e
Revises: b3d7e1f05a92
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "c8a6f20d913e"
down_revision = "b3d7e1f05a92"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("jobs", sa.Column("compute_target", sa.String(), server_default="cloud", nullable=True))
    op.add_column(
        "jobs",
        sa.Column("compute_group_id", postgresql.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=True),
    )
    op.execute("UPDATE jobs SET compute_target = 'cloud', compute_group_id = id")
    op.create_check_constraint("ck_jobs_compute_target", "jobs", "compute_target IN ('cloud', 'local')")
    op.alter_column("jobs", "compute_target", nullable=False)
    op.alter_column("jobs", "compute_group_id", nullable=False)
    with op.get_context().autocommit_block():
        op.create_index(
            "ix_jobs_compute_claim",
            "jobs",
            ["compute_target", "stage", "status", "created_at"],
            postgresql_concurrently=True,
        )
        op.create_index("ix_jobs_compute_group_id", "jobs", ["compute_group_id"], postgresql_concurrently=True)


def downgrade():
    # Operational rollback keeps this schema; this explicit downgrade is for
    # disposable databases only after every binary has stopped using the fields.
    op.drop_index("ix_jobs_compute_group_id", table_name="jobs")
    op.drop_index("ix_jobs_compute_claim", table_name="jobs")
    op.drop_constraint("ck_jobs_compute_target", "jobs", type_="check")
    op.drop_column("jobs", "compute_group_id")
    op.drop_column("jobs", "compute_target")
