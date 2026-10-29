"""Add the auxiliary logic worker stage to the existing durable queue.

Revision ID: a38e901c6d72
Revises: 868a58959f73
"""

from alembic import op

revision = "a38e901c6d72"
down_revision = "868a58959f73"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE jobstage ADD VALUE IF NOT EXISTS 'logic' BEFORE 'done'")


def downgrade() -> None:
    # Stop/drain logic workers before rollback. Preserve job/artifact history and mark unexecuted work terminal.
    op.execute(
        "UPDATE jobs SET status='failed_terminal', detail='Logic worker migration rolled back', "
        "lease_id=NULL, lease_expires_at=NULL, worker_id=NULL WHERE stage='logic'"
    )
    op.execute("UPDATE jobs SET stage='done' WHERE stage='logic'")
    op.execute("UPDATE job_dependencies SET required_stage='done' WHERE required_stage='logic'")
    # Keep the now-unused enum member. Rebuilding the enum would require tearing down existing
    # stage-dependent triggers; the older application never reads a row with this retired value.
