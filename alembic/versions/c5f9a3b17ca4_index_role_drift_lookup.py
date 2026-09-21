"""Index case-insensitive role drift lookups without blocking event writers."""

from alembic import op

revision = "c5f9a3b17ca4"
down_revision = "c4e8f2a06b93"
branch_labels = None
depends_on = None


def upgrade():
    # Own revision: failure building the concurrent index must not require
    # replaying already-committed queue/trigger DDL. Remove an invalid index
    # left by an interrupted build before retrying.
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS ix_indexed_event_logs_role_lookup")
        op.execute(
            "CREATE INDEX CONCURRENTLY ix_indexed_event_logs_role_lookup "
            "ON indexed_event_logs(chain_id,lower(event_address),topic0,block_number)"
        )


def downgrade():
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS ix_indexed_event_logs_role_lookup")
