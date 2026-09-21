"""Durable worker boot identity and queue-aware drain coordination."""

from alembic import op

revision = "c6a10d82e5b7"
down_revision = "c5f9a3b17ca4"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        CREATE TABLE worker_lifecycle (
            id integer PRIMARY KEY CHECK (id = 1),
            boot_id uuid,
            machine_id text,
            phase text NOT NULL DEFAULT 'stopped'
                CHECK (phase IN ('running', 'draining', 'stopped')),
            started_at timestamptz,
            heartbeat_at timestamptz,
            last_work_at timestamptz,
            idle_since timestamptz,
            next_start_at timestamptz,
            paused boolean NOT NULL DEFAULT true
        );
        INSERT INTO worker_lifecycle (id) VALUES (1);
    """)


def downgrade():
    op.drop_table("worker_lifecycle")
