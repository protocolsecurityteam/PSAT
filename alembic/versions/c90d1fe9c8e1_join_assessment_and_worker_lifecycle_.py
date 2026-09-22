"""Join the Assessment and worker lifecycle migration histories.

The two branches were developed independently. Keep both applied histories
intact so databases already at the worker lifecycle head can still run the
Assessment cutover migration before reaching this revision.
"""

revision = "c90d1fe9c8e1"
down_revision = ("a8c2d4e6f901", "c6a10d82e5b7")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
