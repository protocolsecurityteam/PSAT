"""Add replace-in-place prepared company responses.

Revision ID: c8a41e6d2b90
Revises: b3d7e1f05a92
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "c8a41e6d2b90"
down_revision = "b3d7e1f05a92"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "company_page_snapshots",
        sa.Column("protocol_id", sa.Integer(), sa.ForeignKey("protocols.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("company_name", sa.String(255)),
        sa.Column("version", sa.String(100)),
        sa.Column("source_started_at", sa.DateTime(timezone=True)),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("overview_gzip", sa.LargeBinary()),
        sa.Column("functions_gzip", sa.LargeBinary()),
        sa.Column("dirty_token", postgresql.UUID(as_uuid=True)),
        sa.Column("built_token", postgresql.UUID(as_uuid=True)),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
    )


def downgrade() -> None:
    op.drop_table("company_page_snapshots")
