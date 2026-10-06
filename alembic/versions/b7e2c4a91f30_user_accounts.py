"""user accounts (Neon Auth identities), sessions, saved webhooks, and owned subscriptions

Revision ID: b7e2c4a91f30
Revises: c7e3a9d15b28

Existing subscriptions keep their inline URL and no owner; account-created rows point at a saved webhook instead.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "b7e2c4a91f30"
down_revision: Union[str, Sequence[str], None] = "c7e3a9d15b28"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("neon_auth_id", sa.String(), nullable=True, unique=True),
        sa.Column("email", sa.String(), nullable=False, unique=True),
        sa.Column("email_verified", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("display_name", sa.String(), nullable=True),
        sa.Column("avatar_url", sa.String(), nullable=True),
        sa.Column("is_admin", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "user_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("token_hash", sa.String(length=64), nullable=False, unique=True),
        sa.Column(
            "user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"])
    op.create_table(
        "user_webhooks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("label", sa.String(), nullable=True),
        sa.Column("discord_webhook_url", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_user_webhooks_user_id", "user_webhooks", ["user_id"])

    op.add_column(
        "protocol_subscriptions",
        sa.Column(
            "user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True
        ),
    )
    op.add_column(
        "protocol_subscriptions",
        sa.Column(
            "webhook_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("user_webhooks.id", ondelete="CASCADE"),
            nullable=True,
        ),
    )
    op.create_index("ix_protocol_subscriptions_user_id", "protocol_subscriptions", ["user_id"])
    op.create_check_constraint(
        "ck_protocol_subscriptions_one_target",
        "protocol_subscriptions",
        "discord_webhook_url IS NULL OR webhook_id IS NULL",
    )


def downgrade() -> None:
    op.drop_constraint("ck_protocol_subscriptions_one_target", "protocol_subscriptions", type_="check")
    op.drop_index("ix_protocol_subscriptions_user_id", table_name="protocol_subscriptions")
    op.drop_column("protocol_subscriptions", "webhook_id")
    op.drop_column("protocol_subscriptions", "user_id")
    op.drop_table("user_webhooks")
    op.drop_table("user_sessions")
    op.drop_table("users")
