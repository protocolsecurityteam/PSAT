"""add effects stage enum value + effect cache/verdict tables

Revision ID: d8f3a1c02e47
Revises: c2d5e8f1a4b7
Create Date: 2026-07-21 00:00:00.000000

EFFECTS_RESOLUTION_SPEC Phase 1. Additive only.

  - ``ALTER TYPE jobstage ADD VALUE 'effects' BEFORE 'coverage'`` MUST run in an
    ``autocommit_block`` — Postgres rejects ``ADD VALUE`` inside a transaction.
    ``BEFORE 'coverage'`` puts it at the right progression slot; idempotent via
    ``IF NOT EXISTS``. Two columns use the type (``jobs.stage``,
    ``job_dependencies.required_stage``) — the additive value needs no column
    rewrite, but the downgrade rebuild below alters both.
  - ``effect_behavior_cache`` / ``effect_verdicts`` are new tables (mirror the
    ``bytecode_cache`` create convention); needed so ``alembic check`` doesn't
    flag the new models as drift.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "d8f3a1c02e47"
down_revision: Union[str, Sequence[str], None] = "c2d5e8f1a4b7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ADD VALUE cannot run inside a transaction; opt this statement out of
    # Alembic's per-migration transaction wrapper.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE jobstage ADD VALUE IF NOT EXISTS 'effects' BEFORE 'coverage'")

    op.create_table(
        "effect_behavior_cache",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("behavior_hash", sa.String(length=80), nullable=False),
        sa.Column("effect_class", sa.String(length=40), nullable=False),
        sa.Column("scope", sa.String(length=20), server_default="kernel", nullable=False),
        sa.Column("contract_surface_hash", sa.String(length=80), server_default="", nullable=False),
        sa.Column("gate_ref", sa.String(length=255), server_default="", nullable=False),
        sa.Column("verdict", sa.String(length=20), nullable=False),
        sa.Column("tier", sa.String(length=20), nullable=False),
        sa.Column("transcript_ptr", sa.Text(), nullable=True),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("analysis_schema_version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("audit_status", sa.String(length=20), nullable=True),
        sa.Column("audit_peer_hash", sa.String(length=80), nullable=True),
        sa.Column("audited_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("hit_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "behavior_hash",
            "effect_class",
            "scope",
            "contract_surface_hash",
            "gate_ref",
            name="uq_effect_behavior_cache_identity",
        ),
    )
    op.create_index(
        "ix_effect_behavior_cache_behavior_class",
        "effect_behavior_cache",
        ["behavior_hash", "effect_class"],
        unique=False,
    )

    op.create_table(
        "effect_verdicts",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("function_id", sa.Integer(), nullable=True),
        sa.Column("chain_id", sa.Integer(), nullable=False),
        sa.Column("contract_address", sa.String(length=42), nullable=False),
        sa.Column("selector", sa.String(length=10), server_default="", nullable=False),
        sa.Column("effect_class", sa.String(length=40), nullable=False),
        sa.Column("behavior_hash", sa.String(length=80), nullable=True),
        sa.Column("verdict", sa.String(length=20), nullable=False),
        sa.Column("tier", sa.String(length=20), nullable=False),
        sa.Column("concrete_destination", sa.String(length=42), nullable=True),
        sa.Column("current_check_passed", sa.Boolean(), nullable=True),
        sa.Column("witness", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("transcript_ptr", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.ForeignKeyConstraint(["function_id"], ["effective_functions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "chain_id",
            "contract_address",
            "selector",
            "effect_class",
            name="uq_effect_verdicts_identity",
        ),
    )
    op.create_index("ix_effect_verdicts_function_id", "effect_verdicts", ["function_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_effect_verdicts_function_id", table_name="effect_verdicts")
    op.drop_table("effect_verdicts")
    op.drop_index("ix_effect_behavior_cache_behavior_class", table_name="effect_behavior_cache")
    op.drop_table("effect_behavior_cache")

    # Postgres has no ALTER TYPE ... DROP VALUE. Rebuild the enum without
    # 'effects': demote any rows carrying it (defensive — nothing should, since
    # the flag ships off), rename current -> _old, recreate the pre-migration
    # value set/order, swap both consuming columns, drop the old type.
    op.execute("UPDATE jobs SET stage = 'coverage' WHERE stage = 'effects'")
    op.execute("UPDATE job_dependencies SET required_stage = 'coverage' WHERE required_stage = 'effects'")
    op.execute("ALTER TYPE jobstage RENAME TO jobstage_old")
    op.execute(
        "CREATE TYPE jobstage AS ENUM "
        "('discovery', 'dapp_crawl', 'defillama_scan', 'selection', 'static', "
        "'resolution', 'policy', 'coverage', 'done')"
    )
    op.execute("ALTER TABLE jobs ALTER COLUMN stage TYPE jobstage USING stage::text::jobstage")
    op.execute(
        "ALTER TABLE job_dependencies ALTER COLUMN required_stage TYPE jobstage USING required_stage::text::jobstage"
    )
    op.execute("DROP TYPE jobstage_old")
