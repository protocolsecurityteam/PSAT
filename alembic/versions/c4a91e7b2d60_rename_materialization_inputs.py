"""rename materialization inputs for the Assessment architecture

Revision ID: c4a91e7b2d60
Revises: b3d7e1f05a92
Create Date: 2026-08-31 02:20:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "c4a91e7b2d60"
down_revision: Union[str, Sequence[str], None] = "b3d7e1f05a92"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "UPDATE contract_materializations "
        "SET status = 'failed', error = COALESCE(error, 'retired pending state') "
        "WHERE status = 'pending'"
    )
    op.alter_column("contract_materializations", "status", server_default=sa.text("'building'"))
    # The retired column remains readable by old machines during the rolling
    # window, but new writers no longer send it. Give those inserts the legacy
    # value implied by a missing analysis_state instead of violating NOT NULL.
    op.alter_column("control_graph_nodes", "analyzed", server_default=sa.false())
    # Expand first: release commands run while old Fly machines are still live.
    # New code reads these columns; old machines keep reading the original names
    # until the rolling replacement completes. A later deployment may contract
    # the retired physical columns once no old process can query them.
    op.add_column("jobs", sa.Column("static_facts_schema_version", sa.Integer(), nullable=True))
    op.execute("UPDATE jobs SET static_facts_schema_version = analysis_schema_version")
    op.add_column(
        "contract_materializations",
        sa.Column("static_facts_schema_version", sa.Integer(), server_default="1", nullable=False),
    )
    op.add_column("contract_materializations", sa.Column("static_facts", postgresql.JSONB(), nullable=True))
    op.add_column("contract_materializations", sa.Column("observation_plan", postgresql.JSONB(), nullable=True))
    op.add_column("contract_materializations", sa.Column("static_facts_blob_key", sa.Text(), nullable=True))
    op.add_column("contract_materializations", sa.Column("observation_plan_blob_key", sa.Text(), nullable=True))
    op.execute(
        "UPDATE contract_materializations SET "
        "static_facts_schema_version = analysis_schema_version, "
        "static_facts = analysis, observation_plan = tracking_plan, "
        "static_facts_blob_key = analysis_blob_key, observation_plan_blob_key = tracking_plan_blob_key"
    )
    op.add_column(
        "effect_behavior_cache",
        sa.Column("static_facts_schema_version", sa.Integer(), server_default="1", nullable=False),
    )
    op.execute("UPDATE effect_behavior_cache SET static_facts_schema_version = analysis_schema_version")
    op.add_column("contract_materializations", sa.Column("effects", postgresql.JSONB(), nullable=True))
    # Rows without an Assessment owner are not valid projections in the new
    # architecture. Remove them instead of letting NULL claims render as a
    # proven-empty capability surface.
    op.execute(
        "DELETE FROM effective_functions ef USING contracts c "
        "WHERE ef.contract_id = c.id AND ("
        "ef.claims IS NULL OR jsonb_typeof(ef.claims) = 'null' OR c.job_id IS NULL OR "
        "NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.job_id = c.job_id AND a.name = 'assessment'))"
    )
    op.execute(
        "DELETE FROM contract_summaries cs USING contracts c "
        "WHERE cs.contract_id = c.id AND (c.job_id IS NULL OR "
        "NOT EXISTS (SELECT 1 FROM artifacts a WHERE a.job_id = c.job_id AND a.name = 'assessment'))"
    )


def downgrade() -> None:
    op.drop_column("contract_materializations", "effects")
    op.drop_column("effect_behavior_cache", "static_facts_schema_version")
    op.drop_column("contract_materializations", "observation_plan_blob_key")
    op.drop_column("contract_materializations", "static_facts_blob_key")
    op.drop_column("contract_materializations", "observation_plan")
    op.drop_column("contract_materializations", "static_facts")
    op.drop_column("contract_materializations", "static_facts_schema_version")
    op.drop_column("jobs", "static_facts_schema_version")
    op.alter_column("control_graph_nodes", "analyzed", server_default=None)
    op.alter_column("contract_materializations", "status", server_default=sa.text("'pending'"))
