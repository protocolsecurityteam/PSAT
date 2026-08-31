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
    op.alter_column("jobs", "analysis_schema_version", new_column_name="static_facts_schema_version")
    op.alter_column(
        "contract_materializations",
        "analysis_schema_version",
        new_column_name="static_facts_schema_version",
    )
    op.alter_column(
        "effect_behavior_cache",
        "analysis_schema_version",
        new_column_name="static_facts_schema_version",
    )
    op.alter_column("contract_materializations", "analysis", new_column_name="static_facts")
    op.alter_column("contract_materializations", "tracking_plan", new_column_name="observation_plan")
    op.alter_column(
        "contract_materializations",
        "analysis_blob_key",
        new_column_name="static_facts_blob_key",
    )
    op.alter_column(
        "contract_materializations",
        "tracking_plan_blob_key",
        new_column_name="observation_plan_blob_key",
    )
    op.drop_column("effective_functions", "effect_labels")
    op.drop_column("effective_functions", "effect_targets")
    op.drop_column("effective_functions", "action_summary")
    op.drop_column("control_graph_nodes", "analyzed")


def downgrade() -> None:
    op.add_column(
        "control_graph_nodes",
        sa.Column("analyzed", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column("effective_functions", sa.Column("action_summary", sa.Text(), nullable=True))
    op.add_column(
        "effective_functions",
        sa.Column("effect_targets", postgresql.ARRAY(sa.String(length=255)), nullable=True),
    )
    op.add_column(
        "effective_functions",
        sa.Column("effect_labels", postgresql.ARRAY(sa.String(length=100)), nullable=True),
    )
    op.alter_column("contract_materializations", "status", server_default=sa.text("'pending'"))
    op.alter_column(
        "contract_materializations",
        "observation_plan_blob_key",
        new_column_name="tracking_plan_blob_key",
    )
    op.alter_column(
        "contract_materializations",
        "static_facts_blob_key",
        new_column_name="analysis_blob_key",
    )
    op.alter_column("contract_materializations", "observation_plan", new_column_name="tracking_plan")
    op.alter_column("contract_materializations", "static_facts", new_column_name="analysis")
    op.alter_column(
        "contract_materializations",
        "static_facts_schema_version",
        new_column_name="analysis_schema_version",
    )
    op.alter_column(
        "effect_behavior_cache",
        "static_facts_schema_version",
        new_column_name="analysis_schema_version",
    )
    op.alter_column("jobs", "static_facts_schema_version", new_column_name="analysis_schema_version")
