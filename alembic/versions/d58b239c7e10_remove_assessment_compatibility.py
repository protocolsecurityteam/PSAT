"""Finish the Assessment cutover; requires old application processes stopped."""

from alembic import op

revision = "d58b239c7e10"
down_revision = "c4a91e7b2d60"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table, columns in {
        "jobs": ("analysis_schema_version",),
        "contract_materializations": (
            "analysis_schema_version",
            "analysis",
            "tracking_plan",
            "analysis_blob_key",
            "tracking_plan_blob_key",
        ),
        "effect_behavior_cache": ("analysis_schema_version",),
        "effective_functions": ("effect_labels", "effect_targets", "action_summary"),
        "control_graph_nodes": ("analyzed",),
    }.items():
        for column in columns:
            op.drop_column(table, column)
    op.execute(
        "UPDATE monitored_contracts SET contract_type = 'regular' WHERE contract_type IN ('role_control', 'contract')"
    )
    op.drop_constraint("ck_monitored_contracts_contract_type", "monitored_contracts", type_="check")
    op.create_check_constraint(
        "ck_monitored_contracts_contract_type",
        "monitored_contracts",
        "contract_type IN ('regular', 'proxy', 'safe', 'timelock', 'pausable')",
    )


def downgrade() -> None:
    raise RuntimeError("Retired analytical columns cannot be restored. Restore a pre-cutover database backup.")
