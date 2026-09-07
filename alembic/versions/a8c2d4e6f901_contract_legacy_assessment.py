"""Contract legacy analytical storage after the temporal import is complete."""

from alembic import context, op

revision = "a8c2d4e6f901"
down_revision = "f6a1c2d3e4b5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    existing_database = not context.config.attributes.get("assessment_fresh_database", False)
    if existing_database and context.get_x_argument(as_dictionary=True).get("assessment_cutover") != "stopped":
        raise RuntimeError(
            "Temporal Assessment contraction requires all old processes stopped and the import reconciled. "
            "Use the manual maintenance cutover; ordinary rolling deployment is refused."
        )
    bind = op.get_bind()
    remaining = bind.exec_driver_sql(
        "SELECT count(*) FROM artifacts WHERE name IN ('assessment', 'principal_history')"
    ).scalar()
    if remaining:
        raise RuntimeError(
            f"Temporal Assessment import is incomplete: {remaining} legacy analytical artifact row(s) remain"
        )
    unarchived = bind.exec_driver_sql(
        """
        SELECT count(*)
        FROM assessment_import_manifests m
        LEFT JOIN assessment_payloads p ON p.id = m.source_payload_id
        WHERE p.id IS NULL
        """
    ).scalar()
    if unarchived:
        raise RuntimeError(f"Temporal Assessment source archive is incomplete: {unarchived} payload(s) missing")
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
    raise RuntimeError("Deleted analytical columns require restoring the verified pre-cutover backup")
