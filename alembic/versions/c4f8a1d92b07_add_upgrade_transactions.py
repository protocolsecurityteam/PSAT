"""add upgrade_transactions + contract_creation_witnesses (C4 executor fold)

Revision ID: c4f8a1d92b07
Revises: b6d5e1c07a94
Create Date: 2026-07-30 12:00:00.000000

``upgrade_events`` stores no sender, no receipt and no trace, so nothing in the
corpus could answer "who executed this upgrade" or even "how many upgrade
actions were there". 120 events span 68 distinct transactions and one of them
carries 19 ``Upgraded`` logs across 19 proxies, so any count taken per event
inflates a single governance action up to 19x.

Two tables, both keyed by the thing the facts are actually about:

* ``upgrade_transactions`` — receipt-derived facts per ``(chain_id, tx_hash)``.
  The transaction hash IS the governance action id. Columns on
  ``upgrade_events`` were the alternative and were rejected: they would store
  each fact once per event (1.76x on average, 19x worst case) with nothing
  keeping the copies consistent, and a NULL ``executor_kind`` would conflate
  "receipt not fetched" with "fetched and undetermined" — a defaulted witness.
  Here the ROW'S EXISTENCE is the coverage discriminator and ``not_determined``
  is an explicit stored value.

* ``contract_creation_witnesses`` — the second, independent deployment arm.
  A proxy deployed by a factory has a populated ``receipt.to``, so the receipt
  rule alone cannot tell its deployment-time ``Upgraded`` log from an upgrade.
  Both witnesses (indexer creation tx + provably absent code in the preceding
  block) are required and must agree.

``upgrade_events`` gains a nullable ``chain_id`` purely as the link half of a
composite MATCH SIMPLE foreign key: a NULL in either column disables the
constraint, which is what lets an event exist before its receipt fact is folded
and what carries the poll writer's ``tx_hash``-less rows.

REBASE MARKER — Wave-2 migration chain position 2 (U4 -> **U8** -> U10A ->
U10B -> U7B). Unit 4's revision had not landed when this was authored, so
``down_revision`` points at the then-current head; repoint it at Unit 4's
revision id when this branch is rebased onto it.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "c4f8a1d92b07"
down_revision = "b6d5e1c07a94"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "upgrade_transactions",
        sa.Column("chain_id", sa.Integer(), nullable=False),
        sa.Column("tx_hash", sa.String(length=66), nullable=False),
        sa.Column("block_number", sa.BigInteger(), nullable=False),
        sa.Column("block_hash", sa.String(length=66), nullable=False),
        sa.Column("tx_status", sa.Integer(), nullable=False),
        sa.Column("receipt_from", sa.String(length=42), nullable=False),
        sa.Column("receipt_to", sa.String(length=42), nullable=True),
        sa.Column("created_contract_address", sa.String(length=42), nullable=True),
        sa.Column("is_contract_creation", sa.Boolean(), nullable=False),
        sa.Column("executor_kind", sa.String(length=20), nullable=False),
        sa.Column("executor_address", sa.String(length=42), nullable=True),
        sa.Column("executor_classification_source", sa.String(length=40), nullable=True),
        sa.Column("executor_classified_type", sa.String(length=20), nullable=True),
        sa.Column("executor_classification_block", sa.BigInteger(), nullable=True),
        sa.Column("executor_call_targets", postgresql.JSONB(), nullable=True),
        sa.Column("receipt_log_set_complete_for_tx", sa.Boolean(), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "executor_kind IN ('timelock_routed', 'safe_direct', 'not_determined')",
            name="ck_upgrade_transactions_executor_kind",
        ),
        sa.CheckConstraint(
            "(executor_kind = 'not_determined') = (executor_address IS NULL) "
            "AND (executor_kind = 'not_determined') = (executor_classification_source IS NULL) "
            "AND (executor_kind = 'not_determined') = (executor_classified_type IS NULL)",
            name="ck_upgrade_transactions_executor_gate_attached",
        ),
        sa.CheckConstraint(
            "executor_kind = 'timelock_routed' OR coalesce(jsonb_typeof(executor_call_targets), 'unset') = 'unset'",
            name="ck_upgrade_transactions_call_targets_gated",
        ),
        sa.PrimaryKeyConstraint("chain_id", "tx_hash"),
    )
    op.create_index("ix_upgrade_transactions_tx_hash", "upgrade_transactions", ["tx_hash"])

    op.create_table(
        "contract_creation_witnesses",
        sa.Column("chain_id", sa.Integer(), nullable=False),
        sa.Column("address", sa.String(length=42), nullable=False),
        sa.Column("creation_tx_hash", sa.String(length=66), nullable=True),
        sa.Column("creation_block", sa.BigInteger(), nullable=True),
        sa.Column("code_probe_block", sa.BigInteger(), nullable=True),
        sa.Column("code_absent_at_probe", sa.Boolean(), nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "(code_probe_block IS NULL) = (code_absent_at_probe IS NULL)",
            name="ck_contract_creation_witnesses_code_probe_paired",
        ),
        sa.PrimaryKeyConstraint("chain_id", "address"),
    )

    op.add_column("upgrade_events", sa.Column("chain_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        "fk_upgrade_events_upgrade_transaction",
        "upgrade_events",
        "upgrade_transactions",
        ["chain_id", "tx_hash"],
        ["chain_id", "tx_hash"],
    )


def downgrade() -> None:
    op.drop_constraint("fk_upgrade_events_upgrade_transaction", "upgrade_events", type_="foreignkey")
    op.drop_column("upgrade_events", "chain_id")
    op.drop_table("contract_creation_witnesses")
    op.drop_index("ix_upgrade_transactions_tx_hash", table_name="upgrade_transactions")
    op.drop_table("upgrade_transactions")
