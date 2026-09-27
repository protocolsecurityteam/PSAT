"""Current balance publication, retry state and effects recovery.

Revision ID: d8e51f0a2b64
Revises: d7a42c91e803
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "d8e51f0a2b64"
down_revision = "d7a42c91e803"
branch_labels = None
depends_on = None

# Frozen migration vocabulary: do not import mutable application policies.
_COLUMNS = """cb.id, cb.contract_id, cb.token_address, cb.token_name, cb.token_symbol,
       cb.decimals, cb.raw_balance, cb.usd_value, cb.price_usd, cb.fetched_at,
       cb.observed_address, cb.block_number, cb.price_block_number, cb.fetch_id,
       cb.source, cb.entity_chain, cb.entity_address"""
_NEW_COLUMNS = ", cb.decimals_known, cb.observed_at, cb.price_observed_at"
_SAME_SUBJECT = """(
    f.contract_id = cb.contract_id
    OR (cb.contract_id IS NULL AND f.contract_id IS NULL
        AND f.entity_chain = cb.entity_chain AND f.entity_address = cb.entity_address)
)"""
_ELIGIBLE_CLASS = """CASE WHEN cb.token_address IS NULL
    THEN f.native_status IN ('proven_zero', 'proven_nonzero', 'not_determined')
    ELSE f.asset_set_status IN ('returned_assets', 'returned_empty', 'at_page_cap')
END"""
_ACCEPTED_FIRST = """CASE WHEN cb.token_address IS NOT NULL
    AND f.asset_set_status IN ('returned_assets', 'returned_empty') THEN 1 ELSE 0 END DESC"""


def _create_latest_view(*, with_metadata: bool) -> None:
    """Accepted token snapshots win over partial prefixes on both schema versions.

    Explicit eligibility excludes failed and unattempted classes. Downgrading
    must not let a skipped class hide previously successful rows, nor restore
    destructive partial-prefix replacement. Only the column shape rolls back.
    """
    columns = _COLUMNS + (_NEW_COLUMNS if with_metadata else "")
    op.execute(f"""
        CREATE VIEW contract_balances_latest AS
        SELECT {columns}
        FROM contract_balances cb
        WHERE cb.fetch_id = (
            SELECT f.id
            FROM contract_balance_fetches f
            WHERE {_SAME_SUBJECT} AND {_ELIGIBLE_CLASS}
            ORDER BY {_ACCEPTED_FIRST}, f.fetched_at DESC, f.id DESC
            LIMIT 1
        )
        UNION ALL
        SELECT {columns}
        FROM contract_balances cb
        WHERE cb.fetch_id IS NULL
          AND NOT EXISTS (
            SELECT 1 FROM contract_balance_fetches f
            WHERE {_SAME_SUBJECT} AND {_ELIGIBLE_CLASS}
          )
    """)


def upgrade() -> None:
    op.add_column("protocols", sa.Column("last_balance_attempt_at", sa.DateTime(timezone=True), nullable=True))
    op.execute("DROP VIEW contract_balances_latest")
    op.add_column("contract_balance_fetches", sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True))
    for name, typ in (
        ("decimals_known", sa.Boolean()),
        ("observed_at", sa.DateTime(timezone=True)),
        ("price_observed_at", sa.DateTime(timezone=True)),
    ):
        op.add_column("contract_balances", sa.Column(name, typ, nullable=True))
    for name, typ in (
        ("holdings_observed_at", sa.DateTime(timezone=True)),
        ("holdings_partial", sa.Boolean()),
        ("valuation_partial", sa.Boolean()),
    ):
        op.add_column("tvl_snapshots", sa.Column(name, typ, nullable=True))
    op.create_table(
        "balance_collection_state",
        sa.Column("chain_id", sa.Integer(), primary_key=True),
        sa.Column("address", sa.String(42), primary_key=True),
        sa.Column("read_class", sa.String(16), primary_key=True),
        sa.Column("generation", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("lease_owner", sa.String(36)),
        sa.Column("lease_until", sa.DateTime(timezone=True)),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("observed_at", sa.DateTime(timezone=True)),
        sa.Column("failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("outcome", sa.String(32)),
        sa.Column("payload", postgresql.JSONB()),
    )
    op.create_index("ix_balance_collection_state_next_attempt_at", "balance_collection_state", ["next_attempt_at"])
    op.create_table(
        "pending_effects_work",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("protocol_id", sa.Integer(), sa.ForeignKey("protocols.id", ondelete="CASCADE"), nullable=False),
        sa.Column("chain_id", sa.Integer(), nullable=False),
        sa.Column("deployment_address", sa.String(42), nullable=False),
        sa.Column("contract_id", sa.Integer(), sa.ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False),
        sa.Column(
            "function_id", sa.Integer(), sa.ForeignKey("effective_functions.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("effect_family", sa.String(50), nullable=False),
        sa.Column("reason", sa.String(80), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("queued_job_id", postgresql.UUID(), sa.ForeignKey("jobs.id", ondelete="SET NULL")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint(
            "chain_id", "deployment_address", "function_id", "effect_family", name="uq_pending_effects_identity"
        ),
    )
    op.create_index("ix_pending_effects_due", "pending_effects_work", ["state", "next_attempt_at"])
    _create_latest_view(with_metadata=True)

    op.execute("""
        INSERT INTO protocol_score_queue (protocol_id, reason, dirty_at)
        SELECT id, 'delivery_classification_retired', now() FROM protocols
        ON CONFLICT (protocol_id) DO UPDATE
            SET reason = EXCLUDED.reason, dirty_at = EXCLUDED.dirty_at
    """)


def downgrade() -> None:
    op.drop_column("protocols", "last_balance_attempt_at")
    # Raw observations survive. Their new metadata is unavailable after rollback;
    # re-upgrading leaves it unknown instead of inventing observation times.
    # Safe projection rules survive too; rollback needs compatible app readers.
    op.execute("DROP VIEW contract_balances_latest")
    for table in ("pending_effects_work", "balance_collection_state"):
        op.drop_table(table)
    for name in (
        "holdings_observed_at",
        "holdings_partial",
        "valuation_partial",
    ):
        op.drop_column("tvl_snapshots", name)
    for name in ("decimals_known", "observed_at", "price_observed_at"):
        op.drop_column("contract_balances", name)
    op.drop_column("contract_balance_fetches", "observed_at")
    _create_latest_view(with_metadata=False)
