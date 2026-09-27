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


# Frozen canonical names and known legacy aliases as of this revision. A NULL
# verdict chain is recoverable only from an explicit contract chain, never ETH
# by default. Current effect_verdicts disallow NULL, but old imported data can
# predate that invariant; retaining this guard makes the backfill fail closed.
_CHAIN_NAMES = """
    ('ethereum', 1), ('mainnet', 1), ('eth', 1), ('ethereum mainnet', 1), ('eth mainnet', 1),
    ('arbitrum', 42161), ('arbitrum one', 42161),
    ('optimism', 10), ('optimistic ethereum', 10),
    ('polygon', 137), ('polygon pos', 137), ('matic', 137),
    ('base', 8453), ('base mainnet', 8453),
    ('avalanche', 43114), ('avalanche c chain', 43114), ('avax', 43114),
    ('bsc', 56), ('bnb', 56), ('bnb chain', 56), ('binance smart chain', 56),
    ('linea', 59144), ('scroll', 534352), ('zksync', 324), ('zk sync', 324),
    ('blast', 81457), ('mode', 34443), ('berachain', 80094)
"""
_AFFECTED_VERDICTS = f"""
    WITH chain_names(name, chain_id) AS (VALUES {_CHAIN_NAMES})
    SELECT DISTINCT c.protocol_id, COALESCE(v.chain_id, chain_names.chain_id) AS chain_id,
        lower(COALESCE(NULLIF(ef.deployment_address, ''), c.address)) AS deployment_address,
        c.id AS contract_id, ef.id AS function_id, v.effect_class AS effect_family
    FROM effective_functions ef
    JOIN contracts c ON c.id = ef.contract_id
    JOIN effect_verdicts v ON v.function_id = ef.id
    LEFT JOIN chain_names ON chain_names.name = regexp_replace(lower(trim(c.chain)), '[[:space:]_-]+', ' ', 'g')
    WHERE c.protocol_id IS NOT NULL AND v.effect_class IN ('value_out', 'supply')
"""


_AFFECTED_EMPTY_PLANS = f"""
    WITH chain_names(name, chain_id) AS (VALUES {_CHAIN_NAMES})
    SELECT DISTINCT c.protocol_id, chain_names.chain_id,
        lower(COALESCE(NULLIF(ef.deployment_address, ''), c.address)) AS deployment_address,
        c.id AS contract_id, ef.id AS function_id, 'candidate_selection' AS effect_family
    FROM effects_plan_markers marker
    JOIN contracts c ON c.id = marker.contract_id
    JOIN effective_functions ef ON ef.contract_id = c.id
    LEFT JOIN chain_names ON chain_names.name = regexp_replace(lower(trim(c.chain)), '[[:space:]_-]+', ' ', 'g')
    WHERE c.protocol_id IS NOT NULL
"""
_AFFECTED_WORK = (
    f"SELECT * FROM ({_AFFECTED_VERDICTS}) verdicts UNION SELECT * FROM ({_AFFECTED_EMPTY_PLANS}) empty_plans"
)


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
        ("external_slug", sa.String(255)),
        ("external_observed_at", sa.DateTime(timezone=True)),
        ("external_retrieved_at", sa.DateTime(timezone=True)),
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
        "provider_permits",
        sa.Column("quota_key", sa.String(100), primary_key=True),
        sa.Column("next_allowed_at", sa.DateTime(timezone=True), nullable=False),
    )
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
        sa.Column("required_generation", sa.BigInteger(), nullable=False),
        sa.Column("consumed_generation", sa.BigInteger(), nullable=False),
        sa.Column("input_fingerprint", sa.String(64)),
        sa.Column("evidence_fingerprint", sa.String(64)),
        sa.Column("evidence_generation", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("covered_tokens", postgresql.JSONB(), nullable=False),
        sa.Column("candidate_tokens", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
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

    # Only families which actually consumed balance evidence are invalidated.
    # Empty-plan markers also need candidate selection retried: old balance
    # filters could suppress all plans. The current cascade determines eligibility.
    # Enrolling a supply task for every old pause/upgrade verdict creates work
    # that the function can never execute and therefore can never complete.
    op.execute(f"""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM ({_AFFECTED_WORK}) affected WHERE chain_id IS NULL) THEN
                RAISE EXCEPTION 'Balance migration: affected legacy effects work has no chain; repair its contract chain first';
            END IF;
        END $$
    """)
    op.execute(f"""
        INSERT INTO pending_effects_work
            (protocol_id, chain_id, deployment_address, contract_id, function_id, effect_family,
             reason, state, required_generation, consumed_generation, covered_tokens, attempts)
        SELECT protocol_id, chain_id, deployment_address, contract_id, function_id, effect_family,
            'balance_semantics_changed', 'pending', 0, 0, '[]'::jsonb, 0
        FROM ({_AFFECTED_WORK}) affected
        ON CONFLICT DO NOTHING
    """)
    op.execute("""
        INSERT INTO protocol_score_queue (protocol_id, reason, dirty_at)
        SELECT id, 'balance_semantics_changed', now() FROM protocols
        ON CONFLICT (protocol_id) DO UPDATE
            SET reason = EXCLUDED.reason, dirty_at = EXCLUDED.dirty_at
    """)


def downgrade() -> None:
    op.drop_column("protocols", "last_balance_attempt_at")
    # Raw observations survive. Their new metadata is unavailable after rollback;
    # re-upgrading leaves it unknown instead of inventing observation times.
    # Safe projection rules survive too; rollback needs compatible app readers.
    op.execute("DROP VIEW contract_balances_latest")
    for table in ("pending_effects_work", "provider_permits", "balance_collection_state"):
        op.drop_table(table)
    for name in (
        "external_slug",
        "external_observed_at",
        "external_retrieved_at",
        "holdings_observed_at",
        "holdings_partial",
        "valuation_partial",
    ):
        op.drop_column("tvl_snapshots", name)
    for name in ("decimals_known", "observed_at", "price_observed_at"):
        op.drop_column("contract_balances", name)
    op.drop_column("contract_balance_fetches", "observed_at")
    _create_latest_view(with_metadata=False)
