"""Widen ``contract_balances.usd_value`` past the cent.

``numeric(20,2)`` is a resolution floor on a fact that was earned on-chain: a
holding worth $0.0035 is computed at full precision from an integer quantity and
an unrounded price, and then stored as ``0.00`` — indistinguishable from a
holding of nothing. Every consumer downstream reads that back as "no number
here", so the balance sheet of an entity whose every asset is sub-cent publishes
as not-determined and the work that priced it is thrown away at the last step.

``numeric(38,18)`` is the write the read already assumed: 18 fractional digits is
the resolution an ERC-20 quantity is itself quoted at, and 20 integral digits is
more than the sum of every dollar in circulation. Nothing about the value's
meaning changes — it is the same dollars, no longer truncated.

``contract_balances_latest`` is a VIEW over this column, and Postgres refuses to
alter a column a view selects, so the view is dropped and recreated around the
ALTER. The definition below is verbatim from ``b2f7c0e14a35``, the migration that
last defined it; recreating it is what keeps this migration's two arms honest,
not a rewrite.

Revision ID: b8d3c5f21a04
Revises: a6b2e0f37c19
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "b8d3c5f21a04"
down_revision = "a6b2e0f37c19"
branch_labels = None
depends_on = None


# Verbatim from ``b2f7c0e14a35`` — the view is dropped only because the ALTER
# needs it out of the way, so it comes back byte-identical.
_LATEST_VIEW = """
CREATE VIEW contract_balances_latest AS
SELECT cb.id, cb.contract_id, cb.token_address, cb.token_name, cb.token_symbol,
       cb.decimals, cb.raw_balance, cb.usd_value, cb.price_usd, cb.fetched_at,
       cb.observed_address, cb.block_number, cb.price_block_number, cb.fetch_id,
       cb.source
FROM contract_balances cb
WHERE cb.fetch_id = (
        SELECT f.id FROM contract_balance_fetches f
        WHERE f.contract_id = cb.contract_id
          AND CASE WHEN cb.token_address IS NULL
                   THEN f.native_status    <> 'fetch_failed'
                   ELSE f.asset_set_status <> 'fetch_failed' END
        ORDER BY f.fetched_at DESC, f.id DESC
        LIMIT 1)
UNION ALL
SELECT cb.id, cb.contract_id, cb.token_address, cb.token_name, cb.token_symbol,
       cb.decimals, cb.raw_balance, cb.usd_value, cb.price_usd, cb.fetched_at,
       cb.observed_address, cb.block_number, cb.price_block_number, cb.fetch_id,
       cb.source
FROM contract_balances cb
WHERE cb.fetch_id IS NULL
  AND NOT EXISTS (
        SELECT 1 FROM contract_balance_fetches f
        WHERE f.contract_id = cb.contract_id
          AND CASE WHEN cb.token_address IS NULL
                   THEN f.native_status    <> 'fetch_failed'
                   ELSE f.asset_set_status <> 'fetch_failed' END)
"""


def upgrade() -> None:
    op.execute("DROP VIEW IF EXISTS contract_balances_latest")
    op.alter_column(
        "contract_balances",
        "usd_value",
        existing_type=sa.Numeric(precision=20, scale=2),
        type_=sa.Numeric(precision=38, scale=18),
        existing_nullable=True,
    )
    op.execute(_LATEST_VIEW)


def downgrade() -> None:
    # Narrowing back TRUNCATES: every sub-cent figure written under the wide
    # column collapses to 0.00 and is gone. Postgres does the rounding itself on
    # the cast, so this direction is lossy by construction and says so rather
    # than pretending the two types are interchangeable.
    op.execute("DROP VIEW IF EXISTS contract_balances_latest")
    op.alter_column(
        "contract_balances",
        "usd_value",
        existing_type=sa.Numeric(precision=38, scale=18),
        type_=sa.Numeric(precision=20, scale=2),
        existing_nullable=True,
    )
    op.execute(_LATEST_VIEW)
