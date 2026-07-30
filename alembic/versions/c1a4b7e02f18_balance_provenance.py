"""Balance provenance: fetch plane, per-row heights, insert-only latest view.

Two planes, deliberately separated.

``contract_balances`` keeps meaning exactly what it meant — a row is a WITNESSED
POSITIVE QUANTITY. It gains provenance columns only (which address, which
height, which fetch). It gains no new row shapes: measured on the pre-migration
corpus, 0 of 1617 rows carry a non-positive ``raw_balance``, and
``services.effects.selection`` consumes a row's mere existence as "this
deployment holds this asset", so writing a zero or a failure there would publish
holdings that do not exist.

``contract_balance_fetches`` is the new fetch-provenance plane and its rows are
NOT holdings. It carries the three-state discriminators that used to be an
absence: a native read that failed, a native read that returned a pinned zero,
and an ERC-20 page that came back empty because the fetch failed rather than
because nothing is held.

``contract_balances_latest`` is the read surface, needed because the destructive
per-contract DELETE is gone. Both writers are insert-only now, so a naive reader
would sum across cycles.

Revision ID: c1a4b7e02f18
Revises: b6d5e1c07a94
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "c1a4b7e02f18"
down_revision = "b6d5e1c07a94"
branch_labels = None
depends_on = None


# Per ROW CLASS independently, the latest NON-FAILED fetch wins wholesale.
#
# Wholesale, because a fetch's rows ARE the set it observed: picking the latest
# row per (contract, asset) instead would keep republishing an asset the holder
# has since sold.
#
# Per row class, because a transient ERC-20 failure must not withdraw the native
# holding — and because the native and ERC-20 quantities come from different
# reads (Q1 keeps ERC-20 unpinned), so they genuinely belong to different fetches
# in general.
#
# Non-failed, because a failed fetch writes few or no rows, and letting it win
# would republish "holds nothing" out of a failure.
#
# The legacy arm keys on the absence of a NON-FAILED fetch, not on the absence of
# any fetch: a first fetch that fails must not delete 1,617 rows of history from
# the view.
_LATEST_VIEW = """
CREATE VIEW contract_balances_latest AS
SELECT cb.id, cb.contract_id, cb.token_address, cb.token_name, cb.token_symbol,
       cb.decimals, cb.raw_balance, cb.usd_value, cb.price_usd, cb.fetched_at,
       cb.observed_address, cb.block_number, cb.price_block_number, cb.fetch_id
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
       cb.observed_address, cb.block_number, cb.price_block_number, cb.fetch_id
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
    op.create_table(
        "contract_balance_fetches",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("contract_id", sa.Integer(), nullable=False),
        sa.Column("chain_id", sa.Integer(), nullable=False),
        sa.Column("observed_address", sa.String(length=42), nullable=False),
        sa.Column("block_number", sa.BigInteger(), nullable=True),
        sa.Column("native_status", sa.String(length=32), nullable=False),
        sa.Column("asset_set_status", sa.String(length=32), nullable=False),
        sa.Column("asset_page_length", sa.Integer(), nullable=True),
        sa.Column("writer", sa.String(length=32), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["contract_id"], ["contracts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        # A pinned zero is a proven zero; an unpinned one is not. Enforced here
        # rather than by writer discipline so a future writer cannot mint a
        # proven_zero out of an Etherscan ``tag=latest`` answer.
        sa.CheckConstraint(
            "native_status <> 'proven_zero' OR block_number IS NOT NULL",
            name="ck_cbf_proven_zero_requires_block",
        ),
    )
    op.create_index("ix_cbf_contract_fetched", "contract_balance_fetches", ["contract_id", "fetched_at", "id"])

    op.add_column("contract_balances", sa.Column("observed_address", sa.String(length=42), nullable=True))
    op.add_column("contract_balances", sa.Column("block_number", sa.BigInteger(), nullable=True))
    op.add_column("contract_balances", sa.Column("price_block_number", sa.BigInteger(), nullable=True))
    op.add_column("contract_balances", sa.Column("fetch_id", sa.BigInteger(), nullable=True))
    op.create_foreign_key(
        "fk_contract_balances_fetch_id",
        "contract_balances",
        "contract_balance_fetches",
        ["fetch_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index("ix_contract_balances_fetch_id", "contract_balances", ["fetch_id"])
    # An ERC-20 quantity comes from an unpinned ``tag=latest`` answer even when
    # the same fetch pinned its native read. Without this, a token row could
    # inherit a height its quantity was never read at.
    op.create_check_constraint(
        "ck_contract_balances_token_block_null",
        "contract_balances",
        "token_address IS NULL OR block_number IS NULL",
    )
    # No price source in this system carries a height. The column exists so the
    # three-state is machine-checkable rather than a comment, and the constraint
    # is what makes it one.
    op.create_check_constraint(
        "ck_contract_balances_price_block_null",
        "contract_balances",
        "price_block_number IS NULL",
    )

    # No backfill is possible and none is attempted: every pre-existing row's
    # observation height and observed address were never recorded, so they stay
    # NULL = not_determined, permanently.
    op.execute(_LATEST_VIEW)


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS contract_balances_latest")
    op.drop_constraint("ck_contract_balances_price_block_null", "contract_balances", type_="check")
    op.drop_constraint("ck_contract_balances_token_block_null", "contract_balances", type_="check")
    op.drop_index("ix_contract_balances_fetch_id", table_name="contract_balances")
    op.drop_constraint("fk_contract_balances_fetch_id", "contract_balances", type_="foreignkey")
    op.drop_column("contract_balances", "fetch_id")
    op.drop_column("contract_balances", "price_block_number")
    op.drop_column("contract_balances", "block_number")
    op.drop_column("contract_balances", "observed_address")
    op.drop_index("ix_cbf_contract_fetched", table_name="contract_balance_fetches")
    op.drop_table("contract_balance_fetches")
