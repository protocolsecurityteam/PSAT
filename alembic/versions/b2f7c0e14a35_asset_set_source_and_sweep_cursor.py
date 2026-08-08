"""Asset-set source/basis, the sweep cursor, and the two proxies their own jobs own.

Three things, one migration, because they are one claim.

**Source.** ``asset_set_status`` records what an answer was; it never recorded
WHOSE answer it is. An empty asset list from a third-party index is that index's
completeness claim about itself and proves nothing about the chain; an empty
list derived from the chain's own transfer logs through a named block is an
earned negative. ``asset_set_source`` is that distinction, ``asset_set_basis``
is the sentence scoping it, and the default is the honest one for every row
already stored: they all came from Etherscan pages.

**Cursor.** ``swept_through_block`` is both the extent of the claim and the
cursor that keeps a full-history log scan a once-per-contract cost instead of a
per-cycle one. Two CHECKs keep it honest: a sweep-sourced set must carry one,
and only a completed sweep may.

**Ownership.** Two proxy rows carried ``protocol_id IS NULL`` while the
implementation they front is a contract the protocol owns AND their own analysis
job belongs to that same protocol. Nothing read them: not the balance producers,
whose population is protocol-scoped, and not the value plane, which loads fetch
records the same way. One of them holds 19.06 ETH. The backfill is that
conjunction and nothing looser — the impl-ownership witness alone would still be
a guess about a shared implementation, and job ownership alone admits every
dependency a protocol's jobs ever compiled.

Revision ID: b2f7c0e14a35
Revises: a4c8e60d97b1
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "b2f7c0e14a35"
down_revision = "a4c8e60d97b1"
branch_labels = None
depends_on = None


_LATEST_VIEW_WITH_SOURCE = """
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

_LATEST_VIEW_WITHOUT_SOURCE = _LATEST_VIEW_WITH_SOURCE.replace(",\n       cb.source", "")

# A proxy is owned by the protocol whose implementation runs at it AND whose job
# analysed it. Both conjuncts, on the same protocol, or the row is left NULL.
_BACKFILL_OWNERSHIP = """
UPDATE contracts c
SET protocol_id = owner.protocol_id
FROM contracts owner, jobs j
WHERE c.protocol_id IS NULL
  AND c.is_proxy
  AND c.implementation IS NOT NULL
  AND lower(owner.address) = lower(c.implementation)
  AND COALESCE(owner.chain, 'ethereum') = COALESCE(c.chain, 'ethereum')
  AND owner.protocol_id IS NOT NULL
  AND j.id = c.job_id
  AND j.protocol_id = owner.protocol_id
"""


def upgrade() -> None:
    op.add_column(
        "contract_balance_fetches",
        sa.Column("asset_set_source", sa.String(length=32), nullable=False, server_default="etherscan_pages"),
    )
    op.add_column("contract_balance_fetches", sa.Column("asset_set_basis", sa.Text(), nullable=True))
    op.add_column("contract_balance_fetches", sa.Column("sweep_status", sa.String(length=32), nullable=True))
    op.add_column("contract_balance_fetches", sa.Column("swept_through_block", sa.BigInteger(), nullable=True))
    op.create_check_constraint(
        "ck_cbf_sweep_source_requires_block",
        "contract_balance_fetches",
        "asset_set_source <> 'chain_log_sweep' OR swept_through_block IS NOT NULL",
    )
    op.create_check_constraint(
        "ck_cbf_swept_block_requires_completed_sweep",
        "contract_balance_fetches",
        "swept_through_block IS NULL OR sweep_status = 'completed'",
    )

    op.add_column("contract_balances", sa.Column("source", sa.String(length=32), nullable=True))
    # No backfill of ``source`` on existing rows: what read them was not
    # recorded, and stamping the current default on history would assert a
    # provenance nobody witnessed. NULL is that third state.
    op.execute("DROP VIEW IF EXISTS contract_balances_latest")
    op.execute(_LATEST_VIEW_WITH_SOURCE)

    op.execute(_BACKFILL_OWNERSHIP)


def downgrade() -> None:
    # The ownership backfill is deliberately NOT reversed: it recorded a fact the
    # rows always had, and un-recording it would re-hide a code-bearing contract
    # from the producers. Reversing the schema is what this direction is for.
    op.execute("DROP VIEW IF EXISTS contract_balances_latest")
    op.execute(_LATEST_VIEW_WITHOUT_SOURCE)
    op.drop_column("contract_balances", "source")
    op.drop_constraint("ck_cbf_swept_block_requires_completed_sweep", "contract_balance_fetches", type_="check")
    op.drop_constraint("ck_cbf_sweep_source_requires_block", "contract_balance_fetches", type_="check")
    op.drop_column("contract_balance_fetches", "swept_through_block")
    op.drop_column("contract_balance_fetches", "sweep_status")
    op.drop_column("contract_balance_fetches", "asset_set_basis")
    op.drop_column("contract_balance_fetches", "asset_set_source")
