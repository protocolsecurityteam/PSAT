"""Widen ``contract_balances.price_usd`` past the eighth decimal.

The sibling of ``b8d3c5f21a04``, and the same disease one column over. A price
is dollars per whole unit, and for a token quoted below ``1e-8`` — a supply in
the trillions is ordinary — ``numeric(20,8)`` stores the quote as
``0.00000000``. That literal is already spoken for: the writers store ``0`` for
"no price known", so a real quote landing on the floor becomes indistinguishable
from a price that never answered, and the ambiguity is unrecoverable from the
row.

``numeric(38,18)`` is the same resolution ``usd_value`` now carries and the same
resolution an ERC-20 quantity is quoted at, so the two money columns on the row
stop disagreeing about how fine a fact they are willing to hold. Nothing about
the value's meaning changes — it is the same dollars per unit, no longer
truncated.

Schema only. Rows already written under the narrow column were truncated at the
write and no ALTER recovers them; they are re-read by the next producer cycle,
which is the only thing that can know what the price was.

``contract_balances_latest`` is a VIEW that projects this column, and Postgres
refuses to alter a column a view selects, so the view is dropped and recreated
around the ALTER. The definition below is verbatim from ``c3a71f9d40e8``, the
migration that last defined it.

Revision ID: d4f1a7c62b90
Revises: c3a71f9d40e8
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "d4f1a7c62b90"
down_revision = "c3a71f9d40e8"
branch_labels = None
depends_on = None


# Verbatim from ``c3a71f9d40e8`` — the view is dropped only because the ALTER
# needs it out of the way, so it comes back byte-identical, entity arm included.
_SAME_SUBJECT = """(f.contract_id = cb.contract_id
           OR (cb.contract_id IS NULL AND f.contract_id IS NULL
               AND f.entity_chain = cb.entity_chain
               AND f.entity_address = cb.entity_address))"""

_CLASS_NOT_FAILED = """CASE WHEN cb.token_address IS NULL
                   THEN f.native_status    <> 'fetch_failed'
                   ELSE f.asset_set_status <> 'fetch_failed' END"""

_COLUMNS = """cb.id, cb.contract_id, cb.token_address, cb.token_name, cb.token_symbol,
       cb.decimals, cb.raw_balance, cb.usd_value, cb.price_usd, cb.fetched_at,
       cb.observed_address, cb.block_number, cb.price_block_number, cb.fetch_id,
       cb.source, cb.entity_chain, cb.entity_address"""

_LATEST_VIEW = f"""
CREATE VIEW contract_balances_latest AS
SELECT {_COLUMNS}
FROM contract_balances cb
WHERE cb.fetch_id = (
        SELECT f.id FROM contract_balance_fetches f
        WHERE {_SAME_SUBJECT}
          AND {_CLASS_NOT_FAILED}
        ORDER BY f.fetched_at DESC, f.id DESC
        LIMIT 1)
UNION ALL
SELECT {_COLUMNS}
FROM contract_balances cb
WHERE cb.fetch_id IS NULL
  AND NOT EXISTS (
        SELECT 1 FROM contract_balance_fetches f
        WHERE {_SAME_SUBJECT}
          AND {_CLASS_NOT_FAILED})
"""


def upgrade() -> None:
    op.execute("DROP VIEW IF EXISTS contract_balances_latest")
    op.alter_column(
        "contract_balances",
        "price_usd",
        existing_type=sa.Numeric(precision=20, scale=8),
        type_=sa.Numeric(precision=38, scale=18),
        existing_nullable=True,
    )
    op.execute(_LATEST_VIEW)


def downgrade() -> None:
    # Narrowing back TRUNCATES: every quote finer than the eighth decimal
    # collapses, and one below it collapses onto the same 0 the writers use for
    # "no price known". Postgres does the rounding itself on the cast, so this
    # direction is lossy by construction and says so rather than pretending the
    # two types are interchangeable.
    op.execute("DROP VIEW IF EXISTS contract_balances_latest")
    op.alter_column(
        "contract_balances",
        "price_usd",
        existing_type=sa.Numeric(precision=38, scale=18),
        type_=sa.Numeric(precision=20, scale=8),
        existing_nullable=True,
    )
    op.execute(_LATEST_VIEW)
