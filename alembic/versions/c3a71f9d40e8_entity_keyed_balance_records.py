"""Balance records may be keyed on an ENTITY that has no ``contracts`` row.

The balance plane could only ever answer for an address the ``contracts`` table
names. That is a fact about this database's bookkeeping, not about the perimeter
the score is computed over: 153 of protocol 1's entities are proven-codeless
principals discovered through the control graph — Safe owners, capability
principals — and they have no ``contracts`` row on any protocol. Nothing could
read them, so their balance sheets published ``no_rows``: not "holds nothing",
not "holds something", but "nobody looked", forever.

Minting carrier ``contracts`` rows for them was measured and rejected: a
``contracts`` row is read by the audit-coverage denominator, the selection
worker's candidate pool, the published TVL breakdown and the discovery-credit
census, so the row would stand in for "code that could carry an audit" and for
"a deployment whose holdings are the protocol's money" — a name standing in for
a witness in four places at once. (``RestakingPosition`` records the same
adjudication, reached the same way.)

So the identity moves onto the record instead. ``contract_id`` becomes nullable
and ``(entity_chain, entity_address)`` carries the other arm; a CHECK keeps
exactly one of them populated, so a row is keyed one way or the other and never
half of each. Contract-keyed rows are untouched by construction — their new
columns are NULL and every existing predicate on ``contract_id`` still selects
exactly what it selected before.

**The view is the load-bearing part.** ``contract_balances_latest`` decided which
fetch's row set is current with ``f.contract_id = cb.contract_id``, and that
comparison is NULL — never true — for a row whose ``contract_id`` is NULL. Every
entity-keyed row would have fallen silently out of the view: written, stored,
and invisible to every consumer, which is the exact silent-fallback shape this
plane exists to refuse. The rule is therefore restated on the coalesced key: the
contract arm where the row has a contract, the ``(chain, address)`` arm where it
does not. The two arms are mutually exclusive by the CHECK, so no row can match
both and the contract-keyed behaviour is unchanged term for term.

Revision ID: c3a71f9d40e8
Revises: b8d3c5f21a04
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "c3a71f9d40e8"
down_revision = "b8d3c5f21a04"
branch_labels = None
depends_on = None


# The identity predicate, written once and used by both arms of the view. The
# first disjunct is the OLD rule verbatim; ``=`` is already NULL-safe in the
# direction that matters here (a NULL ``cb.contract_id`` makes it NULL, never
# true), so the second disjunct is the only way an entity-keyed row is ever
# matched, and it can never fire for a contract-keyed one.
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

# Verbatim from ``b8d3c5f21a04`` — what the view was before the entity key.
_LATEST_VIEW_CONTRACT_ONLY = """
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

_EXACTLY_ONE_KEY = (
    "(contract_id IS NOT NULL AND entity_chain IS NULL AND entity_address IS NULL) "
    "OR (contract_id IS NULL AND entity_chain IS NOT NULL AND entity_address IS NOT NULL)"
)


def upgrade() -> None:
    op.execute("DROP VIEW IF EXISTS contract_balances_latest")

    for table, check_name in (
        ("contract_balance_fetches", "ck_cbf_exactly_one_subject_key"),
        ("contract_balances", "ck_contract_balances_exactly_one_subject_key"),
    ):
        op.add_column(table, sa.Column("entity_chain", sa.String(length=100), nullable=True))
        op.add_column(table, sa.Column("entity_address", sa.String(length=42), nullable=True))
        op.alter_column(table, "contract_id", existing_type=sa.Integer(), nullable=True)
        op.create_check_constraint(check_name, table, _EXACTLY_ONE_KEY)

    # Mirrors ``ix_cbf_contract_fetched`` on the other arm: the view's per-class
    # winner is an ORDER BY fetched_at DESC, id DESC LIMIT 1 under an equality on
    # the subject, and the contract arm has had that index since it existed.
    op.create_index(
        "ix_cbf_entity_fetched",
        "contract_balance_fetches",
        ["entity_chain", "entity_address", "fetched_at", "id"],
    )
    op.create_index(
        "ix_contract_balances_entity",
        "contract_balances",
        ["entity_chain", "entity_address"],
    )

    op.execute(_LATEST_VIEW)


def downgrade() -> None:
    # Entity-keyed rows have no contract to fall back to, so narrowing DELETES
    # them rather than leaving rows the restored NOT NULL cannot hold. Said out
    # loud because it is destructive: the direction is lossy by construction.
    op.execute("DROP VIEW IF EXISTS contract_balances_latest")
    op.execute("DELETE FROM contract_balances WHERE contract_id IS NULL")
    op.execute("DELETE FROM contract_balance_fetches WHERE contract_id IS NULL")
    op.drop_index("ix_contract_balances_entity", table_name="contract_balances")
    op.drop_index("ix_cbf_entity_fetched", table_name="contract_balance_fetches")
    for table, check_name in (
        ("contract_balance_fetches", "ck_cbf_exactly_one_subject_key"),
        ("contract_balances", "ck_contract_balances_exactly_one_subject_key"),
    ):
        op.drop_constraint(check_name, table, type_="check")
        op.alter_column(table, "contract_id", existing_type=sa.Integer(), nullable=False)
        op.drop_column(table, "entity_address")
        op.drop_column(table, "entity_chain")
    op.execute(_LATEST_VIEW_CONTRACT_ONLY)
