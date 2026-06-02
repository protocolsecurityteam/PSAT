"""multichain identity: jobs.chain + address_labels (address, chain) PK

Revision ID: c4f1a9d2e8b7
Revises: a7f3c2e9b104
Create Date: 2026-05-30

Threads chain identity through the job layer so multichain dedupe keys on
(chain, address) rather than address-only:

- ``jobs.chain`` is denormalized from ``request['chain']`` (canonicalized,
  default 'ethereum') so the queue can filter (chain, address) in SQL instead
  of post-filtering the request JSONB in Python.
- ``address_labels`` becomes per-(address, chain): the same address can be a
  different entity on different networks. Existing labels backfill to
  'ethereum'.

``contracts``, ``monitored_contracts``, ``watched_proxies``,
``job_dependencies`` and the chain_id-keyed caches were already chain-aware,
so they're untouched. Child analysis rows (principals, control-graph nodes,
dependencies, balances, upgrade events) inherit their chain from the parent
contract/job and deliberately do NOT carry their own column — for generic
multichain (no cross-chain references) that data would always equal the
parent's chain.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "c4f1a9d2e8b7"
down_revision: Union[str, Sequence[str], None] = "e9c3a5b2d7f4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- jobs.chain: denormalized chain identity ---
    op.add_column("jobs", sa.Column("chain", sa.String(length=100), nullable=True))

    # Backfill from request['chain'], canonicalized; NULL/missing -> 'ethereum'.
    # One UPDATE per distinct raw value keeps the canonicalization in Python
    # (shared with runtime) while staying a handful of set-based writes.
    bind = op.get_bind()
    from utils.chains import canonical_chain

    distinct = bind.execute(sa.text("SELECT DISTINCT request->>'chain' AS c FROM jobs")).fetchall()
    for (raw,) in distinct:
        canon = canonical_chain(raw) or "ethereum"
        if raw is None:
            bind.execute(sa.text("UPDATE jobs SET chain = :c WHERE request->>'chain' IS NULL"), {"c": canon})
        else:
            bind.execute(sa.text("UPDATE jobs SET chain = :c WHERE request->>'chain' = :r"), {"c": canon, "r": raw})

    # --- address_labels: (address) PK -> (address, chain) ---
    op.add_column(
        "address_labels",
        sa.Column("chain", sa.String(length=100), nullable=False, server_default="ethereum"),
    )
    op.drop_constraint("address_labels_pkey", "address_labels", type_="primary")
    op.create_primary_key("address_labels_pkey", "address_labels", ["address", "chain"])


def downgrade() -> None:
    op.drop_constraint("address_labels_pkey", "address_labels", type_="primary")
    op.create_primary_key("address_labels_pkey", "address_labels", ["address"])
    op.drop_column("address_labels", "chain")

    op.drop_column("jobs", "chain")
