"""Delivery-shape evidence: how a (chain, token, holder) balance arrived.

A plane of its own, and the reasons are measured rather than stylistic.

``contract_balances`` rows are evicted — retention depth 10 plus ``ON DELETE
CASCADE`` from the fetch — so an annotation carried there is gone within about
ten producer cycles and every delivering receipt would have to be re-read. A
delivering transaction is block-stamped and immutable; it outlives every fetch
that ever observed the holding. And a (holder, token) delivery is a fact about
two addresses, not about the protocol whose producer happened to measure it, so
nothing here is protocol-scoped.

Rows ACCRETE and are never rewritten: a later cycle may append deliveries found
above ``measured_through_block`` and advance that cursor, and may do nothing
else. ``measured_through_block`` is both the extent of the all-quantifier and
the cursor that keeps the full-history pass a once-per-pair cost.

The claim stored here is delivery SHAPE. It never says a token is worthless — a
real token can be airdrop-delivered, which is measured on this corpus.

Revision ID: d7f4c2a91e35
Revises: c3a9f21b7d48
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "d7f4c2a91e35"
down_revision = "c3a9f21b7d48"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "token_delivery_evidence",
        # BIGSERIAL, matching the seven other BigInteger primary keys in this
        # schema. An IDENTITY column here would read back as a default the ORM
        # model does not declare, which is exactly what ``alembic check``
        # compares — and a check that fails on the schema's own shape is a
        # check nobody can use to catch a real drift.
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("chain_id", sa.Integer(), nullable=False),
        sa.Column("holder_address", sa.String(length=42), nullable=False),
        sa.Column("token_address", sa.String(length=42), nullable=False),
        sa.Column("scanned_from_block", sa.BigInteger(), nullable=False),
        sa.Column("measured_through_block", sa.BigInteger(), nullable=False),
        sa.Column("deliveries", postgresql.JSONB(none_as_null=True), nullable=False),
        sa.Column("delivery_count", sa.Integer(), nullable=False),
        sa.Column("unreadable_deliveries", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("min_fan_out", sa.Integer(), nullable=True),
        sa.Column("fan_out_threshold_k", sa.Integer(), nullable=False),
        sa.Column("delivery_shape", sa.String(length=32), nullable=False, server_default="not_determined"),
        sa.Column("basis", sa.Text(), nullable=False),
        sa.Column("first_measured_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("measured_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("chain_id", "holder_address", "token_address", name="uq_tde_chain_holder_token"),
        # The positive verdict is an all-quantifier over readable receipts: it
        # cannot stand beside a delivery nobody could read, and it cannot stand
        # over an empty delivery set. A holding whose arrival is not on record
        # is not_determined, never airdrop-delivered.
        sa.CheckConstraint(
            "delivery_shape <> 'fan_out_all' OR "
            "(unreadable_deliveries = 0 AND delivery_count > 0 AND min_fan_out >= fan_out_threshold_k)",
            name="ck_tde_fan_out_all_is_earned",
        ),
        # The earned negative must be measured too: a missing reading is not a
        # small fan-out.
        sa.CheckConstraint(
            "delivery_shape <> 'has_direct_delivery' OR "
            "(delivery_count > 0 AND min_fan_out IS NOT NULL AND min_fan_out < fan_out_threshold_k)",
            name="ck_tde_direct_delivery_is_measured",
        ),
        sa.CheckConstraint(
            "delivery_shape IN ('fan_out_all', 'has_direct_delivery', 'not_determined')",
            name="ck_tde_delivery_shape_vocabulary",
        ),
        sa.CheckConstraint("jsonb_typeof(deliveries) = 'array'", name="ck_tde_deliveries_is_array"),
        sa.CheckConstraint("measured_through_block >= scanned_from_block", name="ck_tde_range_is_ordered"),
    )
    op.create_index("ix_tde_chain_token", "token_delivery_evidence", ["chain_id", "token_address"])
    op.create_index("ix_tde_chain_holder", "token_delivery_evidence", ["chain_id", "holder_address"])


def downgrade() -> None:
    op.drop_index("ix_tde_chain_holder", table_name="token_delivery_evidence")
    op.drop_index("ix_tde_chain_token", table_name="token_delivery_evidence")
    op.drop_table("token_delivery_evidence")
