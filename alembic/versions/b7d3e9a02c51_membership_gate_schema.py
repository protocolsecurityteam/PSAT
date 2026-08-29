"""Membership-gate schema: nominations, witnesses, deployer registry, ops_kv.

DISCOVERY_MEMBERSHIP_GATE_SPEC.md §4. Additions only; nothing dropped.

- ``contracts.nominated_protocol_id`` — which protocol nominated the address
  (§3.1). Backfilled for existing orphans from job provenance, else the
  single-protocol deployment; rows with neither stay NULL (``unclaimed``).
- ``contract_membership_witnesses`` — one row per recorded membership reason
  (§4.2). Uniqueness on (contract, protocol, rule, via_address) is a partial
  index pair because Postgres treats NULL ≠ NULL and w1/w5/w6 rows carry no
  via_address.
- ``protocol_deployers`` — the §3.3 trust ladder registry. Class C is the
  absence of a row.
- ``contract_probe_attempts`` — latest owner/authority/EIP-1967 probe reads
  per (contract, chain) so a parked candidate is explainable (§3.5,
  invariant 5). ``contract_creation_witnesses`` keeps the code/creation arm
  unchanged (§4.4).
- ``ops_kv`` — minimal persistent marker store for ``enabled_chains_seen``
  (§3.4 event 4).

Revision ID: b7d3e9a02c51
Revises: e5b2d9a41c73
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "b7d3e9a02c51"
down_revision: Union[str, Sequence[str], None] = "e5b2d9a41c73"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("contracts", sa.Column("nominated_protocol_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        "fk_contracts_nominated_protocol_id",
        "contracts",
        "protocols",
        ["nominated_protocol_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_contracts_nominated_protocol_id", "contracts", ["nominated_protocol_id"])

    # Orphan backfill (§4.1): job provenance first, then the single-protocol
    # deployment; rows with neither stay NULL (unclaimed). Source tags carry no
    # protocol linkage, so they cannot recover it.
    op.execute(
        sa.text(
            "UPDATE contracts SET nominated_protocol_id = jobs.protocol_id "
            "FROM jobs "
            "WHERE contracts.job_id = jobs.id "
            "AND contracts.protocol_id IS NULL "
            "AND contracts.nominated_protocol_id IS NULL "
            "AND jobs.protocol_id IS NOT NULL"
        )
    )
    op.execute(
        sa.text(
            "UPDATE contracts SET nominated_protocol_id = (SELECT min(id) FROM protocols) "
            "WHERE protocol_id IS NULL "
            "AND nominated_protocol_id IS NULL "
            "AND (SELECT count(*) FROM protocols) = 1"
        )
    )

    op.create_table(
        "contract_membership_witnesses",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("contract_id", sa.Integer(), nullable=False),
        sa.Column("protocol_id", sa.Integer(), nullable=False),
        sa.Column("rule", sa.String(length=32), nullable=False),
        sa.Column("via_address", sa.String(length=42), nullable=True),
        sa.Column("evidence", postgresql.JSONB(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["contract_id"], ["contracts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["protocol_id"], ["protocols.id"], ondelete="CASCADE"),
        sa.CheckConstraint(
            "rule IN ('w1_code', 'w2_structural', 'w3_control', 'w4_deployer', 'w5_human', 'w6_llama_seed')",
            name="ck_contract_membership_witnesses_rule",
        ),
    )
    op.create_index("ix_contract_membership_witnesses_contract_id", "contract_membership_witnesses", ["contract_id"])
    op.create_index("ix_contract_membership_witnesses_protocol_id", "contract_membership_witnesses", ["protocol_id"])
    op.create_index(
        "uq_membership_witness_with_via",
        "contract_membership_witnesses",
        ["contract_id", "protocol_id", "rule", "via_address"],
        unique=True,
        postgresql_where=sa.text("via_address IS NOT NULL"),
    )
    op.create_index(
        "uq_membership_witness_no_via",
        "contract_membership_witnesses",
        ["contract_id", "protocol_id", "rule"],
        unique=True,
        postgresql_where=sa.text("via_address IS NULL"),
    )

    op.create_table(
        "protocol_deployers",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("protocol_id", sa.Integer(), nullable=False),
        sa.Column("address", sa.String(length=42), nullable=False),
        sa.Column("trust_class", sa.String(length=1), nullable=False),
        sa.Column("evidence", postgresql.JSONB(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["protocol_id"], ["protocols.id"], ondelete="CASCADE"),
        sa.CheckConstraint("trust_class IN ('A', 'B')", name="ck_protocol_deployers_trust_class"),
        sa.UniqueConstraint("protocol_id", "address", name="uq_protocol_deployers_protocol_address"),
    )
    op.create_index("ix_protocol_deployers_address", "protocol_deployers", ["address"])

    op.create_table(
        "contract_probe_attempts",
        sa.Column("contract_id", sa.Integer(), nullable=False),
        sa.Column("chain_id", sa.Integer(), nullable=False),
        sa.Column("block_number", sa.BigInteger(), nullable=True),
        sa.Column("results", postgresql.JSONB(), nullable=False),
        sa.Column("probed_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.PrimaryKeyConstraint("contract_id", "chain_id"),
        sa.ForeignKeyConstraint(["contract_id"], ["contracts.id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_contract_probe_attempts_resolved",
        "contract_probe_attempts",
        [sa.text("(results->'resolved_addresses')")],
        postgresql_using="gin",
    )

    op.create_table(
        "ops_kv",
        sa.Column("key", sa.String(length=128), nullable=False),
        sa.Column("value", postgresql.JSONB(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )


def downgrade() -> None:
    op.drop_table("ops_kv")
    op.drop_index("ix_contract_probe_attempts_resolved", table_name="contract_probe_attempts")
    op.drop_table("contract_probe_attempts")
    op.drop_index("ix_protocol_deployers_address", table_name="protocol_deployers")
    op.drop_table("protocol_deployers")
    op.drop_index("uq_membership_witness_no_via", table_name="contract_membership_witnesses")
    op.drop_index("uq_membership_witness_with_via", table_name="contract_membership_witnesses")
    op.drop_index("ix_contract_membership_witnesses_protocol_id", table_name="contract_membership_witnesses")
    op.drop_index("ix_contract_membership_witnesses_contract_id", table_name="contract_membership_witnesses")
    op.drop_table("contract_membership_witnesses")
    op.drop_index("ix_contracts_nominated_protocol_id", table_name="contracts")
    op.drop_constraint("fk_contracts_nominated_protocol_id", "contracts", type_="foreignkey")
    op.drop_column("contracts", "nominated_protocol_id")
