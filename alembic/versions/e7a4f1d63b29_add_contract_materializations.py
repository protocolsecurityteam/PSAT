"""add contract_materializations table

Revision ID: e7a4f1d63b29
Revises: d1e3a8c2f9b4
Create Date: 2026-05-02 19:00:00.000000

Cross-job, cross-process materialization cache. Today three caches exist
around contract materialization (etherscan_cache, _ARTIFACT_CACHE,
nested_artifacts) and none of them dedupe across worker processes.
Two impl jobs in the same protocol therefore each pay full forge+Slither
cost on every shared sub-contract — the LP+EtherFi PR-62 incident.

Schema notes:
  - PRIMARY KEY (chain, bytecode_keccak): the dedup key. Two contracts
    deployed at different addresses with byte-identical bytecode (every
    OZ ERC1967Proxy, every Gnosis Safe singleton) share one row.
  - UNIQUE (chain, address): supports address-keyed lookups in the
    historical schema. A later migration replaces string chain identity
    with numeric ``chain_id``.
  - status: 'pending' marks a row whose builder is in flight (someone
    holds the advisory lock); 'ready' marks a usable cache row;
    'failed' marks a row whose last build threw — kept for ops triage,
    not consulted on lookup.
  - analysis / tracking_plan: stored INLINE as JSONB. Keeping the bundle
    in Postgres keeps the offline test path (no Tigris) self-contained
    and the row self-describing. A future migration can move large
    payloads to Tigris keyed by ``analysis_blob_key`` / ``tracking_plan_blob_key``
    when the table grows.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "e7a4f1d63b29"
down_revision: Union[str, Sequence[str], None] = "d1e3a8c2f9b4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "contract_materializations",
        sa.Column("chain", sa.String(length=100), nullable=False),
        sa.Column("bytecode_keccak", sa.String(length=66), nullable=False),
        sa.Column("address", sa.String(length=42), nullable=False),
        sa.Column("contract_name", sa.String(length=255), nullable=True),
        sa.Column("analysis", postgresql.JSONB(), nullable=True),
        sa.Column("tracking_plan", postgresql.JSONB(), nullable=True),
        sa.Column("analysis_blob_key", sa.Text(), nullable=True),
        sa.Column("tracking_plan_blob_key", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="pending"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("materialized_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.PrimaryKeyConstraint("chain", "bytecode_keccak"),
        sa.UniqueConstraint("chain", "address", name="uq_contract_materializations_chain_address"),
    )
    op.create_index(
        "ix_contract_materializations_status",
        "contract_materializations",
        ["status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_contract_materializations_status", table_name="contract_materializations")
    op.drop_table("contract_materializations")
