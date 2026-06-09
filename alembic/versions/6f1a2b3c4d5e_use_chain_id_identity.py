"""use chain_id for persisted chain identity

Revision ID: 6f1a2b3c4d5e
Revises: d4e8f1a9c2b7
Create Date: 2026-06-08 00:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "6f1a2b3c4d5e"
down_revision: Union[str, Sequence[str], None] = "d4e8f1a9c2b7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("jobs", sa.Column("chain_id", sa.Integer(), nullable=True))
    op.execute(
        sa.text(
            """
            UPDATE jobs
            SET chain_id = (request->>'chain_id')::integer
            WHERE request IS NOT NULL
              AND request ? 'chain_id'
              AND (request->>'chain_id') ~ '^[0-9]+$'
            """
        )
    )
    op.create_index("ix_jobs_address_chain_id", "jobs", ["address", "chain_id"], unique=False)

    op.add_column("job_dependencies", sa.Column("provider_chain_id", sa.Integer(), nullable=False))
    op.drop_index("ix_job_dep_provider", table_name="job_dependencies")
    op.drop_constraint("uq_job_dep_edge", "job_dependencies", type_="unique")
    op.drop_column("job_dependencies", "provider_chain")
    op.create_unique_constraint(
        "uq_job_dep_edge",
        "job_dependencies",
        ["depender_job_id", "provider_chain_id", "provider_address", "required_stage"],
    )
    op.create_index(
        "ix_job_dep_provider",
        "job_dependencies",
        ["provider_chain_id", "provider_address", "required_stage", "status"],
        unique=False,
    )

    op.add_column("watched_proxies", sa.Column("chain_id", sa.Integer(), nullable=False))
    op.drop_constraint("uq_watched_proxy_address_chain", "watched_proxies", type_="unique")
    op.drop_column("watched_proxies", "chain")
    op.create_unique_constraint(
        "uq_watched_proxy_address_chain_id", "watched_proxies", ["proxy_address", "chain_id"]
    )

    op.add_column("contracts", sa.Column("chain_id", sa.Integer(), nullable=False))
    op.drop_constraint("uq_contract_address_chain", "contracts", type_="unique")
    op.drop_column("contracts", "chains")
    op.drop_column("contracts", "chain")
    op.create_unique_constraint("uq_contract_address_chain_id", "contracts", ["address", "chain_id"])

    op.add_column("monitored_contracts", sa.Column("chain_id", sa.Integer(), nullable=False))
    op.drop_constraint("uq_monitored_contract_address_chain", "monitored_contracts", type_="unique")
    op.drop_column("monitored_contracts", "chain")
    op.create_unique_constraint(
        "uq_monitored_contract_address_chain_id", "monitored_contracts", ["address", "chain_id"]
    )

    op.add_column("contract_materializations", sa.Column("chain_id", sa.Integer(), nullable=False))
    op.drop_constraint("uq_contract_materializations_chain_address", "contract_materializations", type_="unique")
    op.drop_constraint("contract_materializations_pkey", "contract_materializations", type_="primary")
    op.drop_column("contract_materializations", "chain")
    op.create_primary_key("contract_materializations_pkey", "contract_materializations", ["chain_id", "bytecode_keccak"])
    op.create_unique_constraint(
        "uq_contract_materializations_chain_id_address",
        "contract_materializations",
        ["chain_id", "address"],
    )

    op.add_column("mapping_enumeration_cache", sa.Column("chain_id", sa.Integer(), nullable=False))
    op.drop_constraint("mapping_enumeration_cache_pkey", "mapping_enumeration_cache", type_="primary")
    op.drop_column("mapping_enumeration_cache", "chain")
    op.create_primary_key(
        "mapping_enumeration_cache_pkey",
        "mapping_enumeration_cache",
        ["chain_id", "address", "specs_hash"],
    )


def downgrade() -> None:
    raise NotImplementedError("Downgrade from numeric chain identity is unsupported.")
