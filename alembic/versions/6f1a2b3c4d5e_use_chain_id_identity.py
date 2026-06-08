"""use chain_id for persisted chain identity

Revision ID: 6f1a2b3c4d5e
Revises: d4e8f1a9c2b7
Create Date: 2026-06-08 00:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "6f1a2b3c4d5e"
down_revision: Union[str, Sequence[str], None] = "d4e8f1a9c2b7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _chain_label_sql(expr: str) -> str:
    return f"""
    CASE {expr}
      WHEN 1 THEN 'ethereum'
      WHEN 42161 THEN 'arbitrum'
      WHEN 10 THEN 'optimism'
      WHEN 8453 THEN 'base'
      WHEN 137 THEN 'polygon'
      WHEN 43114 THEN 'avalanche'
      WHEN 56 THEN 'bsc'
      WHEN 59144 THEN 'linea'
      WHEN 534352 THEN 'scroll'
      WHEN 324 THEN 'zksync'
      WHEN 81457 THEN 'blast'
      WHEN 34443 THEN 'mode'
      WHEN 80094 THEN 'berachain'
      ELSE NULL
    END
    """


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
    op.add_column("mapping_enumeration_cache", sa.Column("chain", sa.String(length=100), nullable=True))
    op.execute(sa.text(f"UPDATE mapping_enumeration_cache SET chain = {_chain_label_sql('chain_id')}"))
    op.alter_column("mapping_enumeration_cache", "chain", nullable=False)
    op.drop_constraint("mapping_enumeration_cache_pkey", "mapping_enumeration_cache", type_="primary")
    op.drop_column("mapping_enumeration_cache", "chain_id")
    op.create_primary_key("mapping_enumeration_cache_pkey", "mapping_enumeration_cache", ["chain", "address", "specs_hash"])

    op.add_column("contract_materializations", sa.Column("chain", sa.String(length=100), nullable=True))
    op.execute(sa.text(f"UPDATE contract_materializations SET chain = {_chain_label_sql('chain_id')}"))
    op.alter_column("contract_materializations", "chain", nullable=False)
    op.drop_constraint("uq_contract_materializations_chain_id_address", "contract_materializations", type_="unique")
    op.drop_constraint("contract_materializations_pkey", "contract_materializations", type_="primary")
    op.drop_column("contract_materializations", "chain_id")
    op.create_primary_key("contract_materializations_pkey", "contract_materializations", ["chain", "bytecode_keccak"])
    op.create_unique_constraint(
        "uq_contract_materializations_chain_address", "contract_materializations", ["chain", "address"]
    )

    op.add_column("monitored_contracts", sa.Column("chain", sa.String(length=100), nullable=True))
    op.execute(sa.text(f"UPDATE monitored_contracts SET chain = {_chain_label_sql('chain_id')}"))
    op.alter_column("monitored_contracts", "chain", nullable=False)
    op.drop_constraint("uq_monitored_contract_address_chain_id", "monitored_contracts", type_="unique")
    op.drop_column("monitored_contracts", "chain_id")
    op.create_unique_constraint("uq_monitored_contract_address_chain", "monitored_contracts", ["address", "chain"])

    op.add_column("contracts", sa.Column("chain", sa.String(length=100), nullable=True))
    op.add_column("contracts", sa.Column("chains", postgresql.ARRAY(sa.String(length=100)), nullable=True))
    op.execute(sa.text(f"UPDATE contracts SET chain = {_chain_label_sql('chain_id')}"))
    op.execute(
        sa.text(
            """
            UPDATE contracts
            SET chains = ARRAY[chain]
            WHERE chain IS NOT NULL
            """
        )
    )
    op.drop_constraint("uq_contract_address_chain_id", "contracts", type_="unique")
    op.drop_column("contracts", "chain_id")
    op.create_unique_constraint("uq_contract_address_chain", "contracts", ["address", "chain"])

    op.add_column("watched_proxies", sa.Column("chain", sa.String(), nullable=True))
    op.execute(sa.text(f"UPDATE watched_proxies SET chain = {_chain_label_sql('chain_id')}"))
    op.alter_column("watched_proxies", "chain", nullable=False)
    op.drop_constraint("uq_watched_proxy_address_chain_id", "watched_proxies", type_="unique")
    op.drop_column("watched_proxies", "chain_id")
    op.create_unique_constraint("uq_watched_proxy_address_chain", "watched_proxies", ["proxy_address", "chain"])

    op.add_column("job_dependencies", sa.Column("provider_chain", sa.String(length=50), nullable=True))
    op.execute(sa.text(f"UPDATE job_dependencies SET provider_chain = {_chain_label_sql('provider_chain_id')}"))
    op.drop_index("ix_job_dep_provider", table_name="job_dependencies")
    op.drop_constraint("uq_job_dep_edge", "job_dependencies", type_="unique")
    op.drop_column("job_dependencies", "provider_chain_id")
    op.create_unique_constraint(
        "uq_job_dep_edge",
        "job_dependencies",
        ["depender_job_id", "provider_chain", "provider_address", "required_stage"],
    )
    op.create_index(
        "ix_job_dep_provider",
        "job_dependencies",
        ["provider_chain", "provider_address", "required_stage", "status"],
        unique=False,
    )

    op.drop_index("ix_jobs_address_chain_id", table_name="jobs")
    op.drop_column("jobs", "chain_id")
