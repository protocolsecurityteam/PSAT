"""contract_creation_witnesses.creation_genesis: a contract allocated at genesis has no creation tx or deployer.

Revision ID: f1a7c3e9d2b4
Revises: e6f9b3d5a2c7

Etherscan's ``GENESIS`` creator and ``GENESIS_<address>`` tx were stored as a deployer (``0xgenesis``) and a creation
tx; neither is an address or a hash, so both are cleared and the genesis fact is kept as its own column.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "f1a7c3e9d2b4"
down_revision: Union[str, Sequence[str], None] = "e6f9b3d5a2c7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("contract_creation_witnesses", sa.Column("creation_genesis", sa.Boolean(), nullable=True))
    op.execute(
        "UPDATE contract_creation_witnesses SET creation_genesis = true, creation_tx_hash = NULL, "
        "creation_factory = NULL WHERE upper(creation_tx_hash) LIKE 'GENESIS%'"
    )
    op.execute(
        "UPDATE contract_creation_witnesses SET creation_genesis = false "
        "WHERE creation_genesis IS NULL AND creation_tx_hash ~* '^0x[0-9a-f]{64}$'"
    )
    op.execute("UPDATE contracts SET deployer = NULL WHERE deployer IS NOT NULL AND deployer !~* '^0x[0-9a-f]{40}$'")


def downgrade() -> None:
    op.drop_column("contract_creation_witnesses", "creation_genesis")
