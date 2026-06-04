"""add deployment_address to per-deployment resolution-result tables

Revision ID: d4e8f1a9c2b7
Revises: e9c3a5b2d7f4
Create Date: 2026-06-01 00:00:00.000000

A single implementation-bytecode contract row can be the logic behind N
distinct proxy deployments (EIP-1167 clone / beacon families), and each
deployment resolves its controllers against its own proxy storage — so the
same impl ``contract_id`` must hold N independent resolved sets. ``deployment_address``
is the storage-deployment a row was resolved against: the proxy address for an
impl analyzed in proxy context, NULL for a contract resolved against its own
storage (the sole/legacy deployment). Writers scope their wholesale delete to
``(contract_id, deployment_address)`` (sweeping legacy NULL rows on first
re-resolution); readers that must disambiguate filter by it.

NULL for the overwhelming majority of rows (no shared impls today); the column
is a no-op for the 1:1 proxy⇄impl case that dominates current data.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "d4e8f1a9c2b7"
down_revision: Union[str, Sequence[str], None] = "e9c3a5b2d7f4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLES = (
    "effective_functions",
    "controller_values",
    "control_graph_nodes",
    "control_graph_edges",
    "principal_labels",
)


def upgrade() -> None:
    for table in _TABLES:
        op.add_column(table, sa.Column("deployment_address", sa.String(length=42), nullable=True))


def downgrade() -> None:
    for table in _TABLES:
        op.drop_column(table, "deployment_address")
