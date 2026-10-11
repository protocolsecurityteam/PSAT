"""contracts.upgrade_history_status, and the company-page contracts trigger compares it.

Revision ID: c3d9e5a1f7b2
Revises: a7f3c1e9d2b4

Upgrade counts and implementation windows read it, so a proxy whose fetch errored stops reading as never upgraded.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "c3d9e5a1f7b2"
down_revision: Union[str, Sequence[str], None] = "a7f3c1e9d2b4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_BASE_COLUMNS = (
    "id, job_id, protocol_id, nominated_protocol_id, address, chain, contract_name, "
    "is_proxy, proxy_type, implementation, secondary_implementations, beacon, admin, deployer"
)


def _define_update(columns: str) -> None:
    keys = """SELECT unnest(ARRAY['contract:' || r.id, 'address:' || lower(r.address),
            'protocol:' || r.protocol_id || ':contract:' || r.id,
            'protocol:' || r.nominated_protocol_id || ':contract:' || r.id]) AS key FROM ({rows}) r"""
    query = " UNION ALL ".join(
        keys.format(rows=f"SELECT {columns} FROM {rows} EXCEPT SELECT {columns} FROM {other}")
        for rows, other in (("old_rows", "new_rows"), ("new_rows", "old_rows"))
    )
    op.execute(f"""CREATE OR REPLACE FUNCTION psat_page_contracts_update() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN PERFORM psat_page_touch(ARRAY({query})); RETURN NULL; END
        $$""")


def upgrade() -> None:
    op.add_column("contracts", sa.Column("upgrade_history_status", sa.String(16), nullable=True))
    _define_update(_BASE_COLUMNS + ", upgrade_history_status")


def downgrade() -> None:
    _define_update(_BASE_COLUMNS)
    op.drop_column("contracts", "upgrade_history_status")
