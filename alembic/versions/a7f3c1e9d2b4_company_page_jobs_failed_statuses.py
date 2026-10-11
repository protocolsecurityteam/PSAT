"""Company-page jobs trigger also publishes a member job entering or leaving a failed status.

Revision ID: a7f3c1e9d2b4
Revises: b7e2c4a91f30

The overview lists members with no completed analysis by whether an attempt failed, so a job turning failed or
failed_terminal (or a failed job being requeued) changes the page. Queued and processing rows stay quiet, so lease
renewals still touch nothing.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "a7f3c1e9d2b4"
down_revision: Union[str, Sequence[str], None] = "b7e2c4a91f30"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_COLUMNS = "id, address, status, chain_id, request, name, is_proxy, created_at, updated_at"
_PUBLISHED = "('completed', 'failed', 'failed_terminal')"
_COMPLETED_ONLY = "('completed')"


def _keys(rows: str, statuses: str) -> str:
    return f"""SELECT unnest(ARRAY['address:' || lower(r.address),
            'protocol:' || c.protocol_id || ':contract:' || c.id,
            'protocol:' || c.nominated_protocol_id || ':contract:' || c.id]) AS key
            FROM {rows} r LEFT JOIN contracts c ON c.address = lower(r.address)
            WHERE r.status IN {statuses} AND r.address IS NOT NULL"""


def _define(statuses: str) -> None:
    changed = " UNION ALL ".join(
        _keys(f"(SELECT {_COLUMNS} FROM {rows} EXCEPT SELECT {_COLUMNS} FROM {other})", statuses)
        for rows, other in (("old_rows", "new_rows"), ("new_rows", "old_rows"))
    )
    for event, query in (
        ("insert", _keys("new_rows", statuses)),
        ("update", changed),
        ("delete", _keys("old_rows", statuses)),
    ):
        op.execute(f"""CREATE OR REPLACE FUNCTION psat_page_jobs_{event}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN PERFORM psat_page_touch(ARRAY({query})); RETURN NULL; END
        $$""")


def upgrade() -> None:
    _define(_PUBLISHED)


def downgrade() -> None:
    _define(_COMPLETED_ONLY)
