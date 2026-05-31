"""retag current proxy impls: upgrade_history -> current_implementation

Revision ID: e9c3a5b2d7f4
Revises: d8b2f4a1c6e3
Create Date: 2026-05-30 00:10:00.000000

The upgrade-history backfill stamped ``upgrade_history`` on every impl that
appears in a proxy's ``Upgraded`` events — including the proxy's CURRENT live
impl (it appears in the last event). The anchor predicate then excluded that
live impl from analysis, requeue, and resolution-coverage metrics, hiding the
proxy's real functions + principals.

Re-tag the current live impl of every proxy: drop ``upgrade_history`` and add
``current_implementation`` (the live marker honoured by
services/discovery/ranking.not_superseded_impl_clause). Genuinely superseded
impls — addresses that are NOT the current ``implementation`` of any live
proxy — keep ``upgrade_history`` and stay excluded.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "e9c3a5b2d7f4"
down_revision: Union[str, Sequence[str], None] = "d8b2f4a1c6e3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        UPDATE contracts c
        SET discovery_sources =
            array_append(array_remove(c.discovery_sources, 'upgrade_history'), 'current_implementation')
        WHERE c.discovery_sources IS NOT NULL
          AND 'upgrade_history' = ANY(c.discovery_sources)
          AND 'current_implementation' <> ALL(c.discovery_sources)
          AND lower(c.address) IN (
              SELECT lower(p.implementation)
              FROM contracts p
              WHERE p.is_proxy AND p.implementation IS NOT NULL
          )
        """
    )


def downgrade() -> None:
    op.execute(
        """
        UPDATE contracts c
        SET discovery_sources =
            array_append(array_remove(c.discovery_sources, 'current_implementation'), 'upgrade_history')
        WHERE c.discovery_sources IS NOT NULL
          AND 'current_implementation' = ANY(c.discovery_sources)
          AND 'upgrade_history' <> ALL(c.discovery_sources)
        """
    )
