"""role_holder_plane_refreshes: which registry the role floors were folded for, and when

Revision ID: f4d18a7c0b93
Revises: e8c2f47a19d3
Create Date: 2026-07-31

``role_holder_planes`` is keyed by ROLE, so it answers nothing about a REGISTRY
that produced no role: a registry whose fold proposed no candidate is absent from
it in exactly the same way as a registry no pass ever ran against. A periodic
refresher that cannot tell those apart either re-scans every registry every pass
or skips one that was never observed.

This table is the per-registry watermark that removes the ambiguity. Row absence
means never refreshed; ``outcome`` plus ``rows_written`` say what a completed
pass found; and the three observation columns (``trigger_log_block``,
``cursors_warm``, ``refreshed_at``) are what a later pass compares against to
decide the registry is due again.

Rows are minted only where the AccessControl cursor pair exists, so a registry
whose gate was closed stays rowless — it re-selects on its own once the indexer
enrolls it, without a timer to expire or a flag to clear.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "f4d18a7c0b93"
down_revision: Union[str, Sequence[str], None] = "e8c2f47a19d3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "role_holder_plane_refreshes",
        sa.Column("chain_id", sa.Integer(), nullable=False),
        sa.Column("registry_address", sa.String(length=42), nullable=False),
        sa.Column("refreshed_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        # NULL = no AccessControl log was indexed for this registry at the pass.
        # An observation of the index, never a claim that none were emitted.
        sa.Column("trigger_log_block", sa.BigInteger(), nullable=True),
        sa.Column("cursors_warm", sa.Boolean(), nullable=False),
        sa.Column("rows_written", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.PrimaryKeyConstraint("chain_id", "registry_address"),
        sa.CheckConstraint(
            "outcome IN ('no_rows', 'rows_written')",
            name="ck_role_holder_plane_refreshes_outcome_domain",
        ),
        # The count and the token are one fact. Split, a pass could record
        # "confirmed nothing" over rows it wrote, which would stop the registry
        # re-selecting on the evidence that it does have roles to track.
        sa.CheckConstraint(
            "(outcome = 'rows_written') = (rows_written > 0)",
            name="ck_role_holder_plane_refreshes_outcome_matches_count",
        ),
        sa.CheckConstraint(
            "rows_written >= 0",
            name="ck_role_holder_plane_refreshes_count_non_negative",
        ),
    )


def downgrade() -> None:
    op.drop_table("role_holder_plane_refreshes")
