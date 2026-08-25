"""contract_membership_witnesses: index the via and the evidence

Revision ID: d5b1c73f9e08
Revises: c4e8b2f61a37
Create Date: 2026-08-25

Two revocation lookups run on EVERY fact-writer commit and both were sequential
scans:

* ``_revocation_quiescence`` selects the active witnesses whose ``via_address``
  is in the dirty frontier — the partial unique indexes on
  (contract, protocol, rule, via_address) cannot serve a via-only predicate,
  because ``via_address`` is their fourth column.
* ``_vias_citing_evidence_address`` matches an address inside a W3 witness's
  published proof — an ``anchor_chain`` link or terminal anchor, or the member
  hosting a ``principal_fact`` — which needs a jsonb path index to avoid
  reading every row.

The via index is partial on the active rows: a revoked witness is history and is
never a revocation target, so it does not belong in the index the frontier
probes. The GIN index uses ``jsonb_path_ops``, which serves the ``@>``
containment the link lookup issues and is roughly half the size of the default
operator class.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "d5b1c73f9e08"
down_revision: Union[str, Sequence[str], None] = "c4e8b2f61a37"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        "ix_contract_membership_witnesses_active_via",
        "contract_membership_witnesses",
        ["via_address"],
        unique=False,
        postgresql_where=sa.text("revoked_at IS NULL AND via_address IS NOT NULL"),
    )
    op.create_index(
        "ix_contract_membership_witnesses_evidence",
        "contract_membership_witnesses",
        ["evidence"],
        unique=False,
        postgresql_using="gin",
        postgresql_ops={"evidence": "jsonb_path_ops"},
    )


def downgrade() -> None:
    op.drop_index("ix_contract_membership_witnesses_evidence", table_name="contract_membership_witnesses")
    op.drop_index("ix_contract_membership_witnesses_active_via", table_name="contract_membership_witnesses")
