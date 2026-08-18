"""CHECK constraint gating ``monitored_contracts.contract_type``.

The column was an ungated ``String(50)`` while the vocabulary lived only in
``schemas.control_tracking.MonitoredContractType``, so a typo'd or invented
type could be inserted at the ORM layer and every consumer's branch would
silently fall through. The current data carries only vocabulary members
(verified before this migration: regular/pausable/proxy/safe/timelock), so
the constraint validates immediately. ``role_control`` and ``contract`` are
admitted because production code branches on the former and tests plant the
latter as the legacy-row shape; the CHECK and the Literal must list the same
members — update both together or inserts start failing where pyright is
silent.

Revision ID: e5b2d9a41c73
Revises: a7e2c4b90d16
"""

from __future__ import annotations

from alembic import op

revision = "e5b2d9a41c73"
down_revision = "a7e2c4b90d16"
branch_labels = None
depends_on = None

_CONSTRAINT = "ck_monitored_contracts_contract_type"
_MEMBERS = "('regular', 'proxy', 'safe', 'timelock', 'pausable', 'role_control', 'contract')"


def upgrade() -> None:
    op.create_check_constraint(
        _CONSTRAINT,
        "monitored_contracts",
        f"contract_type IN {_MEMBERS}",
    )


def downgrade() -> None:
    op.drop_constraint(_CONSTRAINT, "monitored_contracts", type_="check")
