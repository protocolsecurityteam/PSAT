"""monitored_events.log_index + partial identity index; last_scanned_block BigInteger

Revision ID: c4d6e8f0a1b3
Revises: b3c5d7e9f1a2
Create Date: 2026-07-08

Stage 4 (design §2.4 Layer 2 / HR2): give scan-path monitored_events an
identity by construction so a duplicate scan pass can never double-insert.

``monitored_events.log_index`` (nullable) + a **partial** unique index over
``(monitored_contract_id, tx_hash, log_index, event_type) WHERE log_index IS
NOT NULL``. The predicate is deliberately partial: poll-path
``state_changed_poll`` rows carry ``tx_hash=''`` / ``block_number=0`` and stay
``log_index NULL``, outside the constraint, so a second legitimate poll
detection on a contract is not silently dropped (design Appendix A rejection of
Design B's full constraint). Historical rows (zero in prod) also stay outside;
no backfill.

``monitored_contracts.last_scanned_block`` Integer -> BigInteger, aligning with
``IndexedEventCursor`` (design §2.8). Additive.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "c4d6e8f0a1b3"
down_revision: Union[str, Sequence[str], None] = "b3c5d7e9f1a2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("monitored_events", sa.Column("log_index", sa.Integer(), nullable=True))
    op.create_index(
        "uq_monitored_events_identity",
        "monitored_events",
        ["monitored_contract_id", "tx_hash", "log_index", "event_type"],
        unique=True,
        postgresql_where=sa.text("log_index IS NOT NULL"),
    )
    op.alter_column(
        "monitored_contracts",
        "last_scanned_block",
        existing_type=sa.Integer(),
        type_=sa.BigInteger(),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "monitored_contracts",
        "last_scanned_block",
        existing_type=sa.BigInteger(),
        type_=sa.Integer(),
        existing_nullable=False,
    )
    op.drop_index("uq_monitored_events_identity", table_name="monitored_events")
    op.drop_column("monitored_events", "log_index")
