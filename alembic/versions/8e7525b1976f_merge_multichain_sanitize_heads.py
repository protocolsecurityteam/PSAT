"""merge multichain + sanitize heads

Revision ID: 8e7525b1976f
Revises: 67bd81b64faa, b8d4f2a1c9e6
Create Date: 2026-05-21 22:03:33.128389

Safety checklist (delete once reviewed):
  - CREATE INDEX CONCURRENTLY / ALTER TYPE ADD VALUE must run in
    ``with op.get_context().autocommit_block():`` — they cannot run inside
    a transaction.
  - Adding a NOT NULL column to a populated table needs a server_default
    (or a 3-step add-nullable / backfill / set-not-null sequence).
  - Don't rename columns in one step on a live deploy — old code is still
    reading the old name. Add new column, dual-write, drop later.
  - env.py sets lock_timeout=10s / statement_timeout=300s. Override inside
    the migration if the operation legitimately needs longer.
"""

from __future__ import annotations

from typing import Sequence, Union

revision: str = "8e7525b1976f"
down_revision: Union[str, Sequence[str], None] = ("67bd81b64faa", "b8d4f2a1c9e6")
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
