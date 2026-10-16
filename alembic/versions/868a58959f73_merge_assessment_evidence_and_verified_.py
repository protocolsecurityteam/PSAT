"""Merge assessment evidence and verified compiler migrations

Revision ID: 868a58959f73
Revises: d8e4f2a6b901, b6e3a9d1c5f7
Create Date: 2026-10-16 01:29:59.194286

Join both histories without changing tables or data.
"""

from __future__ import annotations

from typing import Sequence, Union

revision: str = "868a58959f73"
down_revision: Union[str, Sequence[str], None] = ("d8e4f2a6b901", "b6e3a9d1c5f7")
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
