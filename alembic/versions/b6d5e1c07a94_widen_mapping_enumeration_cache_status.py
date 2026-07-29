"""widen mapping_enumeration_cache.status to 64 chars

Revision ID: b6d5e1c07a94
Revises: e2b7d4f9a1c8
Create Date: 2026-07-29 09:00:00.000000

``status`` was sized at 32 by f9c2a83d1e44, when the vocabulary topped
out at ``incomplete_max_pages`` (20). It has since grown
``incomplete_no_hypersync_coverage`` (exactly 32 — no margin) and
``incomplete_ambiguous_writer_event`` (33 — over the edge). An oversized
status makes the whole upsert raise ``StringDataRightTruncation``, and
``db/mapping_enumeration_cache.py`` treats a failed write as a tolerable
lost optimization. It is not: the failed upsert leaves the *previous*
row in place, so a still-fresh ``complete`` keeps being served for an
address whose re-scan honestly came back truncated, and the partial
member set that produced it gets republished as authoritative for the
rest of the TTL.

Additive and non-destructive: VARCHAR(32) -> VARCHAR(64) widens the
domain, so every existing row stays valid and no data is rewritten.
Deliberately not an enum or a CHECK constraint — the vocabulary is
owned by ``services/resolution/mapping_enumerator.py`` and adding a
member should not need a migration. What must not silently regress is
the *fit*, and that is pinned by
``tests/test_mapping_enumeration_status_vocabulary.py``, which
round-trips every status the enumerator can emit through the real
column. The vocabulary is intentionally not enumerated here: a list in
a migration comment is a copy that goes stale.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "b6d5e1c07a94"
down_revision: Union[str, Sequence[str], None] = "e2b7d4f9a1c8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "mapping_enumeration_cache",
        "status",
        existing_type=sa.String(length=32),
        type_=sa.String(length=64),
        existing_nullable=False,
    )


def downgrade() -> None:
    # Narrowing back would fail on any row holding a status longer than
    # 32 chars, which is exactly the population this migration exists to
    # admit. Drop those rows first — they are a TTL-bounded cache, so
    # losing them costs one re-scan and nothing else.
    op.execute("DELETE FROM mapping_enumeration_cache WHERE length(status) > 32")
    op.alter_column(
        "mapping_enumeration_cache",
        "status",
        existing_type=sa.String(length=64),
        type_=sa.String(length=32),
        existing_nullable=False,
    )
