"""Rename artifacts.size_bytes -> stored_object_size_bytes

The column records the length of the object written to the bucket, never the
length of anything held in the row. On every one of the 5,770 rows in this
database ``data`` is the jsonb scalar ``null`` and ``text_data`` is NULL while
``size_bytes`` is nonzero (min 2, max 212,466) — so a size-based liveness check
read "this row is populated" from a column that only ever proved "a remote
object of that size exists". The name now states which.

Revision ID: a17c4e90b3d2
Revises: c5a8d3f1b704
Create Date: 2026-07-26

"""

from collections.abc import Sequence

from alembic import op

revision: str = "a17c4e90b3d2"
down_revision: str | Sequence[str] | None = "c5a8d3f1b704"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column("artifacts", "size_bytes", new_column_name="stored_object_size_bytes")
    op.execute(
        "COMMENT ON COLUMN artifacts.stored_object_size_bytes IS "
        "'Byte length of the object at storage_key in the bucket. Says nothing "
        "about data/text_data, which are null whenever this is set.'"
    )


def downgrade() -> None:
    op.execute("COMMENT ON COLUMN artifacts.stored_object_size_bytes IS NULL")
    op.alter_column("artifacts", "stored_object_size_bytes", new_column_name="size_bytes")
