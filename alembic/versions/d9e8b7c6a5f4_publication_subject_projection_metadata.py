"""Store mutable pipeline display metadata on immutable publication links.

Address and code subject identities stay stable across contract names, tags,
and controller descriptions. Existing links default to empty metadata and the
reader retains a compatibility fallback for earlier subject identities.
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "d9e8b7c6a5f4"
down_revision = "f6a1c2d3e4b5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "assessment_publication_subjects",
        sa.Column("projection_metadata", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )


def downgrade() -> None:
    op.drop_column("assessment_publication_subjects", "projection_metadata")
