"""Preserve existing restaking cursors during tracking-plan reconciliation."""

from alembic import op

revision = "e27a490bc381"
down_revision = "d58b239c7e10"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # PubkeyLinked(bytes32,address,uint256,bytes). Existing fold cursors shared
    # the tracking-plan token; preserve progress and the independent consumer.
    op.execute(
        "UPDATE indexed_event_cursors SET enrollment_basis = 'restaking_fold_asserted' "
        "WHERE enrollment_basis = 'tracked_topics_asserted' "
        "AND topic0 = '0x5e525a525cf73653f769c8305dc71a68b85b0e62e3cc5258fe187ff9fd3e5cb9'"
    )


def downgrade() -> None:
    raise RuntimeError("Restaking provenance cannot safely be collapsed into tracking-plan enrollment")
