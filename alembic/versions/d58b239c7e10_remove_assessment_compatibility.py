"""Reserve the Assessment cutover revision without contracting old readers."""

revision = "d58b239c7e10"
down_revision = "c4a91e7b2d60"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The earlier draft contracted columns here, immediately after its expand
    # migration.  The temporal cutover now defers every destructive operation
    # until immutable records have been imported and reconciled.
    pass


def downgrade() -> None:
    pass
