"""Token/protocol reference: whether a protocol's own discovery names a token.

A sibling to ``token_delivery_evidence`` and its OPPOSITE in lifecycle, which is
the whole reason it is a table rather than a column beside the delivery verdict.

Delivery evidence accretes: a receipt read at a block is a fact that never comes
back. This table is REFRESHED every producer cycle, because the predicate behind
``absent_from_universe`` is anti-monotone — discovery growing can only turn an
absence into a presence — so a verdict taken against a smaller universe must be
able to withdraw. Withdrawal is the safe direction (SHEET_OBSERVATION_SPEC.md
§10.6.5), and a row that could not withdraw would pin a condemnation the tree has
already dissolved.

It exists because the presentation layer cannot assemble the universe itself:
``services.scoring.distill.load_protocol_universe`` is a measured 26.5-second
object-storage read, which is not something an API path may do. The producers
assemble it once per cycle and store the verdict per token.

Absence of a row reads as ``not_determined`` at every consumer, and
``not_determined`` presents the holding. Nothing is pulled from a sheet because
no verdict was stored for it.

Revision ID: a6b2e0f37c19
Revises: d7f4c2a91e35
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "a6b2e0f37c19"
down_revision = "d7f4c2a91e35"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "token_protocol_reference",
        # BIGSERIAL, matching the schema's other BigInteger primary keys. An
        # IDENTITY column would read back as a default the ORM model does not
        # declare, which is exactly what ``alembic check`` compares.
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "protocol_id",
            sa.Integer(),
            sa.ForeignKey("protocols.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("chain_id", sa.Integer(), nullable=False),
        sa.Column("token_address", sa.String(length=42), nullable=False),
        sa.Column("reference_shape", sa.String(length=32), nullable=False, server_default="not_determined"),
        sa.Column("universe_addresses", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("basis", sa.Text(), nullable=False),
        sa.Column("measured_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("protocol_id", "chain_id", "token_address", name="uq_tpr_protocol_chain_token"),
        sa.CheckConstraint(
            "reference_shape IN ('in_universe', 'absent_from_universe', 'not_determined')",
            name="ck_tpr_reference_shape_vocabulary",
        ),
        # An empty universe cannot witness an absence — it would condemn
        # everything held. The fail-closed answer under a universe that could not
        # be built is ``not_determined``, and this keeps that from being edited
        # away by a later writer.
        sa.CheckConstraint(
            "reference_shape <> 'absent_from_universe' OR universe_addresses > 0",
            name="ck_tpr_absence_needs_a_universe",
        ),
    )
    op.create_index("ix_tpr_protocol_chain", "token_protocol_reference", ["protocol_id", "chain_id"])


def downgrade() -> None:
    op.drop_index("ix_tpr_protocol_chain", table_name="token_protocol_reference")
    op.drop_table("token_protocol_reference")
