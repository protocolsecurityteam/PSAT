"""Per-node EigenLayer restaking position: its own plane, never a balance row.

The live EtherFiNode instances are BeaconProxy deployments and have NO
``contracts`` row (measured: zero rows for the probed node and for its pod),
while ``contract_balances.contract_id`` is ``NOT NULL``. Delivering this witness
as balance rows would therefore have required minting a ``contracts`` row per
node, after which ``services.effects.selection`` would read the share quantity as
a HOLDING of a deployment and sum it into the authority graph — closing one gap
by widening another. Nothing in ``contract_balances``,
``contract_balance_fetches`` or ``contract_balances_latest`` is touched here.

There is no USD column on this plane, so a share quantity cannot enter a dollar
figure even by accident.

Every CHECK below is a BACKSTOP. ``services.monitoring.restaking_reads`` decides
the basis first and maps any violating shape to NULL / ``not_determined`` before
a row is built, so one of these firing in production is a bug in the producer.

Two Postgres traps are handled deliberately rather than incidentally:

* a CHECK that evaluates to NULL PASSES. Every arm is written NULL-safe
  (``IS NULL`` / ``IS NOT NULL`` / ``IS NOT DISTINCT FROM``) so that behaviour is
  never load-bearing;
* one level up, the same trap applies to the basis columns themselves. The
  OR-joined arms are fail-closed only because ``shares_basis``,
  ``eigenpod_basis`` and ``cross_read_agreement`` are ``NOT NULL`` — a NULL basis
  would make every arm NULL, and an OR of NULLs is NULL, which passes.

Revision ID: d5b9e0c31f72
Revises: c4f8a1d92b07
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op
from utils.restaking_status import (
    CONSENSUS_LAYER_RESIDUAL_NOT_DETERMINED,
    CROSS_READ_AGREE,
    CROSS_READ_AGREEMENTS,
    EIGENPOD_BASES,
    EIGENPOD_BASIS_NO_EIGENPOD_PROVEN,
    EIGENPOD_BASIS_PROVEN_CROSS_READ,
    NODE_SET_COMPLETENESS_NOT_DETERMINED,
    NON_OBSERVING_SHARES_BASES,
    SHARES_BASES,
    SHARES_BASIS_EIGENLAYER_BEACON_SHARES,
    SHARES_BASIS_NO_EIGENPOD_PROVEN,
    SHARES_COLUMN_COMMENT,
)

revision = "d5b9e0c31f72"
# Wave-2 migration chain position 4: it follows the event-cursor coverage
# revision (a3e7c1d9b840) and precedes the role-holder plane.
down_revision = "a3e7c1d9b840"
branch_labels = None
depends_on = None


def _tuple(values: tuple[str, ...]) -> str:
    return "(" + ", ".join(f"'{value}'" for value in values) + ")"


# Per ``(chain_id, node_address)`` — the chain is part of the key because the
# same address on two chains is two different entities — the most recent
# OBSERVING row wins, under a TOTAL order so two rows at one height resolve
# deterministically.
#
# Both non-observing bases are excluded from winning: ``read_failed`` is a
# transport or decode failure, ``not_determined`` is a transport success whose
# evidence does not license a value, and letting either win would withdraw a
# proven position on the strength of a non-observation.
#
# ABSENCE FROM THIS VIEW IS not_determined, NEVER "no position". A node whose
# every row is non-observing does not appear at all.
_LATEST_VIEW = f"""
CREATE VIEW restaking_positions_latest AS
SELECT p.* FROM restaking_positions p
WHERE p.id = (
    SELECT q.id FROM restaking_positions q
    WHERE q.chain_id = p.chain_id
      AND q.node_address = p.node_address
      AND q.shares_basis IN {_tuple((SHARES_BASIS_EIGENLAYER_BEACON_SHARES, SHARES_BASIS_NO_EIGENPOD_PROVEN))}
    ORDER BY q.block_number DESC, q.id DESC
    LIMIT 1)
"""

_SHARES_ARMS = (
    "("
    f"  shares_basis = '{SHARES_BASIS_EIGENLAYER_BEACON_SHARES}'"
    "   AND eigenlayer_beacon_shares_wei IS NOT NULL"
    f"  AND eigenpod_basis = '{EIGENPOD_BASIS_PROVEN_CROSS_READ}'"
    "   AND shares_strategy IS NOT NULL"
    f"  AND (eigenlayer_beacon_shares_wei <> 0 OR cross_read_agreement = '{CROSS_READ_AGREE}')"
    ") OR ("
    f"  shares_basis = '{SHARES_BASIS_NO_EIGENPOD_PROVEN}'"
    "   AND eigenlayer_beacon_shares_wei IS NOT DISTINCT FROM 0"
    f"  AND eigenpod_basis = '{EIGENPOD_BASIS_NO_EIGENPOD_PROVEN}'"
    "   AND shares_strategy IS NULL"
    ") OR ("
    "   shares_basis IN " + _tuple(NON_OBSERVING_SHARES_BASES) + ""
    "   AND eigenlayer_beacon_shares_wei IS NULL"
    "   AND shares_strategy IS NULL"
    ")"
)


def upgrade() -> None:
    op.create_table(
        "restaking_positions",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("chain_id", sa.Integer(), nullable=False),
        sa.Column("node_address", sa.String(length=42), nullable=False),
        sa.Column("manager_contract_id", sa.Integer(), nullable=True),
        sa.Column("protocol_id", sa.Integer(), nullable=True),
        sa.Column("block_number", sa.BigInteger(), nullable=False),
        sa.Column("block_hash", sa.LargeBinary(length=32), nullable=False),
        sa.Column("eigenpod", sa.String(length=42), nullable=True),
        sa.Column("eigenpod_basis", sa.String(length=32), nullable=False),
        sa.Column(
            "eigenlayer_beacon_shares_wei",
            sa.Numeric(precision=80, scale=0),
            nullable=True,
            comment=SHARES_COLUMN_COMMENT,
        ),
        sa.Column("shares_basis", sa.String(length=40), nullable=False),
        sa.Column("shares_strategy", sa.String(length=42), nullable=True),
        sa.Column("deposit_shares_wei", sa.Numeric(precision=80, scale=0), nullable=True),
        sa.Column("cross_read_agreement", sa.String(length=30), nullable=False),
        sa.Column("active_validator_count", sa.Integer(), nullable=True),
        sa.Column("last_checkpoint_timestamp", sa.BigInteger(), nullable=True),
        sa.Column("consensus_layer_residual", sa.String(length=20), nullable=False),
        sa.Column("node_set_completeness", sa.String(length=20), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["manager_contract_id"], ["contracts.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["protocol_id"], ["protocols.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("shares_basis IN " + _tuple(SHARES_BASES), name="ck_rp_basis_domain"),
        sa.CheckConstraint("eigenpod_basis IN " + _tuple(EIGENPOD_BASES), name="ck_rp_pod_basis_domain"),
        sa.CheckConstraint("cross_read_agreement IN " + _tuple(CROSS_READ_AGREEMENTS), name="ck_rp_agreement_domain"),
        sa.CheckConstraint(_SHARES_ARMS, name="ck_rp_basis_matches_value"),
        sa.CheckConstraint(
            "eigenlayer_beacon_shares_wei IS NULL OR eigenlayer_beacon_shares_wei >= 0",
            name="ck_rp_shares_non_negative",
        ),
        sa.CheckConstraint(
            f"eigenpod_basis <> '{EIGENPOD_BASIS_NO_EIGENPOD_PROVEN}' OR eigenpod IS NULL",
            name="ck_rp_no_pod_has_no_address",
        ),
        sa.CheckConstraint(
            f"eigenpod_basis <> '{EIGENPOD_BASIS_PROVEN_CROSS_READ}' OR eigenpod IS NOT NULL",
            name="ck_rp_pod_cross_read_has_address",
        ),
        sa.CheckConstraint(
            f"eigenpod_basis = '{EIGENPOD_BASIS_PROVEN_CROSS_READ}'"
            " OR (active_validator_count IS NULL AND last_checkpoint_timestamp IS NULL)",
            name="ck_rp_pod_facts_require_pod",
        ),
        sa.CheckConstraint(
            f"consensus_layer_residual = '{CONSENSUS_LAYER_RESIDUAL_NOT_DETERMINED}'",
            name="ck_rp_cl_residual_not_determined",
        ),
        sa.CheckConstraint(
            f"node_set_completeness = '{NODE_SET_COMPLETENESS_NOT_DETERMINED}'",
            name="ck_rp_node_set_completeness",
        ),
    )
    op.create_index("ix_rp_node_block", "restaking_positions", ["chain_id", "node_address", "block_number", "id"])
    op.execute(_LATEST_VIEW)


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS restaking_positions_latest")
    op.drop_index("ix_rp_node_block", table_name="restaking_positions")
    op.drop_table("restaking_positions")
