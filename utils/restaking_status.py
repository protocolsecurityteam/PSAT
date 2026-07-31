"""Restaking-position status vocabularies.

A leaf module on purpose, for the reason ``utils.balance_status`` states: the
reader, the schema, the migration's CHECK constraints and the register must
agree on the exact strings, and a second copy of any of them is a divergence
vector. Nothing here imports anything.

The governing rule is the same one: a value is published as a positive fact only
when the evidence proves it. Every revert, every empty return, every short word
and every unevaluable cross-read lands on ``read_failed`` or ``not_determined``
— never on a quantity, in either direction.

The two constants at the bottom are single-valued by design. They are stored
columns rather than comments so the DB can refuse any other value.
"""

from __future__ import annotations

# --- eigenpod identity -----------------------------------------------------
# Three legs decide this, never two. ``proven_pod_cross_read`` is requirement
# (i) of the shares arm, so a basis mintable from a subset of the legs would
# undo the strictness of the all-zero arm from the other side.
EIGENPOD_BASIS_PROVEN_CROSS_READ = "proven_pod_cross_read"
EIGENPOD_BASIS_NO_EIGENPOD_PROVEN = "no_eigenpod_proven"
EIGENPOD_BASIS_NOT_DETERMINED = "not_determined"
EIGENPOD_BASES = (
    EIGENPOD_BASIS_PROVEN_CROSS_READ,
    EIGENPOD_BASIS_NO_EIGENPOD_PROVEN,
    EIGENPOD_BASIS_NOT_DETERMINED,
)

# --- the shares quantity ---------------------------------------------------
# ``eigenlayer_beacon_shares`` and ``no_eigenpod_proven`` are the two OBSERVING
# bases: a row carrying either witnessed the quantity (possibly as a zero).
# ``read_failed`` and ``not_determined`` are NON-OBSERVING and carry a NULL
# quantity; the ``latest`` view excludes both from winning, because a
# non-observation must never withdraw a proven position.
SHARES_BASIS_EIGENLAYER_BEACON_SHARES = "eigenlayer_beacon_shares"
SHARES_BASIS_NO_EIGENPOD_PROVEN = "no_eigenpod_proven"
SHARES_BASIS_READ_FAILED = "read_failed"
SHARES_BASIS_NOT_DETERMINED = "not_determined"
SHARES_BASES = (
    SHARES_BASIS_EIGENLAYER_BEACON_SHARES,
    SHARES_BASIS_NO_EIGENPOD_PROVEN,
    SHARES_BASIS_READ_FAILED,
    SHARES_BASIS_NOT_DETERMINED,
)
# The partition the view keys on. ``read_failed`` is a transport/decode failure;
# ``not_determined`` is a transport success whose evidence does not license a
# value. Both are non-observations of the quantity and neither may win.
OBSERVING_SHARES_BASES = (
    SHARES_BASIS_EIGENLAYER_BEACON_SHARES,
    SHARES_BASIS_NO_EIGENPOD_PROVEN,
)
NON_OBSERVING_SHARES_BASES = (
    SHARES_BASIS_READ_FAILED,
    SHARES_BASIS_NOT_DETERMINED,
)

# --- cross-read consistency ------------------------------------------------
# ``disagree_within_invariant`` publishes the quantity WITH a flag: withdrawable
# below deposited is what slashing and queued withdrawals legitimately produce.
# ``inconsistent`` suppresses it: past the protocol invariant, the consistency
# model that licensed the number is disproved, so the number goes.
CROSS_READ_AGREE = "agree"
CROSS_READ_DISAGREE_WITHIN_INVARIANT = "disagree_within_invariant"
CROSS_READ_INCONSISTENT = "inconsistent"
CROSS_READ_NOT_DETERMINED = "not_determined"
CROSS_READ_AGREEMENTS = (
    CROSS_READ_AGREE,
    CROSS_READ_DISAGREE_WITHIN_INVARIANT,
    CROSS_READ_INCONSISTENT,
    CROSS_READ_NOT_DETERMINED,
)

# --- single-valued columns -------------------------------------------------
# The consensus-layer residual lives on the beacon chain and no ``eth_call``
# reads it. It is a KEY that is always present with this value, never a number:
# post-Pectra a single validator may hold up to 2048 ETH, so the quantity is
# unbounded above and defaulting it to 0 would be the largest single over-claim
# available in this unit.
CONSENSUS_LAYER_RESIDUAL_NOT_DETERMINED = "not_determined"

# The published meaning of the quantity column, stored in the database itself
# rather than only in a register file — a scorer author reading the schema must
# meet the scope statement without knowing this document exists. Shared by the
# model and the migration so the stored comment and the mapping cannot drift.
SHARES_COLUMN_COMMENT = (
    "EigenLayer beaconChainETH WITHDRAWABLE SHARES for this node at block_number, "
    "read from DelegationManager.getWithdrawableShares against the strategy witnessed "
    "at the same block. A 0 here means zero EigenLayer beaconChainETH withdrawable "
    "shares. It does NOT mean the node holds nothing: node and EigenPod "
    "execution-layer native balances are not_determined on this plane, and the "
    "consensus-layer residual is not_determined and unbounded above. Measured at "
    "block 25643300: summing this column over the 26 enumerated nodes yields 0 wei "
    "while those pods hold 374.148164612 ETH, one of them exactly 320 ETH. Never sum "
    "this column with a spot balance and never convert it to USD on this plane."
)

# The node fold proves a node EXISTS; it can never prove one does not. Its
# cursor is code-asserted rather than descriptor-derived, so it carries the
# incomplete-coverage ceiling and licenses no earned negative. One reachable
# value, DB-enforced.
NODE_SET_COMPLETENESS_NOT_DETERMINED = "not_determined"

__all__ = [
    "CONSENSUS_LAYER_RESIDUAL_NOT_DETERMINED",
    "CROSS_READ_AGREE",
    "CROSS_READ_AGREEMENTS",
    "CROSS_READ_DISAGREE_WITHIN_INVARIANT",
    "CROSS_READ_INCONSISTENT",
    "CROSS_READ_NOT_DETERMINED",
    "EIGENPOD_BASES",
    "EIGENPOD_BASIS_NOT_DETERMINED",
    "EIGENPOD_BASIS_NO_EIGENPOD_PROVEN",
    "EIGENPOD_BASIS_PROVEN_CROSS_READ",
    "NODE_SET_COMPLETENESS_NOT_DETERMINED",
    "NON_OBSERVING_SHARES_BASES",
    "OBSERVING_SHARES_BASES",
    "SHARES_BASES",
    "SHARES_BASIS_EIGENLAYER_BEACON_SHARES",
    "SHARES_BASIS_NOT_DETERMINED",
    "SHARES_BASIS_NO_EIGENPOD_PROVEN",
    "SHARES_BASIS_READ_FAILED",
    "SHARES_COLUMN_COMMENT",
]
