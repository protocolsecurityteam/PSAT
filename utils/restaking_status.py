"""Restaking-position status vocabularies; a leaf module for the same reason as ``utils.balance_status``.

Reverts, empty returns and unevaluable cross-reads land on ``read_failed`` / ``not_determined``, never a quantity. The
single-valued constants are stored columns so the DB can refuse other values.
"""

from __future__ import annotations

# All three legs are required; a basis mintable from a subset would undo the all-zero arm's strictness.
EIGENPOD_BASIS_PROVEN_CROSS_READ = "proven_pod_cross_read"
EIGENPOD_BASIS_NO_EIGENPOD_PROVEN = "no_eigenpod_proven"
EIGENPOD_BASIS_NOT_DETERMINED = "not_determined"
EIGENPOD_BASES = (
    EIGENPOD_BASIS_PROVEN_CROSS_READ,
    EIGENPOD_BASIS_NO_EIGENPOD_PROVEN,
    EIGENPOD_BASIS_NOT_DETERMINED,
)

# Observing bases witnessed the quantity (possibly zero). ``read_failed`` / ``not_determined`` carry NULL and can never
# win in the ``latest`` view: a non-observation must not withdraw a proven position.
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
OBSERVING_SHARES_BASES = (
    SHARES_BASIS_EIGENLAYER_BEACON_SHARES,
    SHARES_BASIS_NO_EIGENPOD_PROVEN,
)
NON_OBSERVING_SHARES_BASES = (
    SHARES_BASIS_READ_FAILED,
    SHARES_BASIS_NOT_DETERMINED,
)

# ``disagree_within_invariant`` publishes with a flag (slashing and queued withdrawals cause it). ``inconsistent``
# suppresses: past the invariant the model is disproved.
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

# No ``eth_call`` reads the beacon-chain residual. Post-Pectra a validator can hold 2048 ETH, so defaulting to 0 would
# be a huge over-claim.
CONSENSUS_LAYER_RESIDUAL_NOT_DETERMINED = "not_determined"

# Stored in the DB so schema readers meet the scope statement; shared by model and migration so they can't drift.
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

# The node fold can prove a node exists, never that one doesn't; its cursor is code-asserted, so no earned negative.
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
