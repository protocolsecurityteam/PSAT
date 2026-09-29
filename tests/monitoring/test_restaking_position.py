"""D1 - per-node restaking position: the record, its bases, and its backstops.

Every expected value is a read at block 25643300, reproduced independently three times;
the wire is replayed, never touched. Two shapes are pinned side by side, since pinning one
alone would ship a rule the measured corpus cannot satisfy:

* node ``0x53e1eb2f…`` - 30e18 shares, 3 active validators, pod native 0;
* node ``0x05b1e403…`` - an EigenPod, **0 shares, 0 validators**, pod holding 3.578775160 ETH
  (26 of the 26 enumerated nodes: the column sums to **0 wei** while pods hold
  **374.148164612 ETH**, ``0x7474b357…`` exactly **320 ETH**).
"""

from __future__ import annotations

import pytest
from sqlalchemy import inspect, select

from db.models import Contract, Protocol, RestakingPosition, RestakingPositionLatest
from services.clients.rpc import selector
from services.monitoring import restaking_reads
from services.monitoring.restaking_reads import (
    PINNED_FINALITY_MARGIN,
    NodeReads,
    decode_address_word,
    decode_int256_word,
    decode_strict_bool_word,
    decode_withdrawable_shares,
    decode_word,
    manager_contract_id_for,
    persist_positions,
    pinned_head,
    position_record,
    restaking_history_depth,
    withdrawable_calldata_operands,
)
from tests.conftest import requires_postgres
from utils.restaking_status import (
    CONSENSUS_LAYER_RESIDUAL_NOT_DETERMINED,
    CROSS_READ_AGREE,
    CROSS_READ_DISAGREE_WITHIN_INVARIANT,
    CROSS_READ_NOT_DETERMINED,
    EIGENPOD_BASIS_NO_EIGENPOD_PROVEN,
    EIGENPOD_BASIS_NOT_DETERMINED,
    EIGENPOD_BASIS_PROVEN_CROSS_READ,
    NODE_SET_COMPLETENESS_NOT_DETERMINED,
    SHARES_BASIS_EIGENLAYER_BEACON_SHARES,
    SHARES_BASIS_NO_EIGENPOD_PROVEN,
    SHARES_BASIS_NOT_DETERMINED,
    SHARES_BASIS_READ_FAILED,
)

BLOCK = 25643300
BLOCK_HASH = "0x" + "ab" * 32

# The witnessed strategy, written in FULL. The near-miss below answers 0 with
# success and is eyeball-identical in any elided form.
STRATEGY = "0xbeac0eeeeeeeeeeeeeeeeeeeeeeeeeeeeeebeac0"
NEAR_MISS_STRATEGY = "0xbeac0eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

NODE_WITH_SHARES = "0x53e1eb2fa5ec3c5097e67265e33ea4e53ab61b79"
POD_WITH_SHARES = "0xb274d6b6f7e02e43b9978625dcd6c84047482d56"
SHARES_WEI = 30000000000000000000

NODE_ZERO_SHARES = "0x05b1e40339823e1af30a8ed70c3fbf7f1d0ce9ae"
POD_ZERO_SHARES = "0x81b58cabe3f00cd37e074a133f87d1012341455c"

BEACON_IMPLEMENTATION = "0x556db8c611fe63e694413f718d795f976dcf5881"

# The enumerating emitter (proxy) and the row that carries the manager's NAME
# (implementation). Provenance must pin to the former.
EFNM_PROXY = "0x8b71140ad2e5d1e7018d2a7f8a288bd3cd38916f"
EFNM_IMPLEMENTATION = "0xcf5928ea7d7f164ec868ceda7a69e08a102b5e05"

ZERO_WORD = "0x" + "0" * 64


# Distinguishes "caller said nothing" from "caller passed None on purpose".
_SENTINEL = "<default>"


def _word(value: int) -> str:
    return "0x" + f"{value:064x}"


def _addr_word(address: str) -> str:
    return "0x" + address.lower().removeprefix("0x").rjust(64, "0")


def _shares_return(withdrawable: int, deposited: int) -> str:
    return "0x" + "".join(f"{v:064x}" for v in (0x40, 0x80, 1, withdrawable, 1, deposited))


def _reads(**overrides: str | None) -> NodeReads:
    base: dict[str, str | None] = {
        "get_eigen_pod": _addr_word(POD_WITH_SHARES),
        "owner_to_pod": _addr_word(POD_WITH_SHARES),
        "has_pod": _word(1),
        "pod_owner_deposit_shares": _word(SHARES_WEI),
        "withdrawable_shares": _shares_return(SHARES_WEI, SHARES_WEI),
        "active_validator_count": _word(3),
        "last_checkpoint_timestamp": _word(1774052327),
    }
    base.update(overrides)
    return NodeReads(**base)


def _calldata(node: str = NODE_WITH_SHARES, strategy: str = STRATEGY) -> str:
    """The exact bytes a ``getWithdrawableShares`` read is issued with."""
    return (
        selector("getWithdrawableShares(address,address[])")
        + node.lower().removeprefix("0x").rjust(64, "0")
        + f"{64:064x}"
        + f"{1:064x}"
        + strategy.lower().removeprefix("0x").rjust(64, "0")
    )


def _record(
    node: str = NODE_WITH_SHARES,
    strategy: str | None = STRATEGY,
    calldata: str | None = _SENTINEL,
    **overrides: str | None,
) -> dict:
    if calldata is _SENTINEL:
        calldata = _calldata(node, strategy) if strategy else None
    return position_record(
        chain_id=1,
        node_address=node,
        block_number=BLOCK,
        block_hash=BLOCK_HASH,
        strategy=strategy,
        reads=_reads(**overrides),
        withdrawable_calldata=calldata,
    )


def _skeleton(node: str) -> dict:
    """The record with every witnessed field at its not-determined state."""
    return {
        "chain_id": 1,
        "node_address": node,
        "block_number": BLOCK,
        "block_hash": BLOCK_HASH,
        "eigenpod": None,
        "eigenpod_basis": EIGENPOD_BASIS_NOT_DETERMINED,
        "eigenlayer_beacon_shares_wei": None,
        "shares_basis": SHARES_BASIS_NOT_DETERMINED,
        "shares_strategy": None,
        "deposit_shares_wei": None,
        "cross_read_agreement": CROSS_READ_NOT_DETERMINED,
        "active_validator_count": None,
        "last_checkpoint_timestamp": None,
        "consensus_layer_residual": CONSENSUS_LAYER_RESIDUAL_NOT_DETERMINED,
        "node_set_completeness": NODE_SET_COMPLETENESS_NOT_DETERMINED,
    }


class TestHappyPathBothShapes:
    def test_node_with_shares_byte_exact(self):
        assert _record() == {
            "chain_id": 1,
            "node_address": NODE_WITH_SHARES,
            "block_number": BLOCK,
            "block_hash": BLOCK_HASH,
            "eigenpod": POD_WITH_SHARES,
            "eigenpod_basis": EIGENPOD_BASIS_PROVEN_CROSS_READ,
            "eigenlayer_beacon_shares_wei": SHARES_WEI,
            "shares_basis": SHARES_BASIS_EIGENLAYER_BEACON_SHARES,
            "shares_strategy": STRATEGY,
            "deposit_shares_wei": SHARES_WEI,
            "cross_read_agreement": CROSS_READ_AGREE,
            "active_validator_count": 3,
            "last_checkpoint_timestamp": 1774052327,
            "consensus_layer_residual": "not_determined",
            "node_set_completeness": "not_determined",
        }

    def test_enumerated_node_zero_shares_with_funded_pod_byte_exact(self):
        """The 26/26 shape. A published 0 beside a pod holding 3.578775160 ETH."""
        record = position_record(
            chain_id=1,
            node_address=NODE_ZERO_SHARES,
            block_number=BLOCK,
            block_hash=BLOCK_HASH,
            strategy=STRATEGY,
            reads=NodeReads(
                get_eigen_pod=_addr_word(POD_ZERO_SHARES),
                owner_to_pod=_addr_word(POD_ZERO_SHARES),
                has_pod=_word(1),
                pod_owner_deposit_shares=_word(0),
                withdrawable_shares=_shares_return(0, 0),
                active_validator_count=_word(0),
                last_checkpoint_timestamp=_word(1784243039),
            ),
            withdrawable_calldata=_calldata(NODE_ZERO_SHARES),
        )
        assert record == {
            "chain_id": 1,
            "node_address": NODE_ZERO_SHARES,
            "block_number": BLOCK,
            "block_hash": BLOCK_HASH,
            "eigenpod": POD_ZERO_SHARES,
            "eigenpod_basis": EIGENPOD_BASIS_PROVEN_CROSS_READ,
            "eigenlayer_beacon_shares_wei": 0,
            "shares_basis": SHARES_BASIS_EIGENLAYER_BEACON_SHARES,
            "shares_strategy": STRATEGY,
            "deposit_shares_wei": 0,
            "cross_read_agreement": CROSS_READ_AGREE,
            "active_validator_count": 0,
            "last_checkpoint_timestamp": 1784243039,
            "consensus_layer_residual": "not_determined",
            "node_set_completeness": "not_determined",
        }


class TestEigenpodIdentityLegs:
    def test_all_three_zero_is_the_proven_absent_arm(self):
        record = _record(
            node=BEACON_IMPLEMENTATION,
            get_eigen_pod=ZERO_WORD,
            owner_to_pod=ZERO_WORD,
            has_pod=_word(0),
        )
        assert record["eigenpod_basis"] == EIGENPOD_BASIS_NO_EIGENPOD_PROVEN
        assert record["shares_basis"] == SHARES_BASIS_NO_EIGENPOD_PROVEN
        assert record["eigenlayer_beacon_shares_wei"] == 0
        assert record["eigenpod"] is None
        assert record["shares_strategy"] is None

    def test_codeless_node_empty_return_is_not_a_proven_zero(self):
        """The constructible attack: a codeless node answers ``getEigenPod()`` with ``"0x"`` AND
        success while EigenLayer's mappings answer zeros; a one-leg reading would mint "proven
        no eigenpod, 0 shares" for an address whose state was never read."""
        record = _record(get_eigen_pod="0x", owner_to_pod=ZERO_WORD, has_pod=_word(0))
        assert record == _skeleton(NODE_WITH_SHARES)

    @pytest.mark.parametrize(
        "leg",
        ["get_eigen_pod", "owner_to_pod", "has_pod"],
    )
    @pytest.mark.parametrize("bad", ["0x", None, "0x00", "0x" + "0" * 62])
    def test_any_short_or_failed_leg_is_not_determined(self, leg, bad):
        record = _record(**{leg: bad})
        assert record["eigenpod_basis"] == EIGENPOD_BASIS_NOT_DETERMINED
        assert record["eigenlayer_beacon_shares_wei"] is None

    def test_two_agreeing_address_legs_with_bad_has_pod_is_not_determined(self):
        """``proven_pod_cross_read`` is requirement (i); two of three is not it."""
        for has_pod in ("0x", _word(2), _word(0), None):
            record = _record(has_pod=has_pod)
            assert record["eigenpod_basis"] == EIGENPOD_BASIS_NOT_DETERMINED
            assert record["shares_basis"] == SHARES_BASIS_NOT_DETERMINED

    def test_disagreeing_address_legs_are_not_determined(self):
        record = _record(owner_to_pod=_addr_word(POD_ZERO_SHARES))
        assert record["eigenpod_basis"] == EIGENPOD_BASIS_NOT_DETERMINED

    def test_has_pod_must_be_exactly_zero_or_one(self):
        assert decode_strict_bool_word(_word(0)) is False
        assert decode_strict_bool_word(_word(1)) is True
        for bad in (_word(2), _word(1 << 255), "0x", "0x01", None):
            assert decode_strict_bool_word(bad) is None


class TestStrategyIsWitnessed:
    def test_unwitnessed_strategy_yields_not_determined(self):
        record = _record(strategy=None)
        # The pod is still proven; only the quantity is withheld.
        assert record["eigenpod_basis"] == EIGENPOD_BASIS_PROVEN_CROSS_READ
        assert record["shares_basis"] == SHARES_BASIS_NOT_DETERMINED
        assert record["eigenlayer_beacon_shares_wei"] is None
        assert record["shares_strategy"] is None


class TestFailedReadsNeverBecomeZero:
    def test_withdrawable_call_failed_is_read_failed_and_null(self):
        record = _record(withdrawable_shares=None)
        assert record["shares_basis"] == SHARES_BASIS_READ_FAILED
        assert record["eigenlayer_beacon_shares_wei"] is None
        assert record["eigenlayer_beacon_shares_wei"] != 0

    @pytest.mark.parametrize(
        "raw",
        ["0x", "0x" + "00" * 32, "0x" + "".join(f"{v:064x}" for v in (0x20, 0x80, 1, 0, 1, 0))],
    )
    def test_malformed_shares_return_is_read_failed(self, raw):
        record = _record(withdrawable_shares=raw)
        assert record["shares_basis"] == SHARES_BASIS_READ_FAILED
        assert record["eigenlayer_beacon_shares_wei"] is None

    def test_deposit_leg_failure_never_substitutes_the_withdrawable_leg(self):
        record = _record(withdrawable_shares=None, pod_owner_deposit_shares=_word(SHARES_WEI))
        assert record["eigenlayer_beacon_shares_wei"] is None

    def test_zero_with_failed_deposit_leg_cannot_publish_a_zero(self):
        """(iii) is unevaluable, so the 0 is withheld rather than published."""
        record = _record(withdrawable_shares=_shares_return(0, 0), pod_owner_deposit_shares=None)
        assert record["shares_basis"] == SHARES_BASIS_NOT_DETERMINED
        assert record["eigenlayer_beacon_shares_wei"] is None

    def test_dm_deposit_leg_below_withdrawable_is_inconsistent(self):
        """A PRESENT deposit leg below the withdrawable leg is a real conflict (unlike an ABSENT
        leg, below): a successful read disproves the accounting model behind the quantity."""
        record = _record(
            pod_owner_deposit_shares=None,
            withdrawable_shares="0x" + "".join(f"{v:064x}" for v in (0x40, 0x80, 1, SHARES_WEI, 1, 0)),
        )
        assert record["shares_basis"] == SHARES_BASIS_NOT_DETERMINED

    def test_nonzero_with_failed_epm_deposit_leg_publishes_single_source(self):
        """INTENDED. An absent deposit leg is not disagreement: suppressing would discard a
        proven read on the strength of a missing one, so the quantity publishes with a NULL
        deposit column and a not-determined cross-read."""
        record = _record(pod_owner_deposit_shares=None)
        assert record["shares_basis"] == SHARES_BASIS_EIGENLAYER_BEACON_SHARES
        assert record["eigenlayer_beacon_shares_wei"] == SHARES_WEI
        assert record["deposit_shares_wei"] is None
        assert record["cross_read_agreement"] == CROSS_READ_NOT_DETERMINED


class TestCrossReadPartition:
    def test_disagree_within_invariant_publishes_with_a_flag(self):
        record = _record(
            withdrawable_shares=_shares_return(SHARES_WEI - 1, SHARES_WEI),
            pod_owner_deposit_shares=_word(SHARES_WEI),
        )
        assert record["cross_read_agreement"] == CROSS_READ_DISAGREE_WITHIN_INVARIANT
        assert record["eigenlayer_beacon_shares_wei"] == SHARES_WEI - 1

    def test_inconsistent_withdrawable_above_deposit_suppresses(self):
        record = _record(
            withdrawable_shares=_shares_return(SHARES_WEI + 1, SHARES_WEI),
            pod_owner_deposit_shares=_word(SHARES_WEI),
        )
        assert record["shares_basis"] == SHARES_BASIS_NOT_DETERMINED
        assert record["eigenlayer_beacon_shares_wei"] is None

    def test_inconsistent_negative_deposit_with_positive_withdrawable_suppresses(self):
        record = _record(
            withdrawable_shares=_shares_return(SHARES_WEI, SHARES_WEI),
            pod_owner_deposit_shares=_word((1 << 256) - 5),
        )
        assert record["shares_basis"] == SHARES_BASIS_NOT_DETERMINED
        assert record["eigenlayer_beacon_shares_wei"] is None

    def test_fully_slashed_zero_against_positive_deposit_is_withheld(self):
        """Intended under-claim: withdrawable 0 with a positive deposit leg fails the zero-only
        equality and publishes nothing. Recorded so a later reader does not "fix" (iii)."""
        record = _record(
            withdrawable_shares=_shares_return(0, SHARES_WEI),
            pod_owner_deposit_shares=_word(SHARES_WEI),
        )
        assert record["shares_basis"] == SHARES_BASIS_NOT_DETERMINED
        assert record["eigenlayer_beacon_shares_wei"] is None


class TestDecoders:
    def test_int256_is_signed_and_unclamped(self):
        assert decode_int256_word(_word((1 << 256) - 1)) == -1
        assert decode_int256_word(_word((1 << 256) - SHARES_WEI)) == -SHARES_WEI
        assert decode_int256_word(_word(SHARES_WEI)) == SHARES_WEI
        # The failure mode this closes: unsigned decoding of -1.
        assert decode_int256_word(_word((1 << 256) - 1)) != (1 << 256) - 1

    def test_negative_deposit_beside_zero_withdrawable_is_withheld(self):
        """Decoded as -5, so ``withdrawable > deposit`` fires and the row is withheld; an
        unsigned read would give ~1.15e77 and publish happily."""
        record = _record(
            pod_owner_deposit_shares=_word((1 << 256) - 5),
            withdrawable_shares=_shares_return(0, 0),
        )
        assert record["shares_basis"] == SHARES_BASIS_NOT_DETERMINED

    def test_word_decoder_rejects_short_returns(self):
        assert decode_word("0x") is None
        assert decode_word("0x0") is None
        assert decode_word(None) is None
        assert decode_word(_word(0)) == 0

    def test_shares_decoder_asserts_the_whole_abi_shape(self):
        assert decode_withdrawable_shares(_shares_return(7, 9)) == (7, 9)
        # Wrong head offsets, wrong array lengths, wrong total length: each of
        # these would otherwise decode an offset or a length AS a quantity.
        assert decode_withdrawable_shares("0x" + "".join(f"{v:064x}" for v in (0x40, 0x80, 2, 1, 1, 1))) == (
            None,
            None,
        )
        assert decode_withdrawable_shares("0x" + "".join(f"{v:064x}" for v in (0x40, 0x80, 1, 1))) == (None, None)
        assert decode_withdrawable_shares("0x") == (None, None)


class TestDecoderStrictness:
    """A short or non-canonical word must not become a clean number. ``int(s, 16)`` accepts
    ``_`` separators and strips whitespace, so a 63-nibble return with a trailing newline would
    pass the length check and decode. Not reachable via ``multicall3_aggregate3`` today (it
    re-hexes via ``bytes.hex()``), but every decoder here is exported."""

    def test_whitespace_padded_short_word_is_not_a_zero(self):
        assert decode_word("0x" + "0" * 63 + "\n") is None

    def test_underscore_separated_word_is_rejected(self):
        assert decode_word("0x_" + "f" * 63) is None

    @pytest.mark.parametrize("body", ["0" * 63 + "\n", "_" + "f" * 63, "g" * 64, "0" * 62 + " 1"])
    def test_non_hex_bodies_reject_across_every_decoder(self, body):
        raw = "0x" + body
        assert decode_word(raw) is None
        assert decode_int256_word(raw) is None
        assert decode_address_word(raw) is None
        assert decode_strict_bool_word(raw) is None

    @pytest.mark.parametrize(
        "dirty",
        [
            pytest.param(
                _shares_return(0, 0)[: 2 + 64 * 3] + "0" * 63 + "\n" + _shares_return(0, 0)[2 + 64 * 4 :],
                id="whitespace-element-word",
            ),
            pytest.param(
                "0x" + " " + "0" * 61 + "40" + "".join(f"{v:064x}" for v in (0x80, 1, 0, 1, 0)),
                id="whitespace-padded-offset-word",
            ),
        ],
    )
    def test_whitespace_in_a_shares_word_is_rejected(self, dirty):
        assert decode_withdrawable_shares(dirty) == (None, None)

    def test_dirty_high_order_bits_are_not_truncated_into_an_address(self):
        """Wire-reachable: a non-conformant or upgraded callee returns this."""
        dirty = "0x" + "de" * 12 + POD_WITH_SHARES.removeprefix("0x")
        assert decode_address_word(dirty) is None
        assert decode_address_word("0x" + "00" * 12 + POD_WITH_SHARES.removeprefix("0x")) == POD_WITH_SHARES

    def test_dirty_address_word_denies_the_pod_cross_read(self):
        dirty = "0x" + "de" * 12 + POD_WITH_SHARES.removeprefix("0x")
        record = _record(get_eigen_pod=dirty, owner_to_pod=dirty)
        assert record["eigenpod_basis"] == EIGENPOD_BASIS_NOT_DETERMINED


class TestStrategyGateIsOnTheIssuedBytes:
    """The witnessed strategy alone is a calling convention, not a gate: the quantity is
    licensed by the answer being read AGAINST that strategy and THIS node, checked out of
    the bytes sent."""

    def test_asserted_strategy_must_match_the_calldata(self):
        record = _record(strategy=NEAR_MISS_STRATEGY, calldata=_calldata(NODE_WITH_SHARES, STRATEGY))
        assert record["shares_basis"] == SHARES_BASIS_NOT_DETERMINED
        assert record["shares_strategy"] is None

    def test_calldata_for_a_different_staker_is_rejected(self):
        record = _record(calldata=_calldata(NODE_ZERO_SHARES, STRATEGY))
        assert record["shares_basis"] == SHARES_BASIS_NOT_DETERMINED

    def test_omitted_calldata_yields_not_determined(self):
        record = _record(calldata=None)
        assert record["shares_basis"] == SHARES_BASIS_NOT_DETERMINED

    @pytest.mark.parametrize(
        "bad",
        [
            "0x",
            "0xdeadbeef",
            "0x" + "00" * 132,
            selector("getWithdrawableShares(address,address[])")
            + NODE_WITH_SHARES.removeprefix("0x").rjust(64, "0")
            + f"{32:064x}"
            + f"{1:064x}"
            + STRATEGY.removeprefix("0x").rjust(64, "0"),
        ],
    )
    def test_malformed_calldata_is_rejected(self, bad):
        assert withdrawable_calldata_operands(bad) is None
        assert _record(calldata=bad)["shares_basis"] == SHARES_BASIS_NOT_DETERMINED


class TestPodFactsRequireAProvenPod:
    def test_pod_facts_withheld_without_the_cross_read(self):
        record = _record(has_pod="0x", active_validator_count=_word(0), last_checkpoint_timestamp=_word(0))
        assert record["active_validator_count"] is None
        assert record["last_checkpoint_timestamp"] is None

    def test_never_checkpointed_zero_is_a_witness_when_the_pod_is_proven(self):
        record = _record(last_checkpoint_timestamp=_word(0))
        assert record["last_checkpoint_timestamp"] == 0

    @pytest.mark.parametrize(
        ("count", "timestamp", "expected"),
        [
            (2**31 - 1, 2**63 - 1, (2**31 - 1, 2**63 - 1)),
            (2**31, 2**63 - 1, (None, 2**63 - 1)),
            (3, 2**63, (3, None)),
            # One malformed pod must not cost every other node its observation: a 2**200 word
            # would reach the insert as a Numeric the int columns cannot hold
            # (NumericValueOutOfRange), taking the whole batch down.
            (2**200, 2**200, (None, None)),
        ],
        ids=["at-both-maxima", "count-over-int4", "timestamp-over-int8", "out-of-range-words-not-an-abort"],
    )
    def test_pod_fact_bounds_are_the_column_widths(self, count, timestamp, expected):
        record = _record(active_validator_count=_word(count), last_checkpoint_timestamp=_word(timestamp))
        assert (record["active_validator_count"], record["last_checkpoint_timestamp"]) == expected


class TestPinnedHead:
    """The stored height and hash must name the same block the reads were at."""

    def _stub(self, monkeypatch, header):
        calls = {"n": 0}

        def fake(url, method, params, **kwargs):
            if method == "eth_blockNumber":
                return hex(BLOCK + PINNED_FINALITY_MARGIN)
            calls["n"] += 1
            return header

        monkeypatch.setattr(restaking_reads, "rpc_request", fake)
        return calls

    def test_matching_header_pins(self, monkeypatch):
        self._stub(monkeypatch, {"number": hex(BLOCK), "hash": BLOCK_HASH})
        assert pinned_head(1, "http://stub") == (BLOCK, BLOCK_HASH)

    def test_header_for_a_different_height_is_refused(self, monkeypatch):
        """A racing or load-balanced upstream can answer another block; pairing that hash with
        this number would make the stored reorg witness name a block the reads never used."""
        self._stub(monkeypatch, {"number": hex(BLOCK - 3), "hash": BLOCK_HASH})
        assert pinned_head(1, "http://stub") is None

    @pytest.mark.parametrize(
        "header",
        [
            {"hash": BLOCK_HASH},
            {"number": BLOCK, "hash": BLOCK_HASH},
            {"number": hex(BLOCK), "hash": "0xabc"},
            {"number": hex(BLOCK)},
            None,
        ],
    )
    def test_unusable_header_writes_nothing(self, monkeypatch, header):
        self._stub(monkeypatch, header)
        assert pinned_head(1, "http://stub") is None


@requires_postgres
class TestConstraintsAreABackstop:
    def _row(self, session, **overrides):
        values = {
            "chain_id": 1,
            "node_address": NODE_WITH_SHARES,
            "block_number": BLOCK,
            "block_hash": b"\x01" * 32,
            "eigenpod": POD_WITH_SHARES,
            "eigenpod_basis": EIGENPOD_BASIS_PROVEN_CROSS_READ,
            "eigenlayer_beacon_shares_wei": SHARES_WEI,
            "shares_basis": SHARES_BASIS_EIGENLAYER_BEACON_SHARES,
            "shares_strategy": STRATEGY,
            "deposit_shares_wei": SHARES_WEI,
            "cross_read_agreement": CROSS_READ_AGREE,
            "active_validator_count": 3,
            "last_checkpoint_timestamp": 1774052327,
            "consensus_layer_residual": "not_determined",
            "node_set_completeness": "not_determined",
        }
        values.update(overrides)
        session.add(RestakingPosition(**values))
        session.flush()

    @pytest.mark.parametrize(
        "overrides",
        [
            pytest.param({"shares_basis": "bogus"}, id="unrecognised-basis"),
            pytest.param({"eigenpod_basis": "bogus"}, id="unrecognised-pod-basis"),
            pytest.param({"cross_read_agreement": "bogus"}, id="unrecognised-agreement"),
            pytest.param({"consensus_layer_residual": "0"}, id="residual-as-number"),
            pytest.param({"consensus_layer_residual": "66000000000000000000"}, id="residual-as-wei"),
            pytest.param({"node_set_completeness": "complete"}, id="node-set-complete"),
            pytest.param(
                {"shares_basis": SHARES_BASIS_READ_FAILED},
                id="read-failed-with-a-quantity",
            ),
            pytest.param(
                {"eigenlayer_beacon_shares_wei": 0, "cross_read_agreement": CROSS_READ_DISAGREE_WITHIN_INVARIANT},
                id="zero-without-agreement",
            ),
            pytest.param(
                {"shares_strategy": None},
                id="quantity-without-a-witnessed-strategy",
            ),
            pytest.param(
                {
                    "eigenpod_basis": EIGENPOD_BASIS_NO_EIGENPOD_PROVEN,
                    "eigenpod": None,
                    "shares_basis": SHARES_BASIS_NO_EIGENPOD_PROVEN,
                    "eigenlayer_beacon_shares_wei": 0,
                    "shares_strategy": None,
                    "deposit_shares_wei": None,
                    "active_validator_count": 0,
                },
                id="pod-facts-without-a-proven-pod",
            ),
            pytest.param(
                {"eigenpod_basis": EIGENPOD_BASIS_NO_EIGENPOD_PROVEN},
                id="absent-pod-carrying-an-address",
            ),
            pytest.param(
                {"eigenlayer_beacon_shares_wei": -1, "deposit_shares_wei": -1},
                id="negative-share-quantity",
            ),
        ],
    )
    def test_violating_shapes_are_rejected(self, db_session, overrides):
        with pytest.raises(Exception):
            self._row(db_session, **overrides)
        db_session.rollback()

    def test_basis_columns_are_not_null_in_the_reflected_schema(self, db_session):
        """The OR-joined arms are fail-closed only while these are NOT NULL: a NULL basis makes
        every arm NULL, and a CHECK evaluating to NULL PASSES in Postgres."""
        columns = {c["name"]: c for c in inspect(db_session.get_bind()).get_columns("restaking_positions")}
        for name in (
            "shares_basis",
            "eigenpod_basis",
            "cross_read_agreement",
            "consensus_layer_residual",
            "node_set_completeness",
            "block_number",
            "block_hash",
        ):
            assert columns[name]["nullable"] is False, name


@requires_postgres
class TestLatestView:
    def _insert(self, session, *, block, basis, shares, node=NODE_WITH_SHARES):
        session.add(
            RestakingPosition(
                chain_id=1,
                node_address=node,
                block_number=block,
                block_hash=bytes([block % 251]) * 32,
                eigenpod=POD_WITH_SHARES if basis != SHARES_BASIS_NO_EIGENPOD_PROVEN else None,
                eigenpod_basis=(
                    EIGENPOD_BASIS_PROVEN_CROSS_READ
                    if basis == SHARES_BASIS_EIGENLAYER_BEACON_SHARES
                    else EIGENPOD_BASIS_NOT_DETERMINED
                ),
                eigenlayer_beacon_shares_wei=shares,
                shares_basis=basis,
                shares_strategy=STRATEGY if basis == SHARES_BASIS_EIGENLAYER_BEACON_SHARES else None,
                deposit_shares_wei=shares,
                cross_read_agreement=CROSS_READ_AGREE,
                active_validator_count=None,
                last_checkpoint_timestamp=None,
                consensus_layer_residual="not_determined",
                node_set_completeness="not_determined",
            )
        )
        session.flush()

    def _latest(self, session, node=NODE_WITH_SHARES):
        return (
            session.query(RestakingPositionLatest)
            .filter(RestakingPositionLatest.node_address == node, RestakingPositionLatest.chain_id == 1)
            .all()
        )

    def test_later_read_failed_row_does_not_withdraw_a_proven_position(self, db_session):
        self._insert(db_session, block=BLOCK, basis=SHARES_BASIS_EIGENLAYER_BEACON_SHARES, shares=SHARES_WEI)
        self._insert(db_session, block=BLOCK + 100, basis=SHARES_BASIS_READ_FAILED, shares=None)
        rows = self._latest(db_session)
        assert [r.block_number for r in rows] == [BLOCK]
        assert rows[0].eigenlayer_beacon_shares_wei == SHARES_WEI
        db_session.rollback()

    def test_later_not_determined_row_does_not_withdraw_a_proven_position(self, db_session):
        self._insert(db_session, block=BLOCK, basis=SHARES_BASIS_EIGENLAYER_BEACON_SHARES, shares=SHARES_WEI)
        self._insert(db_session, block=BLOCK + 100, basis=SHARES_BASIS_NOT_DETERMINED, shares=None)
        rows = self._latest(db_session)
        assert [r.block_number for r in rows] == [BLOCK]
        db_session.rollback()

    def test_later_observing_row_wins(self, db_session):
        self._insert(db_session, block=BLOCK, basis=SHARES_BASIS_EIGENLAYER_BEACON_SHARES, shares=SHARES_WEI)
        self._insert(db_session, block=BLOCK + 100, basis=SHARES_BASIS_EIGENLAYER_BEACON_SHARES, shares=1)
        rows = self._latest(db_session)
        assert [(r.block_number, int(r.eigenlayer_beacon_shares_wei)) for r in rows] == [(BLOCK + 100, 1)]
        db_session.rollback()

    def test_same_height_resolves_deterministically_by_id(self, db_session):
        self._insert(db_session, block=BLOCK, basis=SHARES_BASIS_EIGENLAYER_BEACON_SHARES, shares=SHARES_WEI)
        self._insert(db_session, block=BLOCK, basis=SHARES_BASIS_EIGENLAYER_BEACON_SHARES, shares=7)
        rows = self._latest(db_session)
        assert len(rows) == 1
        assert int(rows[0].eigenlayer_beacon_shares_wei) == 7
        db_session.rollback()

    def test_node_with_only_non_observing_rows_is_absent_not_zero(self, db_session):
        """Absence from the view is not_determined, never "no position": a consumer reading a
        missing row as 0 would reintroduce absent-row-as-$0 at the projection layer."""
        self._insert(db_session, block=BLOCK, basis=SHARES_BASIS_READ_FAILED, shares=None)
        self._insert(db_session, block=BLOCK + 1, basis=SHARES_BASIS_NOT_DETERMINED, shares=None)
        assert self._latest(db_session) == []
        db_session.rollback()

    def test_view_partition_includes_chain_id(self, db_session):
        """The same address on two chains is two entities (cross-chain aliasing)."""
        self._insert(db_session, block=BLOCK, basis=SHARES_BASIS_EIGENLAYER_BEACON_SHARES, shares=SHARES_WEI)
        db_session.add(
            RestakingPosition(
                chain_id=8453,
                node_address=NODE_WITH_SHARES,
                block_number=BLOCK - 1000,
                block_hash=b"\x02" * 32,
                eigenpod=POD_WITH_SHARES,
                eigenpod_basis=EIGENPOD_BASIS_PROVEN_CROSS_READ,
                eigenlayer_beacon_shares_wei=5,
                shares_basis=SHARES_BASIS_EIGENLAYER_BEACON_SHARES,
                shares_strategy=STRATEGY,
                deposit_shares_wei=5,
                cross_read_agreement=CROSS_READ_AGREE,
                consensus_layer_residual="not_determined",
                node_set_completeness="not_determined",
            )
        )
        db_session.flush()
        rows = (
            db_session.query(RestakingPositionLatest)
            .filter(RestakingPositionLatest.node_address == NODE_WITH_SHARES)
            .all()
        )
        assert sorted((r.chain_id, int(r.eigenlayer_beacon_shares_wei)) for r in rows) == [
            (1, SHARES_WEI),
            (8453, 5),
        ]
        db_session.rollback()


@requires_postgres
class TestPersistence:
    def test_producer_never_attempts_a_violating_insert(self, db_session):
        """Constraints are a backstop; the producer is the control flow. Every leg outcome here
        persists without an IntegrityError, so the CHECKs never become a guard the writer leans on."""
        legs = [
            {},
            {"get_eigen_pod": "0x"},
            {"get_eigen_pod": ZERO_WORD, "owner_to_pod": ZERO_WORD, "has_pod": _word(0)},
            {"has_pod": _word(2)},
            {"owner_to_pod": None},
            {"withdrawable_shares": None},
            {"withdrawable_shares": "0x"},
            {"withdrawable_shares": _shares_return(0, 0), "pod_owner_deposit_shares": _word(0)},
            {"withdrawable_shares": _shares_return(0, 0), "pod_owner_deposit_shares": None},
            {"withdrawable_shares": _shares_return(0, SHARES_WEI)},
            {"withdrawable_shares": _shares_return(SHARES_WEI + 1, SHARES_WEI)},
            {"pod_owner_deposit_shares": _word((1 << 256) - 5)},
            {"pod_owner_deposit_shares": None},
            {"active_validator_count": None, "last_checkpoint_timestamp": None},
        ]
        records = [_record(**overrides) for overrides in legs]
        for index, record in enumerate(records):
            record["node_address"] = f"0x{index:040x}"
        assert persist_positions(db_session, records, manager_contract_id=None, protocol_id=None) == len(records)
        stored = db_session.execute(select(RestakingPosition)).scalars().all()
        assert len(stored) == len(records)
        db_session.rollback()

    def test_strategy_none_path_persists(self, db_session):
        record = _record(strategy=None)
        assert persist_positions(db_session, [record], manager_contract_id=None, protocol_id=None) == 1
        db_session.rollback()

    def test_retention_keeps_the_latest_observing_read(self, db_session, monkeypatch):
        monkeypatch.setenv("PSAT_RESTAKING_HISTORY_DEPTH", "2")
        observing = _record()
        observing["block_number"] = BLOCK
        persist_positions(db_session, [observing], manager_contract_id=None, protocol_id=None)
        for offset in range(1, 5):
            failed = _record(withdrawable_shares=None)
            failed["block_number"] = BLOCK + offset
            persist_positions(db_session, [failed], manager_contract_id=None, protocol_id=None)
        rows = (
            db_session.execute(select(RestakingPosition).where(RestakingPosition.node_address == NODE_WITH_SHARES))
            .scalars()
            .all()
        )
        assert any(r.shares_basis == SHARES_BASIS_EIGENLAYER_BEACON_SHARES for r in rows)
        latest = (
            db_session.query(RestakingPositionLatest)
            .filter(RestakingPositionLatest.node_address == NODE_WITH_SHARES)
            .all()
        )
        assert [int(r.eigenlayer_beacon_shares_wei) for r in latest] == [SHARES_WEI]
        db_session.rollback()

    def test_retention_depth_below_one_is_rejected(self, monkeypatch):
        monkeypatch.setenv("PSAT_RESTAKING_HISTORY_DEPTH", "0")
        with pytest.raises(ValueError):
            restaking_history_depth()

    def test_manager_provenance_is_the_emitting_address_row(self, db_session):
        protocol = Protocol(name="restaking-provenance")
        db_session.add(protocol)
        db_session.flush()
        proxy = Contract(protocol_id=protocol.id, address=EFNM_PROXY, implementation=EFNM_IMPLEMENTATION)
        implementation = Contract(protocol_id=protocol.id, address=EFNM_IMPLEMENTATION)
        db_session.add_all([proxy, implementation])
        db_session.flush()
        assert manager_contract_id_for(db_session, emitter=EFNM_PROXY, protocol_id=protocol.id) == proxy.id
        assert manager_contract_id_for(db_session, emitter=EFNM_PROXY, protocol_id=protocol.id) != implementation.id
        db_session.rollback()


@requires_postgres
def test_the_value_plane_publishes_what_it_read_and_what_it_dropped(db_session):
    """Every admission rule states where it fired: a position dropped uncounted reads as a
    node that holds nothing rather than one this plane refused. Lives here because this file
    is in the plane's licensed import surface for ``RestakingPosition`` (see
    ``test_restaking_node_fold``'s import-surface guard)."""
    import uuid

    from services.scoring.planes import load_value_plane

    protocol = Protocol(name=f"restaking-fold-census-{uuid.uuid4().hex[:8]}")
    db_session.add(protocol)
    db_session.flush()
    for node, agreement, block in (
        ("0x" + "e1" * 20, "agree", 100),
        ("0x" + "e2" * 20, "inconsistent", 101),
    ):
        db_session.add(
            RestakingPosition(
                chain_id=1,
                node_address=node,
                protocol_id=protocol.id,
                block_number=block,
                block_hash=bytes([block % 251]) * 32,
                eigenpod="0x" + "ed" * 20,
                eigenpod_basis="proven_pod_cross_read",
                eigenlayer_beacon_shares_wei=32 * 10**18,
                shares_basis="eigenlayer_beacon_shares",
                shares_strategy="0x" + "cd" * 20,
                deposit_shares_wei=32 * 10**18,
                cross_read_agreement=agreement,
                consensus_layer_residual="not_determined",
                node_set_completeness="not_determined",
            )
        )
    db_session.commit()
    try:
        plane = load_value_plane(db_session, protocol.id)
        annotation = next(a for a in plane.annotations if a["fact"].startswith("restaking positions folded"))
        assert annotation["positions_read"] == 2
        assert annotation["positions_dropped"] == {
            "cross_read_inconsistent": 1,
            "shares_basis_not_admissible": 0,
            "shares_unreadable": 0,
            "unknown_chain_id": 0,
        }
        assert annotation["entities"] == 1
    finally:
        db_session.rollback()
        db_session.query(RestakingPosition).filter_by(protocol_id=protocol.id).delete()
        db_session.delete(protocol)
        db_session.commit()
