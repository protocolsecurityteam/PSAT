"""D1 — per-node restaking position: the record, its bases, and its backstops.

Every expected value below is a read taken at block 25643300 and reproduced
independently three times (implementer, gate, implementer again). The wire is
replayed, never touched.

The two shapes that must both hold are pinned side by side, because pinning only
one of them is how this unit would have shipped a rule that the measured corpus
cannot satisfy:

* node ``0x53e1eb2f…`` — 30e18 shares, 3 active validators, pod native 0;
* node ``0x05b1e403…`` — an EigenPod present, **0 shares, 0 validators**, and a
  pod holding 3.578775160 ETH at the same block.

The second is 26 of the 26 enumerated nodes. Over that whole set this column
sums to **0 wei** while the pods hold **374.148164612 ETH**, one of them
(``0x7474b357…``) exactly **320 ETH** — which is what the column's published
meaning has to survive.
"""

from __future__ import annotations

import pytest
from sqlalchemy import inspect, select, text

from db.models import Contract, Protocol, RestakingPosition, RestakingPositionLatest
from services.monitoring.restaking_reads import (
    NodeReads,
    decode_int256_word,
    decode_strict_bool_word,
    decode_withdrawable_shares,
    decode_word,
    manager_contract_id_for,
    persist_positions,
    position_record,
    restaking_history_depth,
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
NEAR_MISS_STRATEGY = "0xbeac0eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

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
    return NodeReads(**base)  # type: ignore[arg-type]


def _record(node: str = NODE_WITH_SHARES, strategy: str | None = STRATEGY, **overrides: str | None) -> dict:
    return position_record(
        chain_id=1,
        node_address=node,
        block_number=BLOCK,
        block_hash=BLOCK_HASH,
        strategy=strategy,
        reads=_reads(**overrides),
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

    def test_residual_key_is_present_and_is_the_string(self):
        for record in (_record(), _record(get_eigen_pod="0x")):
            assert "consensus_layer_residual" in record
            assert record["consensus_layer_residual"] == "not_determined"
            assert record["consensus_layer_residual"] != 0

    def test_published_zero_states_its_scope_and_omits_native_balances(self):
        """What a 0 means, and what it must not be read as.

        Summing this column over the 26 enumerated nodes yields 0 wei while those
        pods hold 374.148164612 ETH at the same block, one of them exactly 320
        ETH. The record therefore carries no node or pod native balance at all —
        those are not_determined on this plane, not zero.
        """
        record = position_record(
            chain_id=1,
            node_address="0xf538ac27909beed9652b8f008f2246851fded09b",
            block_number=BLOCK,
            block_hash=BLOCK_HASH,
            strategy=STRATEGY,
            reads=NodeReads(
                get_eigen_pod=_addr_word("0x7474b357106e509918cd1db47c40a7d0d775d4c7"),
                owner_to_pod=_addr_word("0x7474b357106e509918cd1db47c40a7d0d775d4c7"),
                has_pod=_word(1),
                pod_owner_deposit_shares=_word(0),
                withdrawable_shares=_shares_return(0, 0),
                active_validator_count=_word(0),
                last_checkpoint_timestamp=_word(1784221571),
            ),
        )
        # The pod backing this very row holds exactly 320 ETH at this block.
        assert record["eigenlayer_beacon_shares_wei"] == 0
        assert not [key for key in record if "native" in key or "balance" in key]
        assert record["consensus_layer_residual"] == "not_determined"


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
        """The constructible attack: before deployment the node is codeless.

        ``getEigenPod()`` answers ``"0x"`` WITH success while EigenLayer's
        mappings answer clean zeros. A one-leg reading would mint "proven no
        eigenpod, 0 shares" for an address whose own state was never read.
        """
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

    def test_published_strategy_is_the_witnessed_one(self):
        assert _record()["shares_strategy"] == STRATEGY
        assert _record()["shares_strategy"] != NEAR_MISS_STRATEGY

    def test_near_miss_strategy_answer_is_not_a_proven_zero(self):
        """A wrong strategy returns [0]/[0] with success, as does a non-staker.

        The producer only ever queries the witnessed strategy, so this pins the
        downstream consequence: that answer shape, arriving with a deposit leg
        that also reads 0, is admitted ONLY under three-way agreement — and the
        thing that actually rejects a non-staker is the identity cross-read,
        which a non-staker fails because it is codeless.
        """
        record = position_record(
            chain_id=1,
            node_address="0x00000000000000000000000000000000deadbeef",
            block_number=BLOCK,
            block_hash=BLOCK_HASH,
            strategy=STRATEGY,
            reads=NodeReads(
                get_eigen_pod="0x",
                owner_to_pod=ZERO_WORD,
                has_pod=_word(0),
                pod_owner_deposit_shares=_word(0),
                withdrawable_shares=_shares_return(0, 0),
                active_validator_count=None,
                last_checkpoint_timestamp=None,
            ),
        )
        assert record == _skeleton("0x00000000000000000000000000000000deadbeef")


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
        """A PRESENT deposit leg below the withdrawable leg is a real conflict.

        Distinct from an ABSENT leg (below): here the accounting model that
        licenses the quantity is disproved by a read that succeeded.
        """
        record = _record(
            pod_owner_deposit_shares=None,
            withdrawable_shares="0x" + "".join(f"{v:064x}" for v in (0x40, 0x80, 1, SHARES_WEI, 1, 0)),
        )
        assert record["shares_basis"] == SHARES_BASIS_NOT_DETERMINED

    def test_nonzero_with_failed_epm_deposit_leg_publishes_single_source(self):
        """INTENDED. Absence of the deposit leg is not disagreement.

        Suppressing here would discard a proven read on the strength of a
        missing one, so the quantity publishes with a NULL deposit column and an
        explicitly not-determined cross-read.
        """
        record = _record(pod_owner_deposit_shares=None)
        assert record["shares_basis"] == SHARES_BASIS_EIGENLAYER_BEACON_SHARES
        assert record["eigenlayer_beacon_shares_wei"] == SHARES_WEI
        assert record["deposit_shares_wei"] is None
        assert record["cross_read_agreement"] == CROSS_READ_NOT_DETERMINED


class TestCrossReadPartition:
    def test_agree(self):
        assert _record()["cross_read_agreement"] == CROSS_READ_AGREE

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
        """Intended under-claim: withdrawable 0 with a positive deposit leg.

        It fails the zero-only equality requirement, so it publishes nothing
        rather than a 0 that the deposit leg contradicts. Recorded here so a
        later reader does not "fix" requirement (iii).
        """
        record = _record(
            withdrawable_shares=_shares_return(0, SHARES_WEI),
            pod_owner_deposit_shares=_word(SHARES_WEI),
        )
        assert record["shares_basis"] == SHARES_BASIS_NOT_DETERMINED
        assert record["eigenlayer_beacon_shares_wei"] is None

    def test_disagree_within_invariant_with_zero_is_unreachable_by_construction(self):
        """A zero requires ``agree``, so the pairing cannot be produced."""
        for withdrawable, deposit in ((0, 1), (0, SHARES_WEI)):
            record = _record(
                withdrawable_shares=_shares_return(withdrawable, deposit),
                pod_owner_deposit_shares=_word(deposit),
            )
            assert not (
                record["eigenlayer_beacon_shares_wei"] == 0
                and record["cross_read_agreement"] == CROSS_READ_DISAGREE_WITHIN_INVARIANT
            )


class TestDecoders:
    def test_int256_is_signed_and_unclamped(self):
        assert decode_int256_word(_word((1 << 256) - 1)) == -1
        assert decode_int256_word(_word((1 << 256) - SHARES_WEI)) == -SHARES_WEI
        assert decode_int256_word(_word(SHARES_WEI)) == SHARES_WEI
        # The failure mode this closes: unsigned decoding of -1.
        assert decode_int256_word(_word((1 << 256) - 1)) != (1 << 256) - 1

    def test_negative_deposit_beside_zero_withdrawable_is_withheld(self):
        """Decoded as -5, so ``withdrawable > deposit`` fires and the row is withheld.

        The point is that the sign survives the decode: an unsigned read would
        make the same word ~1.15e77, which is above the withdrawable leg and
        would have published happily.
        """
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


class TestPodFactsRequireAProvenPod:
    def test_pod_facts_withheld_without_the_cross_read(self):
        record = _record(has_pod="0x", active_validator_count=_word(0), last_checkpoint_timestamp=_word(0))
        assert record["active_validator_count"] is None
        assert record["last_checkpoint_timestamp"] is None

    def test_never_checkpointed_zero_is_a_witness_when_the_pod_is_proven(self):
        record = _record(last_checkpoint_timestamp=_word(0))
        assert record["last_checkpoint_timestamp"] == 0


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

    def test_the_measured_shapes_insert(self, db_session):
        self._row(db_session)
        self._row(
            db_session,
            node_address=NODE_ZERO_SHARES,
            eigenpod=POD_ZERO_SHARES,
            eigenlayer_beacon_shares_wei=0,
            deposit_shares_wei=0,
            active_validator_count=0,
            last_checkpoint_timestamp=1784243039,
        )
        db_session.rollback()

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
        ],
    )
    def test_violating_shapes_are_rejected(self, db_session, overrides):
        with pytest.raises(Exception):
            self._row(db_session, **overrides)
        db_session.rollback()

    def test_basis_columns_are_not_null_in_the_reflected_schema(self, db_session):
        """The OR-joined arms are fail-closed only while these are NOT NULL.

        A NULL basis makes every arm NULL; an OR of NULLs is NULL; and a CHECK
        that evaluates to NULL PASSES in Postgres. Nullability here is therefore
        part of the constraint, not a style choice.
        """
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

    def test_no_usd_column_exists_on_this_plane(self, db_session):
        columns = {c["name"] for c in inspect(db_session.get_bind()).get_columns("restaking_positions")}
        assert not [c for c in columns if "usd" in c or "price" in c]


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
        """Absence from the view is not_determined, never "no position".

        With both failure classes excluded, such a node vanishes entirely — so a
        consumer that read a missing row as 0 would reintroduce the
        absent-row-as-$0 shape at the projection layer.
        """
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
        """Constraints are a backstop; the producer is the control flow.

        Every leg outcome in this matrix is persisted without a single
        IntegrityError, which is the property that keeps the CHECKs from
        becoming a guard the writer leans on.
        """
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
def test_column_comment_states_what_a_zero_does_not_mean(db_session):
    comment = db_session.execute(
        text(
            "SELECT col_description('restaking_positions'::regclass, "
            "(SELECT attnum FROM pg_attribute WHERE attrelid='restaking_positions'::regclass "
            "AND attname='eigenlayer_beacon_shares_wei'))"
        )
    ).scalar_one()
    assert "374.148164612 ETH" in comment
    assert "not_determined" in comment
