"""D1 per-node restaking positions, from reads at block 25643300 replayed off the wire.

Two shapes are pinned side by side: node ``0x53e1eb2f…`` (30e18 shares, 3 validators) and ``0x05b1e403…``
(0 shares, 0 validators, pod holding 3.578775160 ETH). All 26 enumerated nodes sum to 0 wei of shares while
pods hold 374 ETH.
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
    decode_strict_bool_word,
    decode_withdrawable_shares,
    manager_contract_id_for,
    persist_positions,
    pinned_head,
    position_record,
    withdrawable_calldata_operands,
)
from tests.conftest import requires_postgres
from utils.restaking_status import (
    CROSS_READ_AGREE,
    CROSS_READ_DISAGREE_WITHIN_INVARIANT,
    EIGENPOD_BASIS_NO_EIGENPOD_PROVEN,
    EIGENPOD_BASIS_NOT_DETERMINED,
    EIGENPOD_BASIS_PROVEN_CROSS_READ,
    SHARES_BASIS_EIGENLAYER_BEACON_SHARES,
    SHARES_BASIS_NO_EIGENPOD_PROVEN,
    SHARES_BASIS_NOT_DETERMINED,
)

BLOCK = 25643300
BLOCK_HASH = "0x" + "ab" * 32

# The near-miss below answers 0 with success and looks identical when elided.
STRATEGY = "0xbeac0eeeeeeeeeeeeeeeeeeeeeeeeeeeeeebeac0"

NODE_WITH_SHARES = "0x53e1eb2fa5ec3c5097e67265e33ea4e53ab61b79"
POD_WITH_SHARES = "0xb274d6b6f7e02e43b9978625dcd6c84047482d56"
SHARES_WEI = 30000000000000000000

NODE_ZERO_SHARES = "0x05b1e40339823e1af30a8ed70c3fbf7f1d0ce9ae"

BEACON_IMPLEMENTATION = "0x556db8c611fe63e694413f718d795f976dcf5881"

# Provenance pins to the proxy, not the named implementation row.
EFNM_PROXY = "0x8b71140ad2e5d1e7018d2a7f8a288bd3cd38916f"
EFNM_IMPLEMENTATION = "0xcf5928ea7d7f164ec868ceda7a69e08a102b5e05"

ZERO_WORD = "0x" + "0" * 64


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

    def test_two_agreeing_address_legs_with_bad_has_pod_is_not_determined(self):
        for has_pod in ("0x", _word(2), _word(0), None):
            record = _record(has_pod=has_pod)
            assert record["eigenpod_basis"] == EIGENPOD_BASIS_NOT_DETERMINED
            assert record["shares_basis"] == SHARES_BASIS_NOT_DETERMINED

    def test_has_pod_must_be_exactly_zero_or_one(self):
        assert decode_strict_bool_word(_word(0)) is False
        assert decode_strict_bool_word(_word(1)) is True
        for bad in (_word(2), _word(1 << 255), "0x", "0x01", None):
            assert decode_strict_bool_word(bad) is None


class TestStrategyIsWitnessed:
    def test_unwitnessed_strategy_yields_not_determined(self):
        record = _record(strategy=None)
        assert record["eigenpod_basis"] == EIGENPOD_BASIS_PROVEN_CROSS_READ
        assert record["shares_basis"] == SHARES_BASIS_NOT_DETERMINED
        assert record["eigenlayer_beacon_shares_wei"] is None
        assert record["shares_strategy"] is None


class TestCrossReadPartition:
    def test_disagree_within_invariant_publishes_with_a_flag(self):
        record = _record(
            withdrawable_shares=_shares_return(SHARES_WEI - 1, SHARES_WEI),
            pod_owner_deposit_shares=_word(SHARES_WEI),
        )
        assert record["cross_read_agreement"] == CROSS_READ_DISAGREE_WITHIN_INVARIANT
        assert record["eigenlayer_beacon_shares_wei"] == SHARES_WEI - 1


class TestDecoders:
    def test_shares_decoder_asserts_the_whole_abi_shape(self):
        assert decode_withdrawable_shares(_shares_return(7, 9)) == (7, 9)
        # Each would otherwise decode an offset or length as a quantity.
        assert decode_withdrawable_shares("0x" + "".join(f"{v:064x}" for v in (0x40, 0x80, 2, 1, 1, 1))) == (
            None,
            None,
        )
        assert decode_withdrawable_shares("0x" + "".join(f"{v:064x}" for v in (0x40, 0x80, 1, 1))) == (None, None)
        assert decode_withdrawable_shares("0x") == (None, None)


class TestDecoderStrictness:
    """``int(s, 16)`` accepts ``_`` and strips whitespace, so a malformed word could decode; unreachable via
    ``multicall3_aggregate3`` today, but the decoders are exported.
    """

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

    def test_dirty_address_word_denies_the_pod_cross_read(self):
        dirty = "0x" + "de" * 12 + POD_WITH_SHARES.removeprefix("0x")
        record = _record(get_eigen_pod=dirty, owner_to_pod=dirty)
        assert record["eigenpod_basis"] == EIGENPOD_BASIS_NOT_DETERMINED


class TestStrategyGateIsOnTheIssuedBytes:
    """The quantity is licensed by the issued bytes naming this strategy and this node."""

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
    @pytest.mark.parametrize(
        ("count", "timestamp", "expected"),
        [
            (2**31 - 1, 2**63 - 1, (2**31 - 1, 2**63 - 1)),
            (2**31, 2**63 - 1, (None, 2**63 - 1)),
            (3, 2**63, (3, None)),
            # A 2**200 word would overflow the int columns and take the whole batch down.
            (2**200, 2**200, (None, None)),
        ],
        ids=["at-both-maxima", "count-over-int4", "timestamp-over-int8", "out-of-range-words-not-an-abort"],
    )
    def test_pod_fact_bounds_are_the_column_widths(self, count, timestamp, expected):
        record = _record(active_validator_count=_word(count), last_checkpoint_timestamp=_word(timestamp))
        assert (record["active_validator_count"], record["last_checkpoint_timestamp"]) == expected


class TestPinnedHead:
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

    def test_basis_columns_are_not_null_in_the_reflected_schema(self, db_session):
        """A CHECK evaluating to NULL passes in Postgres."""
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
class TestPersistence:
    def test_producer_never_attempts_a_violating_insert(self, db_session):
        """The CHECKs are a backstop the writer must never lean on."""
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
    """A dropped position must read as refused, not as holding nothing.

    Lives here because this file is in the plane's licensed import surface.
    """
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
