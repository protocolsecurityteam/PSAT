"""The chain-derived asset sweep and the escalation that reaches it.

The governing rule: an EMPTY asset set may be published only from a scan that
can be shown to be whole. Every arm below is about the shown-whole part — a
window that might have been truncated, a bisect that hit its floor, a balance
that could not be read, a multi-token receipt whose holding has no readable
answer. Each of those must abort the claim rather than shorten the list, because
a shortened list reads downstream as "holds less" and eventually as "holds
nothing".
"""

from __future__ import annotations

import pytest

from db.models import Contract, ContractBalance, ContractBalanceFetch, Protocol
from services.monitoring.asset_sweep import (
    SWEEP_COMPLETED,
    SWEEP_FAILED,
    SWEEP_RESULT_CAP,
    TRANSFER_BATCH_TOPIC0,
    TRANSFER_SINGLE_TOPIC0,
    TRANSFER_TOPIC0,
    SweepCost,
    SweptAsset,
    sweep_holders,
)
from services.monitoring.balance_observation import (
    ESCALATE_NO_FETCH_RECORD,
    ESCALATE_PERSISTENT_FAILURE,
    ESCALATE_RETURNED_EMPTY,
    SWEEP_FAILURE_RUN,
    NativeReading,
    escalation_reason,
    observation_contract,
    record_observation,
    sweep_from_block,
)
from services.monitoring.balance_reads import winning_asset_fetches
from services.resolution.repos.event_logs_rpc import (
    MIN_BISECT_SPAN,
    RpcEventLogFetcher,
    normalize_topic_filter,
)
from tests.conftest import requires_postgres
from tests.support.balance_stubs import failed_page, page
from utils.balance_status import (
    ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
    ASSET_SET_SOURCE_ETHERSCAN_PAGES,
    ASSET_SET_STATUS_AT_PAGE_CAP,
    ASSET_SET_STATUS_FETCH_FAILED,
    ASSET_SET_STATUS_RETURNED_ASSETS,
    ASSET_SET_STATUS_RETURNED_EMPTY,
    BALANCE_WRITER_TVL,
    SWEEP_STATUS_COMPLETED,
    SWEEP_STATUS_FAILED,
)

HOLDER = "0x00000000000000000000000000000000000ho1de"[:42].ljust(42, "1")
TOKEN = "0x000000000000000000000000000000000000c0de"
NFT = "0x000000000000000000000000000000000000f731"


def _pad(address: str) -> str:
    return "0x" + address.lower().removeprefix("0x").rjust(64, "0")


def _log(*, emitter: str, topics: list[str], block: int = 5) -> dict:
    return {
        "address": emitter,
        "topics": topics,
        "data": "0x" + "0" * 64,
        "transactionHash": "0x" + "11" * 32,
        "blockHash": "0x" + "22" * 32,
        "logIndex": "0x0",
        "blockNumber": hex(block),
        "transactionIndex": "0x0",
    }


def _word(value: int) -> str:
    return "0x" + f"{value:064x}"


class _StubRpc:
    """One eth_getLogs wire, scripted per call, with the requests recorded."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[dict] = []

    def __call__(self, url, method, params, **kwargs):
        assert method == "eth_getLogs"
        self.calls.append(params[0])
        answer = self.responses.pop(0) if self.responses else []
        if isinstance(answer, Exception):
            raise answer
        return answer


class TestTopicFilter:
    def test_a_flat_topic_sequence_is_still_the_topic0_or_set(self):
        assert normalize_topic_filter(["0xAA", "0xBB"]) == [["0xaa", "0xbb"]]

    def test_an_empty_flat_sequence_keeps_the_payload_it_always_had(self):
        # ``[[]]`` and ``[]`` are different filters; the historical shape wins.
        assert normalize_topic_filter([]) == [[]]

    def test_a_positional_array_keeps_its_none_slots(self):
        assert normalize_topic_filter([["0xAA"], None, ["0xBB", "0xCC"]]) == [["0xaa"], None, ["0xbb", "0xcc"]]

    def test_an_empty_slot_is_refused_rather_than_sent(self):
        # An empty list in a topic slot matches nothing at some upstreams and
        # everything at others, so a batch that came out empty would silently read
        # as either answer.
        with pytest.raises(ValueError):
            normalize_topic_filter([["0xAA"], None, []])


class TestFetchLogsShapes:
    def test_the_address_key_is_omitted_when_no_emitter_is_known(self, monkeypatch):
        rpc = _StubRpc([[]])
        monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", rpc)
        fetcher = RpcEventLogFetcher("http://rpc.invalid", chain_id=1)
        fetcher.fetch_logs(
            event_address=None, topics=[[TRANSFER_TOPIC0], None, [_pad(HOLDER)]], from_block=0, to_block=9
        )
        assert "address" not in rpc.calls[0]
        assert rpc.calls[0]["topics"] == [[TRANSFER_TOPIC0], None, [_pad(HOLDER)]]

    def test_the_historical_call_shape_sends_the_historical_payload(self, monkeypatch):
        rpc = _StubRpc([[]])
        monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", rpc)
        fetcher = RpcEventLogFetcher("http://rpc.invalid", chain_id=1)
        fetcher.fetch_logs(event_address=[TOKEN], topics=[TRANSFER_TOPIC0], from_block=0, to_block=9)
        assert rpc.calls[0]["address"] == [TOKEN]
        assert rpc.calls[0]["topics"] == [[TRANSFER_TOPIC0]]

    def test_a_filter_that_constrains_nothing_is_refused(self, monkeypatch):
        rpc = _StubRpc([[]])
        monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", rpc)
        fetcher = RpcEventLogFetcher("http://rpc.invalid", chain_id=1)
        with pytest.raises(ValueError):
            fetcher.fetch_logs(event_address=None, topics=[None, None], from_block=0, to_block=9)
        assert rpc.calls == []


class TestSweepFailsClosed:
    """§3.5.1 — a window that cannot be shown whole aborts the entity's claim."""

    def _sweep(self, monkeypatch, responses, *, to_block=9):
        rpc = _StubRpc(responses)
        monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", rpc)
        outcomes, cost = sweep_holders(
            [HOLDER],
            rpc_url="http://rpc.invalid",
            chain_id=1,
            from_block_by_address={HOLDER: 0},
            cost=SweepCost(),
            head_block=to_block,
        )
        return outcomes[HOLDER], rpc, cost

    def test_a_page_at_the_result_cap_at_the_bisect_floor_aborts_the_claim(self, monkeypatch):
        # A page whose length reaches the cap is indistinguishable from one the
        # upstream truncated, and at the bisect floor there is no narrower window
        # left to prove it whole with.
        capped = [_log(emitter=TOKEN, topics=[TRANSFER_TOPIC0, _pad(TOKEN), _pad(HOLDER)])] * SWEEP_RESULT_CAP
        outcome, _rpc, _cost = self._sweep(monkeypatch, [capped], to_block=MIN_BISECT_SPAN - 1)
        assert outcome.status == SWEEP_FAILED
        assert outcome.swept_through_block is None
        assert outcome.assets == ()
        assert "could not be proven whole" in (outcome.failure_reason or "")

    def test_a_window_still_rejecting_at_the_floor_aborts_the_claim(self, monkeypatch):
        outcome, _rpc, _cost = self._sweep(monkeypatch, [RuntimeError("query timed out")], to_block=MIN_BISECT_SPAN - 1)
        assert outcome.status == SWEEP_FAILED
        assert outcome.failure_reason and "query timed out" in outcome.failure_reason

    def test_the_sweep_passes_its_own_result_cap_and_never_the_env(self, monkeypatch):
        # Setting PSAT_GETLOGS_RESULT_CAP in-process would change the DURABLE
        # indexer's fetcher; the sweep's cap must come from its own constructor.
        monkeypatch.setenv("PSAT_GETLOGS_RESULT_CAP", "7")
        capped = [_log(emitter=TOKEN, topics=[TRANSFER_TOPIC0, _pad(TOKEN), _pad(HOLDER)])] * 8
        rpc = _StubRpc([capped])
        monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", rpc)
        monkeypatch.setattr(
            "services.monitoring.asset_sweep.multicall3_aggregate3",
            lambda url, calls, block, **kw: [(True, _word(1))] * len(calls),
        )
        outcomes, _cost = sweep_holders(
            [HOLDER],
            rpc_url="http://rpc.invalid",
            chain_id=1,
            from_block_by_address={HOLDER: 0},
            cost=SweepCost(),
            head_block=MIN_BISECT_SPAN - 1,
        )
        # 8 logs would be at the env's cap of 7 but is far below the sweep's own,
        # so the window is accepted rather than raising at the floor.
        assert outcomes[HOLDER].status == SWEEP_COMPLETED

    def test_the_cycle_request_budget_aborts_the_claim_rather_than_the_list(self, monkeypatch):
        # Exceeding the budget must never shorten an asset list: the holder is
        # recorded as a sweep FAILURE, which writes no completeness and no
        # cursor, so the next cycle re-scans the same blocks.
        monkeypatch.setattr("services.monitoring.asset_sweep.SWEEP_REQUEST_BUDGET", 0)
        rpc = _StubRpc([[], []])
        monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", rpc)
        outcomes, cost = sweep_holders(
            [HOLDER],
            rpc_url="http://rpc.invalid",
            chain_id=1,
            from_block_by_address={HOLDER: 0},
            cost=SweepCost(),
            head_block=9,
        )
        assert outcomes[HOLDER].status == SWEEP_FAILED
        assert outcomes[HOLDER].swept_through_block is None
        assert "budget" in (outcomes[HOLDER].failure_reason or "")
        assert cost.get_logs == 0
        assert rpc.calls == []

    def test_an_unknown_head_aborts_rather_than_scanning_to_an_unnamed_end(self, monkeypatch):
        monkeypatch.setattr(
            "services.monitoring.asset_sweep.rpc_request",
            lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("no head")),
        )
        outcomes, _cost = sweep_holders(
            [HOLDER],
            rpc_url="http://rpc.invalid",
            chain_id=1,
            from_block_by_address={HOLDER: 0},
            cost=SweepCost(),
        )
        assert outcomes[HOLDER].status == SWEEP_FAILED
        assert outcomes[HOLDER].swept_through_block is None


class TestSweepDiscovery:
    def test_the_1155_topics_are_asked_for_in_the_recipient_position_they_use(self, monkeypatch):
        rpc = _StubRpc([[], []])
        monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", rpc)
        sweep_holders(
            [HOLDER],
            rpc_url="http://rpc.invalid",
            chain_id=1,
            from_block_by_address={HOLDER: 0},
            cost=SweepCost(),
            head_block=9,
        )
        first, second = rpc.calls
        assert first["topics"][0] == [TRANSFER_TOPIC0, TRANSFER_SINGLE_TOPIC0, TRANSFER_BATCH_TOPIC0]
        assert first["topics"][2] == [_pad(HOLDER)]
        # ERC-1155 indexes (operator, from, to), so a receipt is topic 3 — and a
        # topic-2-only sweep would see 1155 SENDS and miss every 1155 receipt.
        assert second["topics"][0] == [TRANSFER_SINGLE_TOPIC0, TRANSFER_BATCH_TOPIC0]
        assert second["topics"][3] == [_pad(HOLDER)]

    def test_a_four_topic_transfer_is_typed_and_never_an_erc20_asset(self, monkeypatch):
        rpc = _StubRpc(
            [
                [
                    _log(emitter=TOKEN, topics=[TRANSFER_TOPIC0, _pad(TOKEN), _pad(HOLDER)]),
                    _log(emitter=NFT, topics=[TRANSFER_TOPIC0, _pad(NFT), _pad(HOLDER), _word(7)]),
                ],
                [],
            ]
        )
        monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", rpc)
        monkeypatch.setattr(
            "services.monitoring.asset_sweep.multicall3_aggregate3",
            lambda url, calls, block, **kw: [(True, _word(3))] * len(calls),
        )
        outcomes, _cost = sweep_holders(
            [HOLDER],
            rpc_url="http://rpc.invalid",
            chain_id=1,
            from_block_by_address={HOLDER: 0},
            cost=SweepCost(),
            head_block=9,
        )
        outcome = outcomes[HOLDER]
        assert [a.token_address for a in outcome.assets] == [TOKEN]
        assert [a.token_address for a in outcome.typed_assets] == [NFT]

    def test_an_asset_that_answers_no_word_withholds_completeness_without_dropping_the_rest(self, monkeypatch):
        # ERC-1155 has no ``balanceOf(address)`` at all, so "no word" is the normal
        # answer for one. It must not be read as a zero, and it must not throw away
        # the assets that DID answer — it moves to the typed list, whose presence
        # is what withholds the sheet's completeness claim.
        rpc = _StubRpc(
            [
                [
                    _log(emitter=TOKEN, topics=[TRANSFER_TOPIC0, _pad(TOKEN), _pad(HOLDER)]),
                    _log(emitter=NFT, topics=[TRANSFER_TOPIC0, _pad(NFT), _pad(HOLDER)]),
                ],
                [],
            ]
        )
        monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", rpc)
        monkeypatch.setattr(
            "services.monitoring.asset_sweep.multicall3_aggregate3",
            lambda url, calls, block, **kw: [(True, _word(5)) if call[0] == TOKEN else (False, "0x") for call in calls],
        )
        outcomes, _cost = sweep_holders(
            [HOLDER],
            rpc_url="http://rpc.invalid",
            chain_id=1,
            from_block_by_address={HOLDER: 0},
            cost=SweepCost(),
            head_block=9,
        )
        outcome = outcomes[HOLDER]
        assert outcome.status == SWEEP_COMPLETED
        assert [a.token_address for a in outcome.assets] == [TOKEN]
        assert [(a.token_address, a.raw_balance) for a in outcome.typed_assets] == [(NFT, None)]

    def test_a_balanceof_batch_that_never_answers_aborts_the_claim(self, monkeypatch):
        rpc = _StubRpc([[_log(emitter=TOKEN, topics=[TRANSFER_TOPIC0, _pad(TOKEN), _pad(HOLDER)])], []])
        monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", rpc)

        def _boom(*a, **kw):
            raise RuntimeError("multicall down")

        monkeypatch.setattr("services.monitoring.asset_sweep.multicall3_aggregate3", _boom)
        outcomes, _cost = sweep_holders(
            [HOLDER],
            rpc_url="http://rpc.invalid",
            chain_id=1,
            from_block_by_address={HOLDER: 0},
            cost=SweepCost(),
            head_block=9,
        )
        assert outcomes[HOLDER].status == SWEEP_FAILED
        assert "did not answer" in (outcomes[HOLDER].failure_reason or "")

    def test_an_earlier_sweeps_assets_are_re_read_by_the_incremental_window(self, monkeypatch):
        # An incremental window names only what arrived inside it. Publishing that
        # as the row set would withdraw every asset discovered earlier, and the
        # balance view takes a fetch's rows wholesale — so the omission would read
        # as a sale.
        rpc = _StubRpc([[], []])
        monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", rpc)
        monkeypatch.setattr(
            "services.monitoring.asset_sweep.multicall3_aggregate3",
            lambda url, calls, block, **kw: [(True, _word(7))] * len(calls),
        )
        outcomes, _cost = sweep_holders(
            [HOLDER],
            rpc_url="http://rpc.invalid",
            chain_id=1,
            from_block_by_address={HOLDER: 100},
            known_assets_by_address={HOLDER: (TOKEN,)},
            cost=SweepCost(),
            head_block=200,
        )
        assert [(a.token_address, a.raw_balance) for a in outcomes[HOLDER].assets] == [(TOKEN, 7)]

    def test_a_cursor_past_the_head_costs_no_request(self, monkeypatch):
        rpc = _StubRpc([])
        monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", rpc)
        outcomes, cost = sweep_holders(
            [HOLDER],
            rpc_url="http://rpc.invalid",
            chain_id=1,
            from_block_by_address={HOLDER: 100},
            cost=SweepCost(),
            head_block=99,
        )
        assert outcomes[HOLDER].status == SWEEP_COMPLETED
        assert cost.get_logs == 0


@requires_postgres
class TestEscalationAndRecording:
    def _fixture(self, session, address: str = HOLDER):
        proto = Protocol(name=f"p-{address[-6:]}")
        session.add(proto)
        session.flush()
        contract = Contract(protocol_id=proto.id, address=address, chain="ethereum", contract_name="C")
        session.add(contract)
        session.flush()
        return proto, contract

    def _native(self) -> NativeReading:
        return NativeReading(wei=0, block_number=99, failed=False, price_usd=2000.0, symbol="ETH", name="Ether")

    def test_every_answer_shape_that_must_reach_the_chain_does(self, db_session):
        _proto, contract = self._fixture(db_session)
        assert escalation_reason(db_session, contract_id=contract.id, page=page([])) == ESCALATE_RETURNED_EMPTY
        # A list at the cap is NOT one of them: paging past entry 100 is that
        # state's completeness mechanism and has already run by the time this is
        # asked. Sweeping a holder rich enough to overflow the page buys the same
        # completeness at a bisection-dominated cost.
        assert escalation_reason(db_session, contract_id=contract.id, page=page([], page_length=100)) is None
        # No fetch record at all: the entity never got an answer of its own.
        assert escalation_reason(db_session, contract_id=contract.id, page=failed_page()) == ESCALATE_NO_FETCH_RECORD

    def test_one_failure_is_not_persistence_but_a_run_of_them_is(self, db_session):
        _proto, contract = self._fixture(db_session, address="0x" + "a2" * 20)
        for _ in range(3):
            db_session.add(
                ContractBalanceFetch(
                    contract_id=contract.id,
                    chain_id=1,
                    observed_address=contract.address,
                    native_status="not_determined",
                    asset_set_status=ASSET_SET_STATUS_RETURNED_ASSETS,
                    writer=BALANCE_WRITER_TVL,
                )
            )
        db_session.flush()
        assert escalation_reason(db_session, contract_id=contract.id, page=failed_page()) is None
        for _ in range(3):
            db_session.add(
                ContractBalanceFetch(
                    contract_id=contract.id,
                    chain_id=1,
                    observed_address=contract.address,
                    native_status="not_determined",
                    asset_set_status=ASSET_SET_STATUS_FETCH_FAILED,
                    writer=BALANCE_WRITER_TVL,
                )
            )
        db_session.flush()
        assert escalation_reason(db_session, contract_id=contract.id, page=failed_page()) == ESCALATE_PERSISTENT_FAILURE

    def test_a_completed_empty_sweep_records_an_earned_empty_with_its_extent(self, db_session):
        from services.monitoring.asset_sweep import SweepOutcome

        _proto, contract = self._fixture(db_session, address="0x" + "a3" * 20)
        sweep = SweepOutcome(
            address=contract.address,
            status=SWEEP_COMPLETED,
            swept_from_block=0,
            swept_through_block=1234,
            basis="full-history log scan ... blocks 0-1234",
        )
        recorded = record_observation(
            db_session,
            contract=contract,
            chain_id=1,
            native=self._native(),
            page=page([]),
            writer=BALANCE_WRITER_TVL,
            sweep=sweep,
            escalation=ESCALATE_RETURNED_EMPTY,
        )
        db_session.flush()
        assert recorded.asset_set_status == ASSET_SET_STATUS_RETURNED_EMPTY
        assert recorded.asset_set_source == ASSET_SET_SOURCE_CHAIN_LOG_SWEEP
        assert recorded.fetch.swept_through_block == 1234
        assert recorded.fetch.sweep_status == SWEEP_STATUS_COMPLETED
        assert "blocks 0-1234" in (recorded.fetch.asset_set_basis or "")
        # The cursor is what makes the next cycle incremental.
        assert sweep_from_block(db_session, contract_id=contract.id) == 1235

    def test_a_failed_sweep_publishes_no_completeness_and_no_cursor(self, db_session):
        from services.monitoring.asset_sweep import SweepOutcome

        _proto, contract = self._fixture(db_session, address="0x" + "a4" * 20)
        sweep = SweepOutcome(
            address=contract.address,
            status=SWEEP_FAILED,
            swept_from_block=0,
            swept_through_block=None,
            failure_reason="window could not be proven whole",
        )
        recorded = record_observation(
            db_session,
            contract=contract,
            chain_id=1,
            native=self._native(),
            page=page([], page_length=100),
            writer=BALANCE_WRITER_TVL,
            sweep=sweep,
            escalation=ESCALATE_PERSISTENT_FAILURE,
        )
        db_session.flush()
        # The Etherscan answer stands; the escalation's failure is recorded, and
        # the truncation is NOT withdrawn.
        assert recorded.asset_set_status == ASSET_SET_STATUS_AT_PAGE_CAP
        assert recorded.asset_set_source == ASSET_SET_SOURCE_ETHERSCAN_PAGES
        assert recorded.fetch.sweep_status == SWEEP_STATUS_FAILED
        assert recorded.fetch.swept_through_block is None
        assert "ABORTED" in (recorded.fetch.asset_set_basis or "")
        assert sweep_from_block(db_session, contract_id=contract.id) == 0

    def test_a_typed_receipt_with_no_readable_holding_refuses_the_empty(self, db_session):
        from services.monitoring.asset_sweep import SweepOutcome

        _proto, contract = self._fixture(db_session, address="0x" + "a5" * 20)
        sweep = SweepOutcome(
            address=contract.address,
            status=SWEEP_COMPLETED,
            swept_from_block=0,
            swept_through_block=1234,
            typed_assets=(SweptAsset(token_address=NFT, raw_balance=None, decimals=None, kind="typed"),),
            basis="full-history log scan",
        )
        recorded = record_observation(
            db_session,
            contract=contract,
            chain_id=1,
            native=self._native(),
            page=page([]),
            writer=BALANCE_WRITER_TVL,
            sweep=sweep,
            escalation=ESCALATE_RETURNED_EMPTY,
        )
        db_session.flush()
        assert recorded.asset_set_status == ASSET_SET_STATUS_RETURNED_EMPTY
        # ...but NOT as an earned negative: the source stays the third-party
        # index's, so nothing downstream may read this as a chain-proven empty
        # sheet. The cursor still advances — those blocks WERE read.
        assert recorded.asset_set_source == ASSET_SET_SOURCE_ETHERSCAN_PAGES
        assert recorded.fetch.swept_through_block == 1234
        assert "ERC-721/1155" in (recorded.fetch.asset_set_basis or "")
        assert "NOT claimed complete" in (recorded.fetch.asset_set_basis or "")

    def test_a_swept_asset_is_written_unpriced_and_never_as_zero_dollars(self, db_session):
        from services.monitoring.asset_sweep import SweepOutcome

        _proto, contract = self._fixture(db_session, address="0x" + "a6" * 20)
        sweep = SweepOutcome(
            address=contract.address,
            status=SWEEP_COMPLETED,
            swept_from_block=0,
            swept_through_block=1234,
            assets=(SweptAsset(token_address=TOKEN, raw_balance=500, decimals=6, kind="erc20"),),
            basis="full-history log scan",
        )
        recorded = record_observation(
            db_session,
            contract=contract,
            chain_id=1,
            native=self._native(),
            page=page([]),
            writer=BALANCE_WRITER_TVL,
            sweep=sweep,
            escalation=ESCALATE_RETURNED_EMPTY,
        )
        db_session.flush()
        assert recorded.asset_set_status == ASSET_SET_STATUS_RETURNED_ASSETS
        token_rows = [r for r in recorded.rows if r.token_address == TOKEN]
        assert len(token_rows) == 1
        assert token_rows[0].usd_value is None and token_rows[0].price_usd is None
        assert token_rows[0].source == ASSET_SET_SOURCE_CHAIN_LOG_SWEEP
        assert token_rows[0].raw_balance == "500"

    def test_the_fetch_row_is_filed_against_the_contract_whose_address_was_read(self, db_session):
        proto, impl = self._fixture(db_session, address="0x" + "a7" * 20)
        proxy = Contract(protocol_id=proto.id, address="0x" + "a8" * 20, chain="ethereum", contract_name="Proxy")
        db_session.add(proxy)
        db_session.flush()
        # The resolution worker's shape: a job on the implementation carrying the
        # proxy as the address to read.
        target = observation_contract(db_session, fallback=impl, chain_id=1, requested_address=proxy.address)
        assert target.id == proxy.id
        recorded = record_observation(
            db_session,
            contract=target,
            chain_id=1,
            native=NativeReading(
                wei=19 * 10**18, block_number=99, failed=False, price_usd=2000.0, symbol="ETH", name="Ether"
            ),
            page=page([]),
            writer=BALANCE_WRITER_TVL,
        )
        db_session.flush()
        assert recorded.fetch.contract_id == proxy.id
        assert recorded.fetch.observed_address == proxy.address
        native_rows = (
            db_session.query(ContractBalance)
            .filter(ContractBalance.fetch_id == recorded.fetch.id, ContractBalance.token_address.is_(None))
            .all()
        )
        assert [r.contract_id for r in native_rows] == [proxy.id]
        assert [r.observed_address for r in native_rows] == [proxy.address]

    def test_the_known_asset_list_is_read_off_the_rows_a_consumer_sees(self, db_session):
        from services.monitoring.balance_observation import known_swept_assets

        _proto, contract = self._fixture(db_session, address="0x" + "b1" * 20)
        from services.monitoring.asset_sweep import SweepOutcome

        recorded = record_observation(
            db_session,
            contract=contract,
            chain_id=1,
            native=self._native(),
            page=page([]),
            writer=BALANCE_WRITER_TVL,
            sweep=SweepOutcome(
                address=contract.address,
                status=SWEEP_COMPLETED,
                swept_from_block=0,
                swept_through_block=1234,
                assets=(SweptAsset(token_address=TOKEN, raw_balance=9, decimals=6, kind="erc20"),),
                basis="scan",
            ),
            escalation=ESCALATE_RETURNED_EMPTY,
        )
        db_session.flush()
        assert recorded.asset_set_status == ASSET_SET_STATUS_RETURNED_ASSETS
        # The next cycle's incremental window would name nothing; this is what
        # keeps the asset from silently disappearing out of the row set.
        assert known_swept_assets(db_session, contract_id=contract.id) == (TOKEN,)

    def test_a_run_of_failed_scans_stops_the_escalation_asking_again(self, db_session):
        from services.monitoring.balance_observation import sweep_keeps_failing

        _proto, contract = self._fixture(db_session, address="0x" + "b2" * 20)
        for _ in range(SWEEP_FAILURE_RUN):
            db_session.add(
                ContractBalanceFetch(
                    contract_id=contract.id,
                    chain_id=1,
                    observed_address=contract.address,
                    native_status="not_determined",
                    asset_set_status=ASSET_SET_STATUS_RETURNED_EMPTY,
                    sweep_status=SWEEP_STATUS_FAILED,
                    writer=BALANCE_WRITER_TVL,
                )
            )
        db_session.flush()
        assert sweep_keeps_failing(db_session, contract_id=contract.id) is True
        # ...and the trigger that would otherwise fire stops firing, so an
        # unprovable holder cannot spend the request budget every hour forever.
        assert escalation_reason(db_session, contract_id=contract.id, page=page([])) is None

    def test_a_later_failed_fetch_cannot_withdraw_a_truncation_its_rows_still_carry(self, db_session):
        proto, contract = self._fixture(db_session, address="0x" + "a9" * 20)
        truncated = ContractBalanceFetch(
            contract_id=contract.id,
            chain_id=1,
            observed_address=contract.address,
            native_status="not_determined",
            asset_set_status=ASSET_SET_STATUS_AT_PAGE_CAP,
            writer=BALANCE_WRITER_TVL,
        )
        db_session.add(truncated)
        db_session.flush()
        db_session.add(
            ContractBalance(
                contract_id=contract.id,
                token_address=TOKEN,
                decimals=18,
                raw_balance="1",
                fetch_id=truncated.id,
                observed_address=contract.address,
            )
        )
        later_failure = ContractBalanceFetch(
            contract_id=contract.id,
            chain_id=1,
            observed_address=contract.address,
            native_status="not_determined",
            asset_set_status=ASSET_SET_STATUS_FETCH_FAILED,
            writer=BALANCE_WRITER_TVL,
        )
        db_session.add(later_failure)
        db_session.flush()
        # The LATEST fetch says nothing about completeness; the fetch whose rows
        # the view publishes says they are a prefix, and that is the one a sheet
        # summing those rows must be told about.
        winners = winning_asset_fetches(db_session, proto.id)
        assert winners[contract.id].id == truncated.id
        assert winners[contract.id].asset_set_status == ASSET_SET_STATUS_AT_PAGE_CAP
