"""The optional historical scanner and current observation publisher.

The governing rule: an EMPTY asset set may be published only from a scan that
can be shown to be whole. Every arm below is about the shown-whole part — a
window that might have been truncated, a bisect that hit its floor, a balance
that could not be read, a multi-token receipt whose holding has no readable
answer. Each of those must abort the claim rather than shorten the list, because
a shortened list reads downstream as "holds less" and eventually as "holds
nothing".
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from decimal import Decimal

import pytest
from sqlalchemy import text

from db.models import Contract, ContractBalance, ContractBalanceFetch, Protocol
from services.clients.rpc import selector as rpc_selector
from services.monitoring import asset_sweep as A
from services.monitoring.asset_sweep import (
    SWEEP_COMPLETED,
    SWEEP_FAILED,
    SWEEP_RESULT_CAP,
    TRANSFER_BATCH_TOPIC0,
    TRANSFER_SINGLE_TOPIC0,
    TRANSFER_TOPIC0,
    TYPED_BASIS_ADDRESS_BALANCE,
    TYPED_BASIS_PER_ID_BALANCE_OF_BATCH,
    TYPED_BASIS_PER_ID_BALANCE_OF_ID,
    TYPED_BASIS_PER_ID_OWNER_OF,
    TYPED_STANDARD_ERC721,
    TYPED_STANDARD_ERC1155,
    TYPED_STANDARD_NOT_DETERMINED,
    TYPED_STANDARD_TRANSFER_NO_ID,
    CarriedTypedReceipt,
    SweepCost,
    SweptAsset,
    TypedItem,
    sweep_holders,
)
from services.monitoring.balance_observation import (
    NativeReading,
    observation_contract,
    record_observation,
)
from services.monitoring.balance_reads import ObservationSubject, winning_asset_fetches
from services.resolution.repos.event_logs_rpc import (
    MIN_BISECT_SPAN,
)
from tests.conftest import requires_postgres
from tests.support.balance_stubs import failed_page, page
from utils.balance_status import (
    ASSET_SET_SOURCE_ETHERSCAN_PAGES,
    ASSET_SET_STATUS_AT_PAGE_CAP,
    ASSET_SET_STATUS_FETCH_FAILED,
    BALANCE_WRITER_TVL,
)

HOLDER = "0x00000000000000000000000000000000000a01de"
TOKEN = "0x000000000000000000000000000000000000c0de"
NFT = "0x000000000000000000000000000000000000f731"


def _pad(address: str) -> str:
    return "0x" + address.lower().removeprefix("0x").rjust(64, "0")


def _addr_n(n: int) -> str:
    return "0x" + f"{n:040x}"


def _log(*, emitter: str, topics: list[str], block: int = 5, data: str = "0x" + "0" * 64) -> dict:
    identity = hashlib.sha256((emitter + repr(topics) + data).encode()).hexdigest()
    return {
        "address": emitter,
        "topics": topics,
        "data": data,
        "transactionHash": "0x" + identity,
        "blockHash": "0x" + "22" * 32,
        "logIndex": hex(int(identity[:8], 16)),
        "blockNumber": hex(block),
        "transactionIndex": "0x0",
    }


def _word(value: int) -> str:
    return "0x" + f"{value:064x}"


def _typed(
    token: str,
    *,
    raw_balance: int | None = None,
    standard: str = TYPED_STANDARD_ERC721,
    ids: tuple[str, ...] = (),
    ids_complete: bool = True,
    quantity_basis: str | None = None,
) -> SweptAsset:
    """A typed receipt as a real scan produces it: with a settled id inventory."""
    return SweptAsset(
        token_address=token,
        raw_balance=raw_balance,
        decimals=None,
        kind="typed",
        standard=standard,
        items=tuple(TypedItem(token_id=token_id, quantity=None) for token_id in ids),
        ids_complete=ids_complete,
        quantity_basis=quantity_basis,
    )


def _carried(
    token: str,
    *,
    standard: str = TYPED_STANDARD_ERC721,
    ids: tuple[str, ...] = (),
    ids_complete: bool = True,
) -> CarriedTypedReceipt:
    return CarriedTypedReceipt(address=token, standard=standard, ids=ids, ids_complete=ids_complete)


def _page_row(token: str) -> dict:
    """One holdings row in the shape ``get_token_balances_page`` returns."""
    return {
        "token_address": token,
        "token_name": "T",
        "token_symbol": "T",
        "decimals": 18,
        "balance": 1000,
        "price_usd": None,
        "usd_value": None,
    }


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


def test_streaming_sweep_keeps_budget_across_both_recipient_passes(monkeypatch):
    calls = _StubRpc([[]])
    monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", calls)
    monkeypatch.setattr(A, "SWEEP_REQUEST_BUDGET", 1)
    cost = SweepCost()
    _erc20, _typed, failure = A.discover_recipient_assets(
        [HOLDER], rpc_url="http://rpc.invalid", chain_id=1, from_block=0, to_block=9, cost=cost
    )
    assert len(calls.calls) == cost.get_logs == 1
    assert failure is not None and "budget" in failure


def test_streaming_sweep_charges_transport_retry(monkeypatch):
    calls = 0

    def rpc(_url, _method, _params, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            kwargs["before_retry"]()
        return []

    monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", rpc)
    monkeypatch.setattr(A, "SWEEP_REQUEST_BUDGET", 2)
    cost = SweepCost()
    _erc20, _typed, failure = A.discover_recipient_assets(
        [HOLDER], rpc_url="http://rpc.invalid", chain_id=1, from_block=0, to_block=9, cost=cost
    )
    assert calls == 1
    assert cost.get_logs == 2
    assert failure is not None and "budget" in failure


def test_streaming_sweep_memory_does_not_scale_with_window_count():
    """The old accumulated list retained every decoded log across windows."""
    code = r"""
import json, resource, sys, tracemalloc
from services.monitoring import asset_sweep as A
from services.resolution.repos import event_logs_rpc
holder = "0x" + "a" * 40
token = "0x" + "b" * 40
padded = "0x" + holder[2:].rjust(64, "0")
token_topic = "0x" + token[2:].rjust(64, "0")
def rpc(_url, _method, params, **_kwargs):
    query = params[0]
    if len(query["topics"]) == 4:
        return []
    block = int(query["fromBlock"], 16)
    return [{"address": token, "topics": [A.TRANSFER_TOPIC0, token_topic, padded],
             "data": "0x" + "0" * 64, "transactionHash": "0x" + f"{block * 2500 + i:064x}",
             "blockHash": "0x" + f"{block:064x}", "logIndex": hex(i),
             "transactionIndex": hex(i), "blockNumber": hex(block)} for i in range(2500)]
event_logs_rpc.rpc_request = rpc
windows = int(sys.argv[1])
tracemalloc.start()
cost = A.SweepCost()
assets, typed, failure = A.discover_recipient_assets(
    [holder], rpc_url="http://rpc.invalid", chain_id=1,
    from_block=0, to_block=windows * 1000000 - 1, cost=cost)
assert failure is None and assets[holder] == {token} and not typed[holder]
assert cost.get_logs == 2 * windows
print(json.dumps({"traced_peak": tracemalloc.get_traced_memory()[1],
                  "rss_peak_kb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}))
"""

    def profile(windows):
        env = dict(os.environ, PSAT_MEMORY_SAMPLE_INTERVAL_S="0")
        result = subprocess.run(
            [sys.executable, "-c", code, str(windows)],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )
        return json.loads(result.stdout)

    one, eight = profile(1), profile(8)
    assert eight["traced_peak"] - one["traced_peak"] < 15 * 1024 * 1024
    assert eight["rss_peak_kb"] - one["rss_peak_kb"] < 24 * 1024


class TestBatchFailureIsIsolatedToItsCause:
    """A batch shares its windows, so it used to share its failures.

    The recipient filter is an OR-set in one topic position, which is what makes
    forty holders cost one request instead of forty. The same sharing meant one
    address with a dense incoming history refused thirty-nine quiet neighbours a
    completeness each of them individually could have had — fail-closed, but far
    wider than the evidence supports.
    """

    def _rpc(self, monkeypatch, *, refuse: str):
        """A wire that rejects exactly the windows naming *refuse*."""
        calls: list[dict] = []

        def _request(url, method, params, **kwargs):
            assert method == "eth_getLogs"
            calls.append(params[0])
            wanted = [t for slot in params[0]["topics"] if isinstance(slot, list) for t in slot]
            if _pad(refuse) in wanted:
                raise RuntimeError("query timed out")
            return []

        monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", _request)
        monkeypatch.setattr(
            "services.monitoring.asset_sweep.multicall3_aggregate3",
            lambda url, calls_, block, **kw: [(True, _word(0))] * len(calls_),
        )
        return calls

    def test_only_the_address_that_cannot_be_proven_whole_fails(self, monkeypatch):
        quiet_a, quiet_b = _addr_n(1), _addr_n(2)
        busy = _addr_n(3)
        self._rpc(monkeypatch, refuse=busy)
        outcomes, _cost = sweep_holders(
            [quiet_a, quiet_b, busy],
            rpc_url="http://rpc.invalid",
            chain_id=1,
            from_block_by_address={a: 0 for a in (quiet_a, quiet_b, busy)},
            cost=SweepCost(),
            head_block=MIN_BISECT_SPAN - 1,
        )
        assert outcomes[quiet_a].status == SWEEP_COMPLETED
        assert outcomes[quiet_b].status == SWEEP_COMPLETED
        assert outcomes[busy].status == SWEEP_FAILED
        # The guard is not weakened for the address it fired on.
        assert outcomes[busy].swept_through_block is None
        assert "could not be proven whole" in (outcomes[busy].failure_reason or "")

    def test_an_exhausted_budget_stops_the_isolation_rather_than_spending_more(self, monkeypatch):
        # The budget is why the failure fired; splitting cannot buy an answer
        # with no requests left, so every holder is honestly recorded unproven.
        monkeypatch.setattr("services.monitoring.asset_sweep.SWEEP_REQUEST_BUDGET", 0)
        calls = self._rpc(monkeypatch, refuse=_addr_n(3))
        outcomes, _cost = sweep_holders(
            [_addr_n(1), _addr_n(2), _addr_n(3)],
            rpc_url="http://rpc.invalid",
            chain_id=1,
            from_block_by_address={_addr_n(n): 0 for n in (1, 2, 3)},
            cost=SweepCost(),
            head_block=MIN_BISECT_SPAN - 1,
        )
        assert {o.status for o in outcomes.values()} == {SWEEP_FAILED}
        assert calls == []


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

    def test_a_late_second_pass_failure_never_publishes_the_first_pass(self, monkeypatch):
        first = _log(emitter=TOKEN, topics=[TRANSFER_TOPIC0, _pad(TOKEN), _pad(HOLDER)])
        outcome, _rpc, cost = self._sweep(
            monkeypatch, [[first], RuntimeError("second recipient pass rejected")], to_block=MIN_BISECT_SPAN - 1
        )
        assert cost.get_logs == 2
        assert outcome.status == SWEEP_FAILED
        assert outcome.swept_through_block is None
        assert outcome.assets == ()

    def test_a_malformed_accepted_page_is_not_a_complete_scan(self, monkeypatch):
        malformed = _log(emitter=TOKEN, topics=[TRANSFER_TOPIC0, _pad(TOKEN), _pad(HOLDER)])
        malformed["removed"] = True
        outcome, _rpc, _cost = self._sweep(monkeypatch, [[malformed]], to_block=MIN_BISECT_SPAN - 1)
        assert outcome.status == SWEEP_FAILED
        assert outcome.swept_through_block is None

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

    def test_a_cursor_past_the_head_scans_nothing_but_still_republishes_the_set(self, monkeypatch):
        # "No new asset can have arrived" is not "no asset is held". The view
        # takes a fetch's rows wholesale, so publishing an empty set here would
        # withdraw every holding the last cycle found and claim chain-proven
        # emptiness off a scan that read no blocks at all.
        rpc = _StubRpc([])
        monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", rpc)
        monkeypatch.setattr(
            "services.monitoring.asset_sweep.multicall3_aggregate3",
            lambda url, calls, block, **kw: [(True, _word(3)) if call[0] == TOKEN else (False, "0x") for call in calls],
        )
        outcomes, cost = sweep_holders(
            [HOLDER],
            rpc_url="http://rpc.invalid",
            chain_id=1,
            from_block_by_address={HOLDER: 100},
            # THE OVERLAPPING SHAPE THE CORPUS PRODUCES. A typed asset with a
            # readable count is stored as a row, and the stored-row reader behind
            # ``known_assets`` cannot tell a count row from a quantity row — so
            # the NFT appears in BOTH carried lists. Passing disjoint lists here
            # would test a shape the producer never hands over.
            known_assets_by_address={HOLDER: (TOKEN, NFT)},
            known_typed_by_address={HOLDER: (_carried(NFT),)},
            union_from_by_address={HOLDER: 0},
            cost=SweepCost(),
            head_block=99,
        )
        outcome = outcomes[HOLDER]
        assert outcome.status == SWEEP_COMPLETED
        assert cost.get_logs == 0
        # The NFT must NOT come back as a fungible asset: its decimals() reverts,
        # and an erc20-kinded row would then store an item count at 18 decimals.
        assert [(a.token_address, a.raw_balance) for a in outcome.assets] == [(TOKEN, 3)]
        assert [(a.token_address, a.kind) for a in outcome.typed_assets] == [(NFT, "typed")]
        assert outcome.swept_from_block == 0

    def test_the_basis_names_the_union_extent_not_the_incremental_window(self, monkeypatch):
        rpc = _StubRpc([[], []])
        monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", rpc)
        outcomes, _cost = sweep_holders(
            [HOLDER],
            rpc_url="http://rpc.invalid",
            chain_id=1,
            from_block_by_address={HOLDER: 900},
            union_from_by_address={HOLDER: 0},
            cost=SweepCost(),
            head_block=963,
        )
        # The window was 63 blocks wide; the CLAIM rests on everything since 0.
        assert "blocks 0-963" in outcomes[HOLDER].basis
        assert "blocks 900-963" not in outcomes[HOLDER].basis
        assert outcomes[HOLDER].swept_from_block == 0

    def test_a_carried_typed_asset_is_never_folded_into_the_fungible_set(self, monkeypatch):
        # Its balanceOf is a COUNT of items when it answers at all. Folding it in
        # on a later cycle presents that count as an 18-decimal quantity.
        rpc = _StubRpc([[], []])
        monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", rpc)
        monkeypatch.setattr(
            "services.monitoring.asset_sweep.multicall3_aggregate3",
            lambda url, calls, block, **kw: [(True, _word(2))] * len(calls),
        )
        outcomes, _cost = sweep_holders(
            [HOLDER],
            rpc_url="http://rpc.invalid",
            chain_id=1,
            from_block_by_address={HOLDER: 10},
            known_typed_by_address={HOLDER: (_carried(NFT),)},
            union_from_by_address={HOLDER: 0},
            cost=SweepCost(),
            head_block=20,
        )
        outcome = outcomes[HOLDER]
        assert [a.token_address for a in outcome.assets] == []
        assert [(a.token_address, a.kind) for a in outcome.typed_assets] == [(NFT, "typed")]


_BALANCE_OF = rpc_selector("balanceOf(address)")
_BALANCE_OF_ID = rpc_selector("balanceOf(address,uint256)")
_BALANCE_OF_BATCH = rpc_selector("balanceOfBatch(address[],uint256[])")
_OWNER_OF = rpc_selector("ownerOf(uint256)")


def _single_data(token_id: int, value: int) -> str:
    return "0x" + f"{token_id:064x}" + f"{value:064x}"


def _batch_data(ids: list[int], values: list[int]) -> str:
    """A canonical ``TransferBatch`` payload: two dynamic ``uint256[]`` tails."""
    ids_off = 64
    values_off = 64 + 32 + 32 * len(ids)
    words = [f"{ids_off:064x}", f"{values_off:064x}", f"{len(ids):064x}"]
    words += [f"{i:064x}" for i in ids]
    words += [f"{len(values):064x}"] + [f"{v:064x}" for v in values]
    return "0x" + "".join(words)


def _uint_array_return(values: list[int]) -> str:
    """What ``balanceOfBatch`` returns: one ``uint256[]``, head then tail."""
    return "0x" + f"{32:064x}" + f"{len(values):064x}" + "".join(f"{v:064x}" for v in values)


def _current_typed_entry(session, contract) -> dict:
    """The one typed entry a consumer reads off the CURRENT fetch."""
    from services.monitoring.balance_observation import _current_asset_fetch

    fetch = _current_asset_fetch(session, subject=ObservationSubject.of_contract(contract))
    assert fetch is not None
    return (fetch.typed_assets or [])[0]


def _words(raw: str) -> list[str]:
    """Split an ABI payload the way the fetcher's ``data_words`` does, but without
    its length guard, so a malformed payload reaches the decoder under test."""
    body = raw[2:] if raw.startswith("0x") else raw
    return ["0x" + body[index : index + 64] for index in range(0, len(body), 64)]


class _StubCalls:
    """One Multicall3 wire, answering per selector, with the calldata recorded."""

    def __init__(self, *, address_balance=None, batch=None, balance_of_id=None, owner=None):
        self.address_balance = address_balance
        self.batch = batch
        self.balance_of_id = balance_of_id
        self.owner = owner
        self.calls: list[tuple[str, str]] = []
        self.rounds = 0

    def __call__(self, url, calls, block, **kw):
        self.rounds += 1
        self.calls.extend(calls)
        out = []
        for target, data in calls:
            if data.startswith(_BALANCE_OF_BATCH):
                out.append(self.batch(target, data) if self.batch else (False, "0x"))
            elif data.startswith(_BALANCE_OF_ID):
                out.append(self.balance_of_id(target, data) if self.balance_of_id else (False, "0x"))
            elif data.startswith(_OWNER_OF):
                out.append(self.owner(target, data) if self.owner else (False, "0x"))
            elif data.startswith(_BALANCE_OF):
                out.append(self.address_balance(target, data) if self.address_balance else (False, "0x"))
            else:  # decimals()
                out.append((True, _word(0)))
        return out


class TestTypedIdDecode:
    """The ABI decode, adversarially. Every case here is a payload a token could
    emit and this decoder could get wrong, and getting it wrong in the permissive
    direction is the dangerous one: a SHORT id list reads as a whole inventory,
    and an all-ids-read-zero claim over it publishes "holds nothing" for ids
    nobody looked at. So the rule is a decode this reader cannot follow exactly is
    refused, never approximated.
    """

    def test_the_canonical_batch_layout_decodes(self):
        assert A._batch_ids(_words(_batch_data([5, 9], [1, 2]))) == ["5", "9"]

    def test_a_values_first_tail_is_followed_by_its_offset_not_by_position(self):
        # ids at 0xa0 because values were laid out first. Reading word 2 as the
        # length would return the VALUES array as the id list.
        raw = "0x" + "".join(
            [
                f"{0xA0:064x}",  # ids[] tail, second in the payload
                f"{0x40:064x}",  # values[] tail, first
                f"{2:064x}",
                f"{111:064x}",
                f"{222:064x}",  # values
                f"{2:064x}",
                f"{5:064x}",
                f"{9:064x}",  # ids
            ]
        )
        assert A._batch_ids(_words(raw)) == ["5", "9"]

    def test_a_non_minimal_offset_over_padding_is_followed_too(self):
        raw = "0x" + "".join(
            [
                f"{0x60:064x}",  # ids[] tail, one padding word past the head
                f"{0xC0:064x}",
                f"{0:064x}",  # padding
                f"{1:064x}",
                f"{7:064x}",  # ids
                f"{0:064x}",
                f"{1:064x}",
                f"{1:064x}",  # values
            ]
        )
        assert A._batch_ids(_words(raw)) == ["7"]

    def test_an_empty_id_array_is_settled_empty_and_not_malformed(self):
        # A batch that delivered nothing named no id. That is an answer — an
        # inventory of zero ids — and refusing it as malformed would send the
        # contract back for a full-history re-scan it can never satisfy.
        assert A._batch_ids(_words(_batch_data([], []))) == []

    def test_trailing_garbage_past_the_arrays_is_ignored(self):
        assert A._batch_ids(_words(_batch_data([5], [1]) + f"{0xDEAD:064x}")) == ["5"]

    @pytest.mark.parametrize(
        "raw",
        [
            "0x" + f"{0x20:064x}" + f"{4:064x}" + f"{5:064x}",  # length past the payload
            "0x" + f"{0x21:064x}" + f"{1:064x}" + f"{5:064x}",  # offset not a multiple of 32
            "0x" + f"{0x400:064x}" + f"{1:064x}",  # offset past the end
            "0x" + f"{0x20:064x}" + f"{2**64:064x}",  # absurd length
            "0x" + f"{0x20:064x}" + f"{1:064x}" + "z" * 64,  # non-hex tail word
            "0x",  # nothing at all
        ],
    )
    def test_a_layout_this_decoder_cannot_follow_is_refused(self, raw):
        assert A._batch_ids(_words(raw)) is None

    def test_a_transfer_single_needs_both_of_its_words(self):
        # One word is the id with no value: not the event this decoder claims to
        # have read, so it names no id rather than a possibly-wrong one.
        assert A._single_ids(_words("0x" + f"{7:064x}")) is None
        assert A._single_ids(_words("0x")) is None
        assert A._single_ids(_words(_single_data(7, 3))) == ["7"]

    def test_the_uint_array_decoder_is_the_same_one_the_answers_go_through(self):
        # One decoder for the TransferBatch id array and the balanceOfBatch
        # answer: two would drift, and the drift would be silent.
        assert A._uint_array(_words(_uint_array_return([0, 4, 0]))) == [0, 4, 0]
        assert A._uint_array(_words("0x" + f"{0x20:064x}" + f"{3:064x}" + f"{1:064x}")) is None


class TestTypedReceiptIdRecovery:
    """The ids an ERC-1155 receipt needs, and the one scan that recovers them.

    ``balanceOf(address)`` does not exist on ERC-1155, so an address-level read of
    one of these receipts answers nothing forever — and "nothing" is not zero, so
    the sheet stays refused. The only call that answers is per token id, and the
    ids live in the delivering logs and nowhere else. This class is about
    decoding them, reading them, and above all STORING them: an inventory that is
    not persisted is a full-history re-scan every hour.
    """

    def _sweep(self, monkeypatch, logs_by_pass, calls, **kwargs):
        rpc = _StubRpc(logs_by_pass)
        monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", rpc)
        monkeypatch.setattr("services.monitoring.asset_sweep.multicall3_aggregate3", calls)
        return sweep_holders(
            [HOLDER],
            rpc_url="http://rpc.invalid",
            chain_id=1,
            from_block_by_address={HOLDER: 0},
            cost=SweepCost(),
            head_block=9,
            **kwargs,
        )

    def test_a_transfer_single_names_the_id_it_delivered(self, monkeypatch):
        calls = _StubCalls(batch=lambda t, d: (True, _uint_array_return([0])))
        outcomes, _cost = self._sweep(
            monkeypatch,
            [
                [],
                [
                    _log(
                        emitter=NFT,
                        topics=[TRANSFER_SINGLE_TOPIC0, _pad(NFT), _pad(NFT), _pad(HOLDER)],
                        data=_single_data(7, 3),
                    )
                ],
            ],
            calls,
        )
        receipt = outcomes[HOLDER].typed_assets[0]
        assert receipt.standard == TYPED_STANDARD_ERC1155
        assert [item.token_id for item in receipt.items] == ["7"]
        assert receipt.ids_complete is True

    def test_a_transfer_batch_names_every_id_in_its_array(self, monkeypatch):
        calls = _StubCalls(batch=lambda t, d: (True, _uint_array_return([0, 0])))
        outcomes, _cost = self._sweep(
            monkeypatch,
            [
                [],
                [
                    _log(
                        emitter=NFT,
                        topics=[TRANSFER_BATCH_TOPIC0, _pad(NFT), _pad(NFT), _pad(HOLDER)],
                        data=_batch_data([5, 9], [1, 1]),
                    )
                ],
            ],
            calls,
        )
        receipt = outcomes[HOLDER].typed_assets[0]
        assert [item.token_id for item in receipt.items] == ["5", "9"]
        assert receipt.raw_balance == 0
        assert receipt.quantity_basis == TYPED_BASIS_PER_ID_BALANCE_OF_BATCH

    def test_a_log_whose_ids_cannot_be_decoded_withholds_the_whole_inventory(self, monkeypatch):
        # A short data payload is not a batch of zero ids. Reading it as one would
        # let "every id reads zero" be published over ids nobody ever saw, so the
        # token's inventory is withheld and no per-id read is issued for it.
        calls = _StubCalls(batch=lambda t, d: (True, _uint_array_return([0])))
        outcomes, _cost = self._sweep(
            monkeypatch,
            [
                [],
                [
                    _log(
                        emitter=NFT,
                        topics=[TRANSFER_SINGLE_TOPIC0, _pad(NFT), _pad(NFT), _pad(HOLDER)],
                        data="0x",
                    )
                ],
            ],
            calls,
        )
        receipt = outcomes[HOLDER].typed_assets[0]
        assert receipt.ids_complete is False
        assert receipt.raw_balance is None
        assert not [c for c in calls.calls if c[1].startswith(_BALANCE_OF_BATCH)]

    def test_every_id_reading_zero_is_what_resolves_the_receipt(self, monkeypatch):
        calls = _StubCalls(batch=lambda t, d: (True, _uint_array_return([0, 0])))
        outcomes, cost = self._sweep(
            monkeypatch,
            [
                [],
                [
                    _log(
                        emitter=NFT,
                        topics=[TRANSFER_SINGLE_TOPIC0, _pad(NFT), _pad(NFT), _pad(HOLDER)],
                        data=_single_data(7, 3),
                    ),
                    _log(
                        emitter=NFT,
                        topics=[TRANSFER_SINGLE_TOPIC0, _pad(NFT), _pad(NFT), _pad(HOLDER)],
                        data=_single_data(8, 1),
                    ),
                ],
            ],
            calls,
        )
        receipt = outcomes[HOLDER].typed_assets[0]
        assert receipt.raw_balance == 0
        assert [(i.token_id, i.quantity) for i in receipt.items] == [("7", 0), ("8", 0)]
        # Both ids in ONE balanceOfBatch call, and the whole cohort's per-id round
        # is ONE aggregate3 on top of the address-level round — the recovery costs
        # a request per chain, not a request per id.
        batch_calls = [c for c in calls.calls if c[1].startswith(_BALANCE_OF_BATCH)]
        assert len(batch_calls) == 1
        assert cost.multicall == 2

    def test_one_non_zero_id_keeps_the_receipt_refused(self, monkeypatch):
        # An item still held. The count is published — it is a real reading — but
        # it is not zero, so nothing downstream may read the sheet as empty.
        calls = _StubCalls(batch=lambda t, d: (True, _uint_array_return([0, 2])))
        outcomes, _cost = self._sweep(
            monkeypatch,
            [
                [],
                [
                    _log(
                        emitter=NFT,
                        topics=[TRANSFER_SINGLE_TOPIC0, _pad(NFT), _pad(NFT), _pad(HOLDER)],
                        data=_single_data(7, 3),
                    ),
                    _log(
                        emitter=NFT,
                        topics=[TRANSFER_SINGLE_TOPIC0, _pad(NFT), _pad(NFT), _pad(HOLDER)],
                        data=_single_data(8, 1),
                    ),
                ],
            ],
            calls,
        )
        receipt = outcomes[HOLDER].typed_assets[0]
        assert receipt.raw_balance == 2
        assert [(i.token_id, i.quantity) for i in receipt.items] == [("7", 0), ("8", 2)]

    def test_one_unanswered_id_refuses_the_receipt_rather_than_shrinking_it(self, monkeypatch):
        # The all-quantifier is the claim. A batch that came back short is not a
        # smaller holding, and taking the ids that did answer would publish a zero
        # over an id nobody read.
        calls = _StubCalls(batch=lambda t, d: (True, _uint_array_return([0])))
        outcomes, _cost = self._sweep(
            monkeypatch,
            [
                [],
                [
                    _log(
                        emitter=NFT,
                        topics=[TRANSFER_BATCH_TOPIC0, _pad(NFT), _pad(NFT), _pad(HOLDER)],
                        data=_batch_data([5, 9], [1, 1]),
                    )
                ],
            ],
            calls,
        )
        receipt = outcomes[HOLDER].typed_assets[0]
        assert receipt.raw_balance is None
        assert receipt.quantity_basis is None
        # The IDS are still stored, so the next cycle retries the read alone.
        assert [i.token_id for i in receipt.items] == ["5", "9"]
        assert receipt.ids_complete is True

    def test_a_token_that_reverts_the_batch_read_is_asked_one_id_at_a_time(self, monkeypatch):
        # ERC-1155 mandates both selectors; a token that emits conforming logs is
        # not thereby a token that implements them. Four contracts on the real
        # corpus revert ``balanceOfBatch`` and answer ``balanceOf(address,id)``.
        # Stopping at the first revert would file a readable holding as
        # not_determined.
        calls = _StubCalls(batch=lambda t, d: (False, "0x"), balance_of_id=lambda t, d: (True, _word(4)))
        outcomes, _cost = self._sweep(
            monkeypatch,
            [
                [],
                [
                    _log(
                        emitter=NFT,
                        topics=[TRANSFER_SINGLE_TOPIC0, _pad(NFT), _pad(NFT), _pad(HOLDER)],
                        data=_single_data(7, 1),
                    )
                ],
            ],
            calls,
        )
        receipt = outcomes[HOLDER].typed_assets[0]
        assert receipt.raw_balance == 4
        assert receipt.quantity_basis == TYPED_BASIS_PER_ID_BALANCE_OF_ID
        assert [(i.token_id, i.quantity) for i in receipt.items] == [("7", 4)]

    def test_the_fallback_round_only_asks_about_what_the_batch_left_unread(self, monkeypatch):
        calls = _StubCalls(
            batch=lambda t, d: (True, _uint_array_return([0])) if t == NFT else (False, "0x"),
            balance_of_id=lambda t, d: (True, _word(0)),
        )
        other = "0x000000000000000000000000000000000000f732"
        outcomes, _cost = self._sweep(
            monkeypatch,
            [
                [],
                [
                    _log(
                        emitter=NFT,
                        topics=[TRANSFER_SINGLE_TOPIC0, _pad(NFT), _pad(NFT), _pad(HOLDER)],
                        data=_single_data(7, 1),
                    ),
                    _log(
                        emitter=other,
                        topics=[TRANSFER_SINGLE_TOPIC0, _pad(other), _pad(other), _pad(HOLDER)],
                        data=_single_data(9, 1),
                    ),
                ],
            ],
            calls,
        )
        by_token = {a.token_address: a for a in outcomes[HOLDER].typed_assets}
        assert by_token[NFT].quantity_basis == TYPED_BASIS_PER_ID_BALANCE_OF_BATCH
        assert by_token[other].quantity_basis == TYPED_BASIS_PER_ID_BALANCE_OF_ID
        assert [t for t, d in calls.calls if d.startswith(_BALANCE_OF_ID)] == [other]

    def test_a_reverting_per_id_call_never_becomes_a_zero(self, monkeypatch):
        calls = _StubCalls(batch=lambda t, d: (False, "0x"))
        outcomes, _cost = self._sweep(
            monkeypatch,
            [
                [],
                [
                    _log(
                        emitter=NFT,
                        topics=[TRANSFER_SINGLE_TOPIC0, _pad(NFT), _pad(NFT), _pad(HOLDER)],
                        data=_single_data(7, 3),
                    )
                ],
            ],
            calls,
        )
        assert outcomes[HOLDER].typed_assets[0].raw_balance is None

    def test_a_721_whose_balance_reverts_is_asked_who_owns_each_id(self, monkeypatch):
        calls = _StubCalls(owner=lambda t, d: (True, _pad(TOKEN)))
        outcomes, _cost = self._sweep(
            monkeypatch,
            [[_log(emitter=NFT, topics=[TRANSFER_TOPIC0, _pad(NFT), _pad(HOLDER), _word(42)])], []],
            calls,
        )
        receipt = outcomes[HOLDER].typed_assets[0]
        assert receipt.standard == TYPED_STANDARD_ERC721
        # Owned by someone else now: the item arrived and provably left.
        assert receipt.raw_balance == 0
        assert receipt.quantity_basis == TYPED_BASIS_PER_ID_OWNER_OF

    def test_a_721_still_owned_by_the_holder_counts_as_held(self, monkeypatch):
        calls = _StubCalls(owner=lambda t, d: (True, _pad(HOLDER)))
        outcomes, _cost = self._sweep(
            monkeypatch,
            [[_log(emitter=NFT, topics=[TRANSFER_TOPIC0, _pad(NFT), _pad(HOLDER), _word(42)])], []],
            calls,
        )
        assert outcomes[HOLDER].typed_assets[0].raw_balance == 1

    def test_an_answering_address_balance_needs_no_per_id_round(self, monkeypatch):
        # ERC-721 answers ``balanceOf(address)``. Asking per id anyway would spend
        # a call per token id for a number already in hand.
        calls = _StubCalls(address_balance=lambda t, d: (True, _word(0)), owner=lambda t, d: (True, _pad(HOLDER)))
        outcomes, _cost = self._sweep(
            monkeypatch,
            [[_log(emitter=NFT, topics=[TRANSFER_TOPIC0, _pad(NFT), _pad(HOLDER), _word(42)])], []],
            calls,
        )
        receipt = outcomes[HOLDER].typed_assets[0]
        assert receipt.raw_balance == 0
        assert receipt.quantity_basis == TYPED_BASIS_ADDRESS_BALANCE
        assert [i.token_id for i in receipt.items] == ["42"]
        assert not [c for c in calls.calls if c[1].startswith(_OWNER_OF)]

    def test_the_balance_of_batch_calldata_names_the_holder_once_per_id(self, monkeypatch):
        calls = _StubCalls(batch=lambda t, d: (True, _uint_array_return([0, 0])))
        self._sweep(
            monkeypatch,
            [
                [],
                [
                    _log(
                        emitter=NFT,
                        topics=[TRANSFER_BATCH_TOPIC0, _pad(NFT), _pad(NFT), _pad(HOLDER)],
                        data=_batch_data([5, 9], [1, 1]),
                    )
                ],
            ],
            calls,
        )
        data = next(c[1] for c in calls.calls if c[1].startswith(_BALANCE_OF_BATCH))
        words = [data[10 + i * 64 : 10 + (i + 1) * 64] for i in range((len(data) - 10) // 64)]
        assert int(words[0], 16) == 64  # accounts[] tail
        assert int(words[1], 16) == 64 + 32 + 32 * 2  # ids[] tail, past accounts'
        assert int(words[2], 16) == 2
        assert words[3] == words[4] == _pad(HOLDER)[2:]
        assert int(words[5], 16) == 2
        assert [int(words[6], 16), int(words[7], 16)] == [5, 9]

    def test_a_carried_inventory_reads_the_holding_without_re_scanning_history(self, monkeypatch):
        # The whole point. An incremental window will never name these ids again —
        # they are a million blocks behind the cursor — so the read has to come off
        # the stored inventory or not at all.
        calls = _StubCalls(batch=lambda t, d: (True, _uint_array_return([0, 0])))
        rpc = _StubRpc([[], []])
        monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", rpc)
        monkeypatch.setattr("services.monitoring.asset_sweep.multicall3_aggregate3", calls)
        outcomes, _cost = sweep_holders(
            [HOLDER],
            rpc_url="http://rpc.invalid",
            chain_id=1,
            from_block_by_address={HOLDER: 900},
            known_typed_by_address={
                HOLDER: (_carried(NFT, standard=TYPED_STANDARD_ERC1155, ids=("5", "9"), ids_complete=True),)
            },
            union_from_by_address={HOLDER: 0},
            cost=SweepCost(),
            head_block=963,
        )
        receipt = outcomes[HOLDER].typed_assets[0]
        assert receipt.raw_balance == 0
        assert [i.token_id for i in receipt.items] == ["5", "9"]

    def test_an_incremental_window_never_promotes_a_partial_inventory_to_a_whole_one(self, monkeypatch):
        # The window saw one new id; the record carried none it could vouch for.
        # The union is still a prefix, so nothing is read per id.
        calls = _StubCalls(batch=lambda t, d: (True, _uint_array_return([0])))
        rpc = _StubRpc(
            [
                [],
                [
                    _log(
                        emitter=NFT,
                        topics=[TRANSFER_SINGLE_TOPIC0, _pad(NFT), _pad(NFT), _pad(HOLDER)],
                        block=900,
                        data=_single_data(7, 1),
                    )
                ],
            ]
        )
        monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", rpc)
        monkeypatch.setattr("services.monitoring.asset_sweep.multicall3_aggregate3", calls)
        outcomes, _cost = sweep_holders(
            [HOLDER],
            rpc_url="http://rpc.invalid",
            chain_id=1,
            from_block_by_address={HOLDER: 900},
            known_typed_by_address={HOLDER: (_carried(NFT, standard=TYPED_STANDARD_ERC1155, ids_complete=False),)},
            union_from_by_address={HOLDER: 0},
            cost=SweepCost(),
            head_block=963,
        )
        receipt = outcomes[HOLDER].typed_assets[0]
        assert receipt.ids_complete is False
        assert receipt.raw_balance is None
        assert not [c for c in calls.calls if c[1].startswith(_BALANCE_OF_BATCH)]

    def test_a_token_the_full_history_never_typed_has_a_settled_empty_inventory(self, monkeypatch):
        # An ERC-20 whose ``balanceOf`` returns no word is filed with the typed
        # receipts for the completeness it withholds, but it carries no id and
        # never will. Its inventory is SETTLED empty — otherwise it would demand a
        # fresh full-history scan every cycle, forever.
        calls = _StubCalls()
        outcomes, _cost = self._sweep(
            monkeypatch,
            [[_log(emitter=TOKEN, topics=[TRANSFER_TOPIC0, _pad(TOKEN), _pad(HOLDER)])], []],
            calls,
        )
        receipt = outcomes[HOLDER].typed_assets[0]
        assert receipt.standard == TYPED_STANDARD_TRANSFER_NO_ID
        assert receipt.ids_complete is True
        assert receipt.items == ()
        assert receipt.raw_balance is None

    def test_two_standards_on_one_token_leave_the_standard_undetermined(self, monkeypatch):
        # No selector can be chosen from a contradiction, so none is called.
        calls = _StubCalls(batch=lambda t, d: (True, _uint_array_return([0])))
        outcomes, _cost = self._sweep(
            monkeypatch,
            [
                [_log(emitter=NFT, topics=[TRANSFER_TOPIC0, _pad(NFT), _pad(HOLDER), _word(42)])],
                [
                    _log(
                        emitter=NFT,
                        topics=[TRANSFER_SINGLE_TOPIC0, _pad(NFT), _pad(NFT), _pad(HOLDER)],
                        data=_single_data(7, 1),
                    )
                ],
            ],
            calls,
        )
        receipt = outcomes[HOLDER].typed_assets[0]
        assert receipt.standard == TYPED_STANDARD_NOT_DETERMINED
        assert receipt.raw_balance is None
        assert not [c for c in calls.calls if c[1].startswith(_BALANCE_OF_BATCH)]


@requires_postgres
class TestCurrentObservationRecording:
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

    def test_a_sub_cent_holding_reaches_the_column_at_the_precision_it_was_computed_at(self, db_session):
        """The write is where a priced fact used to die.

        ``usd_value`` was ``numeric(20,2)`` and the native leg rounded to 2dp
        before it, so $0.00156 — an integer quantity at a real price — arrived as
        0.00, which no reader can tell from a holding of nothing. Both halves are
        pinned: the producer writes what it computed, and the column keeps it.
        Asserted off a row re-read from Postgres, never off the ORM object, so
        what is under test is what was STORED.
        """
        _proto, contract = self._fixture(db_session, address="0x" + "c1" * 20)
        # 7.8e-7 ETH at $2000 = $0.00156, and 1 wei at $2000 = $2e-15 — one
        # figure the old 2dp column erased, one below even six decimals.
        native = NativeReading(
            wei=780_000_000_000, block_number=99, failed=False, price_usd=2000.0, symbol="ETH", name="Ether"
        )
        recorded = record_observation(
            db_session,
            subject=ObservationSubject.of_contract(contract),
            chain_id=1,
            native=native,
            page=page(
                [
                    {
                        "token_address": TOKEN,
                        "token_name": "T",
                        "token_symbol": "T",
                        "decimals": 18,
                        "balance": 1,
                        "price_usd": 1.9,
                        "usd_value": 1.9e-9,
                    }
                ]
            ),
            writer=BALANCE_WRITER_TVL,
        )
        db_session.flush()
        db_session.expire_all()
        stored = {
            r.token_address: r.usd_value
            for r in db_session.query(ContractBalance).filter(ContractBalance.fetch_id == recorded.fetch.id).all()
        }

        native_usd = (780_000_000_000 / 1e18) * 2000.0
        # The producer rounds nothing. The column's own last digit is the 18th
        # fractional one, so the stored figure is the computed one quantized
        # THERE and nowhere coarser — the assertion says which resolution is
        # allowed to be lossy, rather than accepting whatever came back.
        assert stored[None] == Decimal(str(native_usd)).quantize(Decimal("1e-18"))
        assert stored[None] == Decimal("0.001560000000000000")
        # And it is the case the old column destroyed — a figure that rounds to
        # $0.00 at the cent yet is not zero.
        assert round(float(stored[None]), 2) == 0.0
        assert stored[None] != Decimal(0)

        # The token leg carried full precision already; the column is what was
        # throwing it away, including below the value plane's own six decimals.
        assert stored[TOKEN] == Decimal(str(1.9e-9)).quantize(Decimal("1e-18"))
        assert stored[TOKEN] == Decimal("0.000000001900000000")
        assert round(float(stored[TOKEN]), 6) == 0.0
        assert stored[TOKEN] != Decimal(0)

    def test_the_columns_hold_eighteen_fractional_digits_and_the_view_projects_them(self, db_session):
        """The storage claim, asserted against Postgres rather than the model.

        The ORM declaration and the migrated column can disagree — an ALTER that
        silently no-ops, or a view left rebuilt on the old type, would leave every
        precision assertion above passing on a widened Python value that the
        database still truncates.
        """
        scales = dict(
            db_session.execute(
                text(
                    "SELECT table_name, numeric_scale FROM information_schema.columns "
                    "WHERE table_name IN ('contract_balances', 'contract_balances_latest') "
                    "AND column_name = 'usd_value'"
                )
            ).all()
        )
        assert scales == {"contract_balances": 18, "contract_balances_latest": 18}

    def test_the_price_column_holds_eighteen_fractional_digits_too(self, db_session):
        """The quote is a fact of the same fineness as the figure computed from it.

        ``price_usd`` was ``numeric(20,8)``, and 0 is the literal the writers use
        for "no price known" — so a token quoted below ``1e-8`` had its real quote
        stored as that same 0 and became indistinguishable from a price that never
        answered. Asserted against ``information_schema`` rather than the model,
        for the reason above: the ORM declaration and the migrated column can
        disagree, and the view can be left rebuilt on the old type.
        """
        scales = dict(
            db_session.execute(
                text(
                    "SELECT table_name, numeric_scale FROM information_schema.columns "
                    "WHERE table_name IN ('contract_balances', 'contract_balances_latest') "
                    "AND column_name = 'price_usd'"
                )
            ).all()
        )
        assert scales == {"contract_balances": 18, "contract_balances_latest": 18}

    def test_a_quote_below_the_eighth_decimal_reaches_the_column_intact(self, db_session):
        """The ambiguity the widening closes, pinned on a stored row.

        ``2.5e-12`` is an ordinary quote for a token with a supply in the
        trillions. The narrow column stored it as ``0.00000000`` — the same value
        the producer writes for "no price known" — so the row could no longer say
        which of the two it was. Re-read from Postgres, never off the ORM object.
        """
        _proto, contract = self._fixture(db_session, address="0x" + "c2" * 20)
        recorded = record_observation(
            db_session,
            subject=ObservationSubject.of_contract(contract),
            chain_id=1,
            native=NativeReading(wei=None, block_number=None, failed=True, price_usd=None, symbol="ETH", name="Ether"),
            page=page(
                [
                    {
                        "token_address": TOKEN,
                        "token_name": "T",
                        "token_symbol": "T",
                        "decimals": 18,
                        "balance": 10**24,
                        "price_usd": 2.5e-12,
                        "usd_value": (10**24 / 10**18) * 2.5e-12,
                    }
                ]
            ),
            writer=BALANCE_WRITER_TVL,
        )
        db_session.flush()
        db_session.expire_all()
        stored = (
            db_session.query(ContractBalance)
            .filter(ContractBalance.fetch_id == recorded.fetch.id, ContractBalance.token_address == TOKEN)
            .one()
        )

        assert stored.price_usd == Decimal("0.000000000002500000")
        # The point of the widening: the quote is no longer the literal that
        # means "nobody priced this".
        assert stored.price_usd != Decimal(0)
        assert round(float(stored.price_usd), 8) == 0.0

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
            subject=ObservationSubject.of_contract(target),
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

    def test_another_tenants_row_is_never_adopted_for_a_read(self, db_session):
        # ``uq_contract_address_chain`` means there is at most ONE row per
        # (address, chain) — so the row that owns an address a job asks about may
        # simply belong to a different protocol. Adopting it would write fetches,
        # rows and a retention prune against another tenant's contract: one
        # protocol's job mutating another's balance plane. Falling back to this
        # row's own address loses an observation, which is the direction that
        # cannot corrupt a neighbour.
        mine, my_contract = self._fixture(db_session, address="0x" + "c1" * 20)
        theirs = Protocol(name="other-tenant")
        db_session.add(theirs)
        db_session.flush()
        shared = "0x" + "c2" * 20
        db_session.add(Contract(protocol_id=theirs.id, address=shared, chain="ethereum", contract_name="Theirs"))
        db_session.flush()

        target = observation_contract(db_session, fallback=my_contract, chain_id=1, requested_address=shared)
        assert target.id == my_contract.id
        assert target.protocol_id == mine.id

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

    @pytest.mark.parametrize("provider_page", [page([]), failed_page(), page([], page_length=100)])
    def test_current_publication_never_starts_a_history_scan(self, db_session, monkeypatch, provider_page):
        _, contract = self._fixture(db_session)

        def forbidden(*args, **kwargs):
            raise AssertionError("Current publication must not scan history")

        monkeypatch.setattr("services.monitoring.balance_observation.run_sweeps", forbidden)
        recorded = record_observation(
            db_session,
            subject=ObservationSubject.of_contract(contract),
            chain_id=1,
            native=self._native(),
            page=provider_page,
            writer=BALANCE_WRITER_TVL,
        )
        assert recorded.fetch.asset_set_status == provider_page.status
        assert recorded.fetch.asset_set_source == ASSET_SET_SOURCE_ETHERSCAN_PAGES
        assert recorded.fetch.swept_through_block is None
