"""The disposition scan: what it may publish, and the four ways it must refuse.

Every arm here is about the same rule. A delivery-shape positive is an
all-quantifier over a pair's deliveries, so it may only stand when the delivery
set is whole and every member of it was metered. These tests hold the scanner to
that: the earned positive, the earned negative, and the three gaps — an
unreadable receipt, an unmeterable delivery, and an empty delivery set — that
must each land on ``not_determined`` rather than on either verdict.

The wire is stubbed at ``rpc_request``, which is where the repo puts the seam:
the fetcher, the receipt helper and the head read all go through it, so the
request SEQUENCE these tests count is the one production issues.
"""

from __future__ import annotations

import pytest

from db.models import Contract, ContractBalance, ContractBalanceFetch, Protocol, TokenDeliveryEvidence
from services.monitoring import delivery_shape
from services.monitoring.asset_sweep import TRANSFER_BATCH_TOPIC0, TRANSFER_SINGLE_TOPIC0, TRANSFER_TOPIC0
from services.monitoring.delivery_shape import (
    DispositionRequest,
    disposition_requests,
    scan_delivery_shape,
)
from tests.conftest import requires_postgres
from utils.balance_status import (
    ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
    ASSET_SET_SOURCE_ETHERSCAN_PAGES,
    ASSET_SET_STATUS_AT_PAGE_CAP,
    ASSET_SET_STATUS_RETURNED_ASSETS,
    DELIVERY_FAN_OUT_BASIS_RECEIPT,
    DELIVERY_FAN_OUT_BASIS_UNREADABLE,
    DELIVERY_SHAPE_FAN_OUT_ALL,
    DELIVERY_SHAPE_HAS_DIRECT_DELIVERY,
    DELIVERY_SHAPE_NOT_DETERMINED,
    NATIVE_STATUS_PROVEN_NONZERO,
)

pytestmark = requires_postgres

CHAIN = 1
OPTIMISM = 10
HEAD = 1_000_000
CREATION = 900_000


def _addr(seed: str) -> str:
    return ("0x" + seed.rjust(40, "0"))[:42].lower()


HOLDER = _addr("a11ce")
TOKEN = _addr("70ce4")
OTHER_TOKEN = _addr("70ce5")


def _pad(address: str) -> str:
    return "0x" + address.removeprefix("0x").rjust(64, "0")


def _tx(n: int) -> str:
    return "0x" + f"{n:064x}"


def _log(*, token: str, holder: str, tx: int, block: int, log_index: int, topics: int = 3) -> dict:
    """One raw ``Transfer`` log as the upstream returns it.

    ``topics=4`` is the ERC-721 shape: the third indexed slot is a token id, not
    a quantity, and the fan-out meter is not defined over it.
    """
    slots = [TRANSFER_TOPIC0, _pad(_addr("5ende4")), _pad(holder)]
    if topics == 4:
        slots.append("0x" + f"{7:064x}")
    return {
        "address": token,
        "topics": slots,
        "data": "0x" + f"{10**18:064x}",
        "transactionHash": _tx(tx),
        "blockHash": _tx(tx + 900),
        "logIndex": hex(log_index),
        "blockNumber": hex(block),
        "transactionIndex": "0x0",
    }


def _receipt(*, token: str, same_token_transfers: int) -> dict:
    """A receipt whose *same_token_transfers* logs are 3-topic same-token sends."""
    logs = [
        {"address": token, "topics": [TRANSFER_TOPIC0, _pad(_addr("5ende4")), _pad(_addr(f"{i:x}"))]}
        for i in range(same_token_transfers)
    ]
    # One unrelated log, so the meter is shown to count same-token transfers
    # rather than the receipt's length.
    logs.append({"address": _addr("f00d"), "topics": [TRANSFER_TOPIC0, _pad(HOLDER), _pad(HOLDER)]})
    return {"logs": logs, "blockHash": _tx(1), "blockNumber": hex(HEAD)}


class Wire:
    """The stubbed upstream, and the counter the cost assertions read."""

    def __init__(self, *, logs: list[dict] | None = None, receipts: dict[str, dict | None] | None = None) -> None:
        self.logs = logs or []
        self.receipts = receipts or {}
        self.head = HEAD
        self.get_logs_calls: list[dict] = []
        self.receipt_calls: list[str] = []

    def __call__(self, url, method, params, *args, **kwargs):
        if method == "eth_getLogs":
            self.get_logs_calls.append(params[0])
            log_filter = params[0]
            lo = int(log_filter["fromBlock"], 16)
            hi = int(log_filter["toBlock"], 16)
            addresses = log_filter.get("address")
            wanted = {a.lower() for a in addresses} if isinstance(addresses, list) else None
            topic_filter = log_filter["topics"]
            out = []
            for raw in self.logs:
                if not (lo <= int(raw["blockNumber"], 16) <= hi):
                    continue
                if wanted is not None and raw["address"].lower() not in wanted:
                    continue
                if not _matches(raw["topics"], topic_filter):
                    continue
                out.append(raw)
            return out
        if method == "eth_getTransactionReceipt":
            self.receipt_calls.append(params[0])
            receipt = self.receipts.get(params[0], "missing")
            if receipt == "missing":
                raise RuntimeError("upstream refused the receipt")
            return receipt
        raise AssertionError(f"unexpected method {method}")


def _matches(topics: list[str], topic_filter: list) -> bool:
    for index, slot in enumerate(topic_filter):
        if slot is None:
            continue
        if index >= len(topics):
            return False
        if topics[index].lower() not in {t.lower() for t in slot}:
            return False
    return True


@pytest.fixture(autouse=True)
def _clean_evidence(db_session):
    """Delivery evidence outlives the protocol it was measured beside.

    That is the point of the plane — the row is a block-stamped fact about two
    addresses, so it carries no protocol FK and nothing cascades it away. The
    shared teardown therefore cannot reach it, and these tests clear it
    themselves.
    """
    db_session.query(TokenDeliveryEvidence).delete()
    db_session.commit()
    yield
    db_session.rollback()
    db_session.query(TokenDeliveryEvidence).delete()
    db_session.commit()


@pytest.fixture
def wire(monkeypatch):
    """Install a stub wire and a deterministic head/creation block."""
    delivery_shape.clear_creation_block_cache()
    installed = Wire()

    def _rpc(url, method, params, *args, **kwargs):
        return installed(url, method, params, *args, **kwargs)

    monkeypatch.setattr("utils.rpc.rpc_request", _rpc)
    monkeypatch.setattr("services.resolution.repos.event_logs_rpc.rpc_request", _rpc)

    def _head(rpc_url, *, chain_id, cost):
        cost.head_reads += 1
        return installed.head

    monkeypatch.setattr("services.monitoring.asset_sweep.sweep_head_block", _head)
    monkeypatch.setattr("utils.etherscan.get_contract_creation_block", lambda address, **kw: CREATION)
    yield installed
    delivery_shape.clear_creation_block_cache()


def _rpc_url_for(_chain_id: int) -> str:
    return "http://stub.invalid"


def _request(tokens=(), *, chain_id: int = CHAIN, holder: str = HOLDER, typed=()) -> DispositionRequest:
    return DispositionRequest(
        contract_id=1,
        chain_id=chain_id,
        holder_address=holder,
        tokens=tuple(tokens) or (TOKEN,),
        typed_tokens=tuple(typed),
    )


def _facts(session) -> dict[tuple[str, str], TokenDeliveryEvidence]:
    return {(row.holder_address, row.token_address): row for row in session.query(TokenDeliveryEvidence).all()}


# --- the earned verdicts ---------------------------------------------------


def test_every_delivery_above_k_earns_the_positive(db_session, wire):
    wire.logs = [
        _log(token=TOKEN, holder=HOLDER, tx=1, block=910_000, log_index=3),
        _log(token=TOKEN, holder=HOLDER, tx=2, block=920_000, log_index=9),
    ]
    wire.receipts = {
        _tx(1): _receipt(token=TOKEN, same_token_transfers=200),
        _tx(2): _receipt(token=TOKEN, same_token_transfers=480),
    }

    cost = scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)

    row = _facts(db_session)[(HOLDER, TOKEN)]
    assert row.delivery_shape == DELIVERY_SHAPE_FAN_OUT_ALL
    assert row.min_fan_out == 200
    assert row.unreadable_deliveries == 0
    assert row.delivery_count == 2
    assert row.scanned_from_block == CREATION
    assert row.measured_through_block == HEAD
    # The basis scopes the claim to the range, the filter and K — a positive
    # whose extent is not stated is a positive over an unstated set.
    assert f"{CREATION}..{HEAD}" in row.basis
    assert "K=25" in row.basis
    assert "recipient topic 2" in row.basis
    assert cost.get_logs == 1 and cost.receipts == 2 and cost.creation_lookups == 1


def test_one_delivery_below_k_is_the_earned_negative(db_session, wire):
    wire.logs = [
        _log(token=TOKEN, holder=HOLDER, tx=1, block=910_000, log_index=3),
        _log(token=TOKEN, holder=HOLDER, tx=2, block=920_000, log_index=9),
    ]
    wire.receipts = {
        _tx(1): _receipt(token=TOKEN, same_token_transfers=500),
        _tx(2): _receipt(token=TOKEN, same_token_transfers=1),
    }

    scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)

    row = _facts(db_session)[(HOLDER, TOKEN)]
    assert row.delivery_shape == DELIVERY_SHAPE_HAS_DIRECT_DELIVERY
    assert row.min_fan_out == 1


# --- the three refusals ----------------------------------------------------


def test_one_unreadable_receipt_beats_every_huge_fan_out(db_session, wire):
    """The arm that matters most: a gap is not outvoted by a majority.

    Two of the three deliveries are unmistakable mass distributions. The third
    could not be read, so nothing is known about it — and a claim that EVERY
    delivery was a distribution cannot be earned from a set with a member nobody
    measured, however lopsided the rest.
    """
    wire.logs = [
        _log(token=TOKEN, holder=HOLDER, tx=1, block=910_000, log_index=1),
        _log(token=TOKEN, holder=HOLDER, tx=2, block=920_000, log_index=2),
        _log(token=TOKEN, holder=HOLDER, tx=3, block=930_000, log_index=3),
    ]
    wire.receipts = {
        _tx(1): _receipt(token=TOKEN, same_token_transfers=1400),
        _tx(2): _receipt(token=TOKEN, same_token_transfers=2379),
        _tx(3): None,
    }

    scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)

    row = _facts(db_session)[(HOLDER, TOKEN)]
    assert row.delivery_shape == DELIVERY_SHAPE_NOT_DETERMINED
    assert row.unreadable_deliveries == 1
    assert row.delivery_count == 3
    # The unreadable delivery is STORED, not dropped: the record has to say
    # which delivery the gap is, or a later cycle cannot close it.
    bases = [entry["fan_out_basis"] for entry in row.deliveries]
    assert bases.count(DELIVERY_FAN_OUT_BASIS_UNREADABLE) == 1
    assert bases.count(DELIVERY_FAN_OUT_BASIS_RECEIPT) == 2
    assert [entry for entry in row.deliveries if entry["fan_out"] is None][0]["tx"] == _tx(3)


def test_no_deliveries_found_is_not_determined_and_never_a_positive(db_session, wire):
    wire.logs = []

    scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)

    row = _facts(db_session)[(HOLDER, TOKEN)]
    assert row.delivery_shape == DELIVERY_SHAPE_NOT_DETERMINED
    assert row.delivery_count == 0
    assert row.min_fan_out is None


def test_a_four_topic_transfer_forces_not_determined(db_session, wire):
    """An ERC-721 delivery indexes a token id where the meter expects nothing.

    It is carried as an unreadable delivery rather than skipped, so the pair
    refuses instead of publishing a verdict over the deliveries that happened to
    be meterable.
    """
    wire.logs = [
        _log(token=TOKEN, holder=HOLDER, tx=1, block=910_000, log_index=1),
        _log(token=TOKEN, holder=HOLDER, tx=2, block=920_000, log_index=2, topics=4),
    ]
    wire.receipts = {_tx(1): _receipt(token=TOKEN, same_token_transfers=900)}

    scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)

    row = _facts(db_session)[(HOLDER, TOKEN)]
    assert row.delivery_shape == DELIVERY_SHAPE_NOT_DETERMINED
    assert row.unreadable_deliveries == 1
    # No receipt was spent on the delivery the meter cannot read.
    assert wire.receipt_calls == [_tx(1)]


# --- accretion and steady state -------------------------------------------


def test_a_second_scan_accretes_and_only_ever_withdraws(db_session, wire):
    wire.logs = [_log(token=TOKEN, holder=HOLDER, tx=1, block=910_000, log_index=1)]
    wire.receipts = {_tx(1): _receipt(token=TOKEN, same_token_transfers=700)}
    scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)
    db_session.flush()
    first = _facts(db_session)[(HOLDER, TOKEN)]
    assert first.delivery_shape == DELIVERY_SHAPE_FAN_OUT_ALL

    # A later block brings a settlement-shaped delivery. The positive withdraws;
    # the earlier delivery is still on the row.
    wire.head = HEAD + 500_000
    wire.logs.append(_log(token=TOKEN, holder=HOLDER, tx=2, block=HEAD + 10, log_index=4))
    wire.receipts[_tx(2)] = _receipt(token=TOKEN, same_token_transfers=1)
    second = scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)
    db_session.flush()

    row = _facts(db_session)[(HOLDER, TOKEN)]
    assert row.delivery_shape == DELIVERY_SHAPE_HAS_DIRECT_DELIVERY
    assert row.delivery_count == 2
    assert row.min_fan_out == 1
    # The full-history window is NOT re-read: the row's own extent says where to
    # resume, so the earlier delivery is carried rather than re-fetched.
    assert row.scanned_from_block == CREATION
    assert row.measured_through_block == HEAD + 500_000
    assert second.receipts == 1
    assert int(wire.get_logs_calls[-1]["fromBlock"], 16) == HEAD + 1


def test_a_second_scan_never_lowers_the_cursor(db_session, wire):
    wire.logs = [_log(token=TOKEN, holder=HOLDER, tx=1, block=910_000, log_index=1)]
    wire.receipts = {_tx(1): _receipt(token=TOKEN, same_token_transfers=700)}
    scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)
    db_session.flush()

    # An upstream that answers with a LOWER head — a lagging replica. The stored
    # extent is a claim already published at the greater height.
    wire.head = HEAD - 100_000
    scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)
    db_session.flush()

    assert _facts(db_session)[(HOLDER, TOKEN)].measured_through_block == HEAD


def test_a_cursored_pair_costs_nothing_on_the_next_cycle(db_session, wire):
    wire.logs = [_log(token=TOKEN, holder=HOLDER, tx=1, block=910_000, log_index=1)]
    wire.receipts = {_tx(1): _receipt(token=TOKEN, same_token_transfers=700)}
    scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)
    db_session.flush()

    second = scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)

    # Head still has to be read; nothing else does. That is what makes the
    # full-history pass a once-per-pair cost rather than an hourly one.
    assert second.get_logs == 0
    assert second.receipts == 0
    assert second.creation_lookups == 0
    assert second.head_reads == 1


# --- budget ----------------------------------------------------------------


def test_budget_exhaustion_writes_no_partial_evidence(db_session, wire, monkeypatch):
    """A pair the budget stopped mid-measurement is unwritten, not shortened.

    Discovery finds two deliveries and the ceiling falls before either receipt.
    A row written here would carry a delivery set nobody metered, which is the
    one thing the all-quantifier cannot be evaluated over.
    """
    wire.logs = [
        _log(token=TOKEN, holder=HOLDER, tx=1, block=910_000, log_index=1),
        _log(token=TOKEN, holder=HOLDER, tx=2, block=920_000, log_index=2),
    ]
    wire.receipts = {
        _tx(1): _receipt(token=TOKEN, same_token_transfers=900),
        _tx(2): _receipt(token=TOKEN, same_token_transfers=900),
    }
    # head (1) + creation (1) + getLogs (1) reaches the ceiling exactly.
    monkeypatch.setattr(delivery_shape, "DISPOSITION_REQUEST_BUDGET", 3)

    cost = scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)

    assert _facts(db_session) == {}
    assert wire.receipt_calls == []
    assert cost.total == 3


def test_budget_exhaustion_before_discovery_writes_nothing(db_session, wire, monkeypatch):
    wire.logs = [_log(token=TOKEN, holder=HOLDER, tx=1, block=910_000, log_index=1)]
    monkeypatch.setattr(delivery_shape, "DISPOSITION_REQUEST_BUDGET", 2)

    scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)

    assert _facts(db_session) == {}
    assert wire.get_logs_calls == []


# --- per-chain windows -----------------------------------------------------


def test_optimism_scans_ten_thousand_block_windows_from_the_creation_block(db_session, wire):
    """Optimism's upstream refuses a wider range, so the window is its cap.

    The creation-block seed is what keeps that affordable: from genesis the same
    scan is four orders of magnitude more requests.
    """
    wire.logs = [_log(token=TOKEN, holder=HOLDER, tx=1, block=950_000, log_index=1)]
    wire.receipts = {_tx(1): _receipt(token=TOKEN, same_token_transfers=900)}

    cost = scan_delivery_shape(db_session, [_request(chain_id=OPTIMISM)], rpc_url_for=_rpc_url_for)

    spans = [(int(call["fromBlock"], 16), int(call["toBlock"], 16)) for call in wire.get_logs_calls]
    assert spans[0][0] == CREATION, "the scan is seeded at the holder's creation block, not at genesis"
    assert all(hi - lo + 1 <= 10_000 for lo, hi in spans)
    assert spans[-1][1] == HEAD
    # (HEAD - CREATION + 1) / 10_000, rounded up.
    assert cost.get_logs == 11
    assert _facts(db_session)[(HOLDER, TOKEN)].delivery_shape == DELIVERY_SHAPE_FAN_OUT_ALL


def test_a_wide_chain_reads_the_whole_history_in_one_window(db_session, wire):
    wire.logs = [_log(token=TOKEN, holder=HOLDER, tx=1, block=950_000, log_index=1)]
    wire.receipts = {_tx(1): _receipt(token=TOKEN, same_token_transfers=900)}

    cost = scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)

    assert cost.get_logs == 1


# --- the population --------------------------------------------------------


def _protocol(session, name: str) -> Protocol:
    proto = Protocol(name=name)
    session.add(proto)
    session.flush()
    return proto


def _contract(session, protocol_id: int, address: str, chain: str = "ethereum") -> Contract:
    row = Contract(protocol_id=protocol_id, address=address, chain=chain, contract_name="C")
    session.add(row)
    session.flush()
    return row


def _readings(
    session,
    contract: Contract,
    *,
    observed_address: str,
    rows: list[tuple[str, object]],
    status: str = ASSET_SET_STATUS_RETURNED_ASSETS,
    source: str = ASSET_SET_SOURCE_ETHERSCAN_PAGES,
    decimals: int = 18,
    raw_balance: str = "1000",
) -> None:
    """One fetch and its whole row set.

    The rows of ONE fetch, because ``contract_balances_latest`` publishes a
    fetch's row set wholesale — a row written under an earlier fetch is not
    current, so a helper that made a fetch per row would model a sheet that
    never existed.
    """
    fetch = ContractBalanceFetch(
        contract_id=contract.id,
        chain_id=CHAIN,
        observed_address=observed_address,
        writer="test",
        native_status=NATIVE_STATUS_PROVEN_NONZERO,
        asset_set_status=status,
        asset_set_source=source,
        asset_set_basis="test",
        swept_through_block=HEAD if source == ASSET_SET_SOURCE_CHAIN_LOG_SWEEP else None,
        swept_from_block=CREATION if source == ASSET_SET_SOURCE_CHAIN_LOG_SWEEP else None,
    )
    session.add(fetch)
    session.flush()
    for token, usd_value in rows:
        session.add(
            ContractBalance(
                contract_id=contract.id,
                token_address=token,
                decimals=decimals,
                raw_balance=raw_balance,
                usd_value=usd_value,
                observed_address=observed_address,
                fetch_id=fetch.id,
                source=source,
            )
        )
    session.flush()


def test_population_groups_by_the_account_the_reading_was_observed_at(db_session):
    """A proxy and its implementation read at one account are ONE holder.

    Keying on ``contracts.address`` would scan an address that holds none of
    these rows, and the account that does hold them would carry no evidence at
    all.
    """
    proto = _protocol(db_session, "grouping")
    proxy = _contract(db_session, proto.id, _addr("9a"))
    impl = _contract(db_session, proto.id, _addr("9b"))
    account = _addr("9a")
    _readings(db_session, proxy, observed_address=account, rows=[(TOKEN, None)])
    _readings(db_session, impl, observed_address=account, rows=[(OTHER_TOKEN, None)])

    requests = disposition_requests(db_session, protocol_id=proto.id)

    assert len(requests) == 1
    assert requests[0].holder_address == account
    assert set(requests[0].tokens) == {TOKEN, OTHER_TOKEN}


def test_population_is_uniform_over_unpriced_readings_on_priced_sheets(db_session):
    proto = _protocol(db_session, "uniform")
    holder = _contract(db_session, proto.id, _addr("aa"))
    _readings(
        db_session,
        holder,
        observed_address=holder.address,
        rows=[(TOKEN, 575_000_000), (OTHER_TOKEN, None), (_addr("70ce6"), 0)],
    )

    requests = disposition_requests(db_session, protocol_id=proto.id)

    assert len(requests) == 1
    # The priced reading is out; the NULL one and the zero-over-a-real-balance
    # one are both in — a $0 figure beside a non-zero quantity is an absent
    # price, not a holding worth nothing.
    assert set(requests[0].tokens) == {OTHER_TOKEN, _addr("70ce6")}


def test_population_refuses_a_holder_whose_asset_list_is_a_prefix(db_session):
    proto = _protocol(db_session, "capped")
    holder = _contract(db_session, proto.id, _addr("bb"))
    _readings(
        db_session,
        holder,
        observed_address=holder.address,
        rows=[(TOKEN, None)],
        status=ASSET_SET_STATUS_AT_PAGE_CAP,
    )

    assert disposition_requests(db_session, protocol_id=proto.id) == []


def test_population_marks_the_swept_zero_decimal_holdings_as_typed(db_session):
    proto = _protocol(db_session, "typed")
    holder = _contract(db_session, proto.id, _addr("cc"))
    _readings(
        db_session,
        holder,
        observed_address=holder.address,
        rows=[(TOKEN, None)],
        decimals=0,
        source=ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
    )

    requests = disposition_requests(db_session, protocol_id=proto.id)

    assert requests[0].typed_tokens == (TOKEN,)


def test_population_leaves_out_a_reading_whose_account_was_never_recorded(db_session):
    """A legacy row's account cannot be recovered, so it is not guessed."""
    proto = _protocol(db_session, "legacy")
    holder = _contract(db_session, proto.id, _addr("dd"))
    _readings(db_session, holder, observed_address=holder.address, rows=[(TOKEN, None)])
    db_session.query(ContractBalance).filter(ContractBalance.token_address == TOKEN).update(
        {ContractBalance.observed_address: None}
    )
    db_session.flush()

    assert disposition_requests(db_session, protocol_id=proto.id) == []


def test_population_folds_in_this_cycles_discoveries(db_session):
    proto = _protocol(db_session, "discovered")
    holder = _contract(db_session, proto.id, _addr("ee"))
    _readings(db_session, holder, observed_address=holder.address, rows=[(TOKEN, None)])
    fresh = DispositionRequest(
        contract_id=holder.id,
        chain_id=CHAIN,
        holder_address=holder.address,
        tokens=(OTHER_TOKEN,),
    )

    requests = disposition_requests(db_session, protocol_id=proto.id, discovered=[fresh])

    assert len(requests) == 1
    assert set(requests[0].tokens) == {TOKEN, OTHER_TOKEN}


# --- ERC-1155 --------------------------------------------------------------


def test_a_typed_token_is_also_asked_for_at_the_1155_recipient_slot(db_session, wire):
    """ERC-1155 indexes ``(operator, from, to)``, so its recipient is topic 3.

    Inert on today's population, which carries no typed receipt — implemented so
    a future one is measured rather than quietly unmeasured. The delivery is
    carried as unreadable: the fan-out meter is calibrated on same-token 3-topic
    ``Transfer`` logs and is not defined over an 1155 batch, so metering one
    here would publish a verdict under a threshold that was never calibrated
    for it.
    """
    single = {
        "address": TOKEN,
        "topics": [
            TRANSFER_SINGLE_TOPIC0,
            _pad(_addr("09e4a704")),
            _pad(_addr("5ende4")),
            _pad(HOLDER),
        ],
        "data": "0x" + f"{7:064x}" + f"{1:064x}",
        "transactionHash": _tx(5),
        "blockHash": _tx(905),
        "logIndex": "0x1",
        "blockNumber": hex(950_000),
        "transactionIndex": "0x0",
    }
    wire.logs = [single]

    cost = scan_delivery_shape(db_session, [_request(typed=(TOKEN,))], rpc_url_for=_rpc_url_for)

    # Two windows: the ERC-20/721 pass and the ERC-1155 pass.
    assert cost.get_logs == 2
    assert wire.get_logs_calls[1]["topics"][3] == [_pad(HOLDER)]
    assert wire.get_logs_calls[1]["topics"][0] == [TRANSFER_SINGLE_TOPIC0, TRANSFER_BATCH_TOPIC0]

    row = _facts(db_session)[(HOLDER, TOKEN)]
    assert row.delivery_shape == DELIVERY_SHAPE_NOT_DETERMINED
    assert row.delivery_count == 1
    assert row.unreadable_deliveries == 1
    assert wire.receipt_calls == []


def test_a_pair_with_too_many_deliveries_is_abandoned_before_any_receipt(db_session, wire):
    """A cost control that fails closed, and correlates with the token being real.

    Mass distributions arrive in one or two transactions; an accumulated
    position arrives in as many as it was accumulated over. Metering a pair with
    hundreds of deliveries costs a receipt each and buys nothing — the first
    live one-shot spent 4,663 receipts that way and never reached two of three
    chains. Over the cap the pair is recorded with every delivery unmeasured,
    which is what happened, and ``not_determined`` is what that earns.
    """
    over = delivery_shape.DISPOSITION_MAX_DELIVERIES_PER_PAIR + 1
    wire.logs = [_log(token=TOKEN, holder=HOLDER, tx=n, block=900_000 + n, log_index=n) for n in range(1, over + 1)]
    # Every one of them would have metered as an unmistakable distribution, so
    # the refusal cannot be read as the fan-out rule firing.
    wire.receipts = {_tx(n): _receipt(token=TOKEN, same_token_transfers=1400) for n in range(1, over + 1)}

    scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)

    row = _facts(db_session)[(HOLDER, TOKEN)]
    assert row.delivery_shape == DELIVERY_SHAPE_NOT_DETERMINED
    assert row.delivery_count == over
    assert row.unreadable_deliveries == over
    # Not one receipt was spent, and the pair is on record so the next cycle
    # does not re-derive it.
    assert wire.receipt_calls == []


def test_a_pair_at_the_cap_is_still_metered(db_session, wire):
    """The cap is a ceiling, not a fence one short of it."""
    at = delivery_shape.DISPOSITION_MAX_DELIVERIES_PER_PAIR
    wire.logs = [_log(token=TOKEN, holder=HOLDER, tx=n, block=900_000 + n, log_index=n) for n in range(1, at + 1)]
    wire.receipts = {_tx(n): _receipt(token=TOKEN, same_token_transfers=1400) for n in range(1, at + 1)}

    scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)

    row = _facts(db_session)[(HOLDER, TOKEN)]
    assert row.delivery_shape == DELIVERY_SHAPE_FAN_OUT_ALL
    assert row.unreadable_deliveries == 0
    assert len(wire.receipt_calls) == at
