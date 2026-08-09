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

from db.models import (
    Contract,
    ContractBalance,
    ContractBalanceFetch,
    Protocol,
    TokenDeliveryEvidence,
    TokenProtocolReference,
)
from services.monitoring import delivery_shape
from services.monitoring.asset_sweep import TRANSFER_BATCH_TOPIC0, TRANSFER_SINGLE_TOPIC0, TRANSFER_TOPIC0
from services.monitoring.delivery_evidence import DELIVERY_ENTRIES_RETAINED, load_delivery_evidence
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
    TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE,
    TOKEN_REFERENCE_IN_UNIVERSE,
    TOKEN_REFERENCE_NOT_DETERMINED,
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


# --- the basis names the row's own extent -----------------------------------


def test_the_basis_names_the_union_extent_and_never_the_passs_window(db_session, wire):
    """A stored claim and the extent it names cannot disagree.

    The steady-state pass covers a few hundred blocks; the claim covers
    millions. A basis quoting the pass would narrate a scope inside which the
    deciding delivery of the stored positive does not even lie — the
    all-quantifier's own scope, wrong on the row that publishes it. The basis is
    composed from ``scanned_from_block`` and ``measured_through_block`` at every
    write for exactly that reason.
    """
    wire.logs = [_log(token=TOKEN, holder=HOLDER, tx=1, block=910_000, log_index=1)]
    wire.receipts = {_tx(1): _receipt(token=TOKEN, same_token_transfers=700)}
    scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)
    db_session.flush()
    assert f"blocks {CREATION}..{HEAD}" in _facts(db_session)[(HOLDER, TOKEN)].basis

    # A second pass reads a 200-block window at the far end of the chain. Its
    # window is not the claim; the union is.
    wire.head = HEAD + 200
    scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)
    db_session.flush()

    row = _facts(db_session)[(HOLDER, TOKEN)]
    assert int(wire.get_logs_calls[-1]["fromBlock"], 16) == HEAD + 1
    assert f"blocks {CREATION}..{HEAD + 200}" in row.basis
    assert f"blocks {HEAD + 1}.." not in row.basis
    assert row.scanned_from_block == CREATION
    assert row.measured_through_block == HEAD + 200


def test_a_cycle_that_finds_nothing_still_repairs_the_stored_basis(db_session, wire):
    """The repair path, and it costs no chain request.

    A row whose sentence was authored under an older rule is rewritten by a
    normal cycle rather than by hand: the writer re-derives the basis from the
    row's own extent columns even when the pass adds no delivery and moves no
    cursor.
    """
    wire.logs = [_log(token=TOKEN, holder=HOLDER, tx=1, block=910_000, log_index=1)]
    wire.receipts = {_tx(1): _receipt(token=TOKEN, same_token_transfers=700)}
    scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)
    db_session.flush()

    row = _facts(db_session)[(HOLDER, TOKEN)]
    row.basis = "delivery shape over blocks 999999..1000000 on chain 1; a window, not a claim"
    db_session.flush()
    measured_at = row.measured_at

    second = scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)
    db_session.flush()

    repaired = _facts(db_session)[(HOLDER, TOKEN)]
    assert f"blocks {CREATION}..{HEAD}" in repaired.basis
    assert second.get_logs == 0 and second.receipts == 0
    # Re-deriving a sentence is not a new observation, so the row is not re-dated.
    assert repaired.measured_at == measured_at


def test_the_basis_carries_no_per_pass_cost_note(db_session, wire):
    """A cost is a fact about a pass; the basis is a fact about a claim.

    Accreting one into the other made the string grow per cycle and describe a
    scan that is not the one the claim rests on. Cost is logged instead.
    """
    wire.logs = [_log(token=TOKEN, holder=HOLDER, tx=1, block=910_000, log_index=1)]
    wire.receipts = {_tx(1): _receipt(token=TOKEN, same_token_transfers=700)}
    scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)
    db_session.flush()

    basis = _facts(db_session)[(HOLDER, TOKEN)].basis
    assert "getLogs" not in basis
    assert "scan cost" not in basis
    assert "K=25" in basis
    # The meter is named for what it counts.
    assert "LOGS" in basis


# --- the stored blob is bounded ---------------------------------------------


def test_an_abandoned_pair_records_a_compact_marker_not_every_delivery(db_session, wire):
    """A pair too heavy to meter is a COUNT plus a sample, never a blob.

    One entry per delivery put 518,723 of them and 40 MB of JSONB into a single
    optimism row on the reference corpus — none of it metered, so none of it
    said anything the count and the marker do not. The row must still carry how
    many deliveries were seen and that zero were metered, which is what holds
    the verdict at ``not_determined``.
    """
    many = 200
    wire.logs = [_log(token=TOKEN, holder=HOLDER, tx=n, block=900_000 + n, log_index=n) for n in range(1, many + 1)]

    scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)
    db_session.flush()

    row = _facts(db_session)[(HOLDER, TOKEN)]
    assert row.delivery_shape == DELIVERY_SHAPE_NOT_DETERMINED
    assert row.delivery_count == many
    assert row.unreadable_deliveries == many
    assert len(row.deliveries) == DELIVERY_ENTRIES_RETAINED
    assert all(entry["fan_out"] is None for entry in row.deliveries)
    assert all(entry["fan_out_basis"] == DELIVERY_FAN_OUT_BASIS_UNREADABLE for entry in row.deliveries)
    assert wire.receipt_calls == []


def test_a_fat_stored_row_is_shrunk_by_the_next_ordinary_cycle(db_session, wire):
    """The migration path for rows an unbounded writer left behind.

    Through the producer, on the cycle's own budget: the writer rewrites a
    stored list that predates the retention bound, and the scalars — which are
    the record — are carried, never recounted from the truncated list.
    """
    wire.logs = [_log(token=TOKEN, holder=HOLDER, tx=1, block=910_000, log_index=1)]
    wire.receipts = {_tx(1): _receipt(token=TOKEN, same_token_transfers=700)}
    scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)
    db_session.flush()

    fat = _facts(db_session)[(HOLDER, TOKEN)]
    fat.deliveries = [
        {"tx": _tx(n), "block": 905_000 + n, "log_index": n, "fan_out": None, "fan_out_basis": "receipt_unreadable"}
        for n in range(1, 5_001)
    ]
    fat.delivery_count = 5_000
    fat.unreadable_deliveries = 5_000
    fat.min_fan_out = None
    fat.delivery_shape = DELIVERY_SHAPE_NOT_DETERMINED
    db_session.flush()

    wire.head = HEAD + 200
    scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)
    db_session.flush()

    row = _facts(db_session)[(HOLDER, TOKEN)]
    assert len(row.deliveries) == DELIVERY_ENTRIES_RETAINED
    # The counts are the record and they are carried, not recounted.
    assert row.delivery_count == 5_000
    assert row.unreadable_deliveries == 5_000
    assert row.delivery_shape == DELIVERY_SHAPE_NOT_DETERMINED


def test_the_reader_never_selects_the_delivery_blob(db_session, wire):
    """``DeliveryFact`` carries no delivery list, so the API path must not read one.

    Deserialising the JSONB for rows nothing reads it from measured 0.86 s on
    the reference corpus, all of it spent on a column the caller never sees.
    """
    from sqlalchemy import event

    wire.logs = [_log(token=TOKEN, holder=HOLDER, tx=1, block=910_000, log_index=1)]
    wire.receipts = {_tx(1): _receipt(token=TOKEN, same_token_transfers=700)}
    scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)
    db_session.commit()

    statements: list[str] = []

    def _record(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    engine = db_session.get_bind()
    event.listen(engine, "before_cursor_execute", _record)
    try:
        facts = load_delivery_evidence(db_session.expire_all() or db_session, [(CHAIN, HOLDER)])
    finally:
        event.remove(engine, "before_cursor_execute", _record)

    assert facts[(CHAIN, HOLDER, TOKEN)].shape == DELIVERY_SHAPE_FAN_OUT_ALL
    selects = [s for s in statements if "token_delivery_evidence" in s]
    assert selects, "the loader issued no query against the evidence table"
    # The exact column reference: ``unreadable_deliveries`` is a scalar the
    # fact does carry, and a bare substring test would match it.
    assert all("token_delivery_evidence.deliveries" not in s for s in selects)


# --- a window that cannot be proven whole -----------------------------------


def test_a_truncated_window_writes_no_evidence_for_the_pairs_it_covered(db_session, wire, monkeypatch):
    """The fail-closed abort, and it is total.

    A page that reaches the result cap is indistinguishable from one the upstream
    cut short, so the fetcher bisects and — at the floor — refuses. Every pair
    that window covered is abandoned: no row, not a shorter delivery set, not a
    partial all-quantifier. The logs that DID come back cannot be given a
    completeness they lack, and the delivery a truncated page dropped is exactly
    the one that would have refuted the positive.
    """
    # Two deliveries in ONE block, at a cap of two: no bisect can separate them,
    # so every window containing them returns a page at the cap and the scan
    # reaches the bisect floor still unable to prove the window whole.
    monkeypatch.setattr(delivery_shape, "DISPOSITION_RESULT_CAP", 2)
    wire.logs = [
        _log(token=TOKEN, holder=HOLDER, tx=1, block=950_000, log_index=1),
        _log(token=TOKEN, holder=HOLDER, tx=2, block=950_000, log_index=2),
    ]
    wire.receipts = {_tx(n): _receipt(token=TOKEN, same_token_transfers=1) for n in (1, 2)}

    scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)
    db_session.flush()

    assert _facts(db_session) == {}
    assert wire.receipt_calls == []


def test_a_truncated_window_never_advances_an_existing_pairs_cursor(db_session, wire, monkeypatch):
    """An abort leaves the earlier claim exactly as it was earned.

    Advancing the cursor over a window nobody proved whole would widen a
    published extent by blocks that were never read.
    """
    wire.logs = [_log(token=TOKEN, holder=HOLDER, tx=1, block=910_000, log_index=1)]
    wire.receipts = {_tx(1): _receipt(token=TOKEN, same_token_transfers=700)}
    scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)
    db_session.flush()
    before = _facts(db_session)[(HOLDER, TOKEN)]
    assert before.delivery_shape == DELIVERY_SHAPE_FAN_OUT_ALL

    monkeypatch.setattr(delivery_shape, "DISPOSITION_RESULT_CAP", 2)
    wire.head = HEAD + 100_000
    wire.logs += [
        _log(token=TOKEN, holder=HOLDER, tx=3, block=HEAD + 50_000, log_index=1),
        _log(token=TOKEN, holder=HOLDER, tx=4, block=HEAD + 50_000, log_index=2),
    ]
    wire.receipts[_tx(3)] = _receipt(token=TOKEN, same_token_transfers=1)
    wire.receipts[_tx(4)] = _receipt(token=TOKEN, same_token_transfers=1)

    scan_delivery_shape(db_session, [_request()], rpc_url_for=_rpc_url_for)
    db_session.flush()

    row = _facts(db_session)[(HOLDER, TOKEN)]
    assert row.measured_through_block == HEAD
    assert row.delivery_count == 1
    assert row.delivery_shape == DELIVERY_SHAPE_FAN_OUT_ALL
    assert f"blocks {CREATION}..{HEAD}" in row.basis


# --- the protocol-reference verdict -----------------------------------------


def _references(session) -> dict[tuple[int, str], TokenProtocolReference]:
    return {(row.chain_id, row.token_address): row for row in session.query(TokenProtocolReference).all()}


class _Universe:
    """A stand-in for ``distill.ProtocolUniverse`` — the three fields read here."""

    def __init__(self, addresses: set[str]) -> None:
        self.addresses = frozenset(addresses)
        self.sources = {"test": len(addresses)}
        self.basis = "test universe"


def test_an_unbuildable_universe_condemns_nothing(db_session, monkeypatch):
    """``None`` from the universe loader is fail-closed, and it is honoured.

    A universe that could not be assembled whole is a SHORT one, and the
    predicate it feeds condemns what is ABSENT — so a short universe condemns
    MORE. Every token lands ``not_determined``; nothing may be pulled from a
    sheet on the strength of an absence from a universe nobody built.
    """
    import services.scoring.distill as distill

    monkeypatch.setattr(distill, "load_protocol_universe", lambda session, protocol_id: None)
    proto = _protocol(db_session, "unbuildable")

    written = delivery_shape.record_protocol_reference(
        db_session,
        protocol_id=proto.id,
        requests=[_request(tokens=(TOKEN, OTHER_TOKEN))],
    )
    db_session.flush()

    assert written == 2
    rows = _references(db_session)
    assert {row.reference_shape for row in rows.values()} == {TOKEN_REFERENCE_NOT_DETERMINED}
    assert all(row.universe_addresses == 0 for row in rows.values())
    assert not [row for row in rows.values() if row.reference_shape == TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE]
    assert all("could not be assembled whole" in row.basis for row in rows.values())


def test_a_universe_loader_that_raises_reads_the_same_as_one_that_refuses(db_session, monkeypatch):
    """An assembly that raised is an assembly that did not happen."""
    import services.scoring.distill as distill

    def _boom(session, protocol_id):
        raise RuntimeError("object storage unreachable")

    monkeypatch.setattr(distill, "load_protocol_universe", _boom)
    proto = _protocol(db_session, "raising")

    delivery_shape.record_protocol_reference(db_session, protocol_id=proto.id, requests=[_request()])
    db_session.flush()

    assert _references(db_session)[(CHAIN, TOKEN)].reference_shape == TOKEN_REFERENCE_NOT_DETERMINED


def test_a_named_token_is_in_the_universe_and_an_unnamed_one_is_absent(db_session, monkeypatch):
    import services.scoring.distill as distill

    monkeypatch.setattr(distill, "load_protocol_universe", lambda session, protocol_id: _Universe({TOKEN}))
    proto = _protocol(db_session, "named")

    delivery_shape.record_protocol_reference(
        db_session, protocol_id=proto.id, requests=[_request(tokens=(TOKEN, OTHER_TOKEN))]
    )
    db_session.flush()

    rows = _references(db_session)
    assert rows[(CHAIN, TOKEN)].reference_shape == TOKEN_REFERENCE_IN_UNIVERSE
    assert rows[(CHAIN, OTHER_TOKEN)].reference_shape == TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE
    assert rows[(CHAIN, OTHER_TOKEN)].universe_addresses == 1


def test_an_empty_universe_condemns_nothing_and_does_not_poison_the_write(db_session, monkeypatch):
    """A universe that named NO address is refused in the WRITER.

    An empty set condemns everything absent from it. ``ck_tpr_absence_needs_a_universe``
    says so at the table too, but reaching it is not a defence: this pass runs
    inside a producer that swallows what it raises, so the constraint violation
    would abort the surrounding transaction and take the BALANCE WRITE down with
    it. The verdict is ``not_determined`` and the session is still usable after.
    """
    import services.scoring.distill as distill

    monkeypatch.setattr(distill, "load_protocol_universe", lambda session, protocol_id: _Universe(set()))
    proto = _protocol(db_session, "empty universe")

    written = delivery_shape.record_protocol_reference(
        db_session, protocol_id=proto.id, requests=[_request(tokens=(TOKEN, OTHER_TOKEN))]
    )
    db_session.flush()

    assert written == 2
    rows = _references(db_session)
    assert {row.reference_shape for row in rows.values()} == {TOKEN_REFERENCE_NOT_DETERMINED}
    assert all(row.universe_addresses == 0 for row in rows.values())
    assert all("named NO address" in row.basis for row in rows.values())

    # The transaction is alive: a poisoned one would refuse this.
    _contract(db_session, proto.id, _addr("live"))
    db_session.flush()


def test_an_empty_universe_withdraws_a_standing_absence(db_session, monkeypatch):
    """It writes ``not_determined`` ROWS rather than nothing at all.

    Writing nothing would leave a previous cycle's ``absent_from_universe``
    standing against a universe this cycle could not measure — a condemnation
    outliving the evidence for it.
    """
    import services.scoring.distill as distill

    proto = _protocol(db_session, "withdrawn by an empty universe")
    monkeypatch.setattr(distill, "load_protocol_universe", lambda session, protocol_id: _Universe({OTHER_TOKEN}))
    delivery_shape.record_protocol_reference(db_session, protocol_id=proto.id, requests=[_request()])
    db_session.flush()
    assert _references(db_session)[(CHAIN, TOKEN)].reference_shape == TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE

    delivery_shape.clear_protocol_universe_memo()
    monkeypatch.setattr(distill, "load_protocol_universe", lambda session, protocol_id: _Universe(set()))
    delivery_shape.record_protocol_reference(db_session, protocol_id=proto.id, requests=[_request()])
    db_session.flush()

    assert _references(db_session)[(CHAIN, TOKEN)].reference_shape == TOKEN_REFERENCE_NOT_DETERMINED


def test_discovery_growth_withdraws_an_absence(db_session, monkeypatch):
    """The anti-monotone direction, and it is why this table is refreshed.

    ``absent_from_universe`` is a verdict against the universe of the day. A
    later cycle whose discovery names the address must be able to take it back —
    the opposite discipline from the delivery-evidence plane, whose rows accrete.
    """
    import services.scoring.distill as distill

    proto = _protocol(db_session, "growth")
    monkeypatch.setattr(distill, "load_protocol_universe", lambda session, protocol_id: _Universe({OTHER_TOKEN}))
    delivery_shape.record_protocol_reference(db_session, protocol_id=proto.id, requests=[_request()])
    db_session.flush()
    assert _references(db_session)[(CHAIN, TOKEN)].reference_shape == TOKEN_REFERENCE_ABSENT_FROM_UNIVERSE

    # The universe memo is what a LATER CYCLE crosses: this test runs both
    # cycles in one process against an unchanged discovery extent, which is
    # exactly the case the memo is entitled to serve from. Cleared so the
    # refresh under test is the table's and not the memo's.
    delivery_shape.clear_protocol_universe_memo()
    monkeypatch.setattr(distill, "load_protocol_universe", lambda session, protocol_id: _Universe({OTHER_TOKEN, TOKEN}))
    delivery_shape.record_protocol_reference(db_session, protocol_id=proto.id, requests=[_request()])
    db_session.flush()

    row = _references(db_session)[(CHAIN, TOKEN)]
    assert row.reference_shape == TOKEN_REFERENCE_IN_UNIVERSE
    assert row.universe_addresses == 2
    assert db_session.query(TokenProtocolReference).count() == 1


# --- the per-process universe memo -------------------------------------------


def _counting_loader(monkeypatch, *universes):
    """Install a loader that answers each call in turn and counts assemblies.

    Returns the call log, so a test asserts on how many 26.5-second assemblies
    the phase actually paid for rather than on how many it was asked for.
    """
    import services.scoring.distill as distill

    calls: list[int] = []

    def _load(session, protocol_id):
        calls.append(int(protocol_id))
        answer = universes[min(len(calls) - 1, len(universes) - 1)]
        return answer

    monkeypatch.setattr(distill, "load_protocol_universe", _load)
    return calls


def test_the_universe_is_assembled_once_per_process_over_one_discovery_extent(db_session, monkeypatch):
    """The 26.5-second assembly is paid once, not once per contract.

    The resolution worker runs this phase per CONTRACT, so on a protocol with
    ~91 contracts carrying unpriced tokens the unmemoized path assembled the
    same universe ~91 times.
    """
    proto = _protocol(db_session, "memo")
    _contract(db_session, proto.id, _addr("memo-1"))
    calls = _counting_loader(monkeypatch, _Universe({TOKEN}))

    for _ in range(5):
        delivery_shape.record_protocol_reference(db_session, protocol_id=proto.id, requests=[_request()])
    db_session.flush()

    assert len(calls) == 1
    row = _references(db_session)[(CHAIN, TOKEN)]
    assert row.reference_shape == TOKEN_REFERENCE_IN_UNIVERSE
    assert "reused" in row.basis


def test_a_widened_discovery_extent_retires_the_memo(db_session, monkeypatch):
    """A memo may never serve a universe built from a NARROWER discovery.

    The extent key is the jobs and contracts the universe would be assembled
    over. One more contract is one more body of source literals and one more
    contract-scoped row set, so the entry is retired and the next call rebuilds.
    """
    proto = _protocol(db_session, "widening")
    _contract(db_session, proto.id, _addr("wide-1"))
    calls = _counting_loader(monkeypatch, _Universe({TOKEN}))

    delivery_shape.record_protocol_reference(db_session, protocol_id=proto.id, requests=[_request()])
    delivery_shape.record_protocol_reference(db_session, protocol_id=proto.id, requests=[_request()])
    assert len(calls) == 1

    _contract(db_session, proto.id, _addr("wide-2"))
    delivery_shape.record_protocol_reference(db_session, protocol_id=proto.id, requests=[_request()])
    assert len(calls) == 2


def test_a_reused_universe_can_only_grow(db_session, monkeypatch):
    """WHICH WAY THE MEMO ERRS: larger.

    The predicate this universe feeds condemns what is ABSENT, so a short
    universe condemns MORE — a stale-short entry is the one dangerous direction.
    What is carried forward is the UNION of every assembly this process made for
    the protocol, so a rebuild that answers with fewer addresses cannot take one
    back: the token the first assembly named stays named.
    """
    proto = _protocol(db_session, "union")
    _contract(db_session, proto.id, _addr("union-1"))
    calls = _counting_loader(monkeypatch, _Universe({TOKEN}), _Universe({OTHER_TOKEN}))

    delivery_shape.record_protocol_reference(db_session, protocol_id=proto.id, requests=[_request()])
    db_session.flush()
    assert _references(db_session)[(CHAIN, TOKEN)].reference_shape == TOKEN_REFERENCE_IN_UNIVERSE

    _contract(db_session, proto.id, _addr("union-2"))
    delivery_shape.record_protocol_reference(
        db_session, protocol_id=proto.id, requests=[_request(tokens=(TOKEN, OTHER_TOKEN))]
    )
    db_session.flush()

    assert len(calls) == 2
    rows = _references(db_session)
    assert rows[(CHAIN, TOKEN)].reference_shape == TOKEN_REFERENCE_IN_UNIVERSE
    assert rows[(CHAIN, OTHER_TOKEN)].reference_shape == TOKEN_REFERENCE_IN_UNIVERSE
    assert rows[(CHAIN, TOKEN)].universe_addresses == 2
    assert "UNION" in rows[(CHAIN, TOKEN)].basis


def test_an_unbuildable_universe_is_never_memoized(db_session, monkeypatch):
    """``None`` is a refusal, not an answer, so it is not carried.

    Caching it would spend the whole reuse window condemning nothing — safe, but
    it would also hide a storage fault that has since cleared behind an answer
    nobody re-asked for. Re-asking costs one assembly and can only narrow the
    refusal.
    """
    proto = _protocol(db_session, "unbuildable memo")
    _contract(db_session, proto.id, _addr("unbuildable-1"))
    calls = _counting_loader(monkeypatch, None, None, _Universe({TOKEN}))

    delivery_shape.record_protocol_reference(db_session, protocol_id=proto.id, requests=[_request()])
    delivery_shape.record_protocol_reference(db_session, protocol_id=proto.id, requests=[_request()])
    db_session.flush()
    assert len(calls) == 2
    assert _references(db_session)[(CHAIN, TOKEN)].reference_shape == TOKEN_REFERENCE_NOT_DETERMINED

    delivery_shape.record_protocol_reference(db_session, protocol_id=proto.id, requests=[_request()])
    db_session.flush()
    assert len(calls) == 3
    assert _references(db_session)[(CHAIN, TOKEN)].reference_shape == TOKEN_REFERENCE_IN_UNIVERSE


def test_the_reuse_window_is_bounded_in_time(db_session, monkeypatch):
    """The extent key cannot see every row the assembly reads.

    Control-graph, principal, effect-verdict, dApp-interaction, monitored-contract
    and restaking rows are read per contract or per protocol, so a resolution job
    can add addresses to an already-keyed contract without widening the extent.
    The TTL is the bound on that residual, and it is a real bound rather than a
    comment: past it the entry is retired whatever the key says.
    """
    proto = _protocol(db_session, "ttl")
    _contract(db_session, proto.id, _addr("ttl-1"))
    calls = _counting_loader(monkeypatch, _Universe({TOKEN}))

    delivery_shape.record_protocol_reference(db_session, protocol_id=proto.id, requests=[_request()])
    delivery_shape.record_protocol_reference(db_session, protocol_id=proto.id, requests=[_request()])
    assert len(calls) == 1

    monkeypatch.setattr(delivery_shape, "_UNIVERSE_MEMO_TTL_SECONDS", 0.0)
    delivery_shape.record_protocol_reference(db_session, protocol_id=proto.id, requests=[_request()])
    assert len(calls) == 2


def test_the_memo_is_per_protocol_and_the_clear_hook_empties_it(db_session, monkeypatch):
    """Two protocols never share an answer, and the hook drops every one."""
    first = _protocol(db_session, "memo A")
    second = _protocol(db_session, "memo B")
    _contract(db_session, first.id, _addr("memo-a"))
    _contract(db_session, second.id, _addr("memo-b"))
    calls = _counting_loader(monkeypatch, _Universe({TOKEN}))

    delivery_shape.record_protocol_reference(db_session, protocol_id=first.id, requests=[_request()])
    delivery_shape.record_protocol_reference(db_session, protocol_id=second.id, requests=[_request()])
    assert calls == [first.id, second.id]

    delivery_shape.record_protocol_reference(db_session, protocol_id=first.id, requests=[_request()])
    assert len(calls) == 2

    delivery_shape.clear_protocol_universe_memo()
    delivery_shape.record_protocol_reference(db_session, protocol_id=first.id, requests=[_request()])
    assert len(calls) == 3
