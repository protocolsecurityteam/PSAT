"""The Safe-execution decode corpus: whole transactions through the real enricher, asserted on the published
enrichment block and the salience level + basis.

Every alert the decode rules can mint appears below, and
:func:`test_the_corpus_covers_every_alert_the_decode_rules_can_mint` states that list as an assertion.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest
from eth_abi.abi import encode as eth_abi_encode

from db.models import Contract, EffectiveFunction, MonitoredContract, MonitoredEvent, Protocol
from services.monitoring import enrichment as enr
from services.monitoring import salience as sal

ZERO = "0x" + "00" * 20
SAFE_EXEC_SELECTOR = "0x6a761202"
MULTISEND_1_3_0 = "0xa238cbeb142c10ef7ad8442c6d1f9e89e07e7761"
MULTISEND_CALL_ONLY_1_4_1 = "0x9641d764fc13c8b624c04430c7356c1c7c8102e2"


def ADDR(n: int) -> str:
    return "0x" + hex(n)[2:].zfill(40)


SAFE = ADDR(0x5AFE)
TARGET = ADDR(0x7A46E7)
RELAYER = ADDR(0xDECAF)
UNKNOWN_LIB = ADDR(0xBADBAD)

SET_FEE = "0x69fe0e2d"  # setFee(uint256)
PAUSE = "0x8456cb59"  # pause()


def exec_transaction_input(
    *,
    to: str,
    value: int = 0,
    data: bytes = b"",
    operation: int = 0,
    gas_token: str = ZERO,
    refund_receiver: str = ZERO,
) -> str:
    args = eth_abi_encode(
        enr._EXEC_TRANSACTION_ARG_TYPES,
        [to, value, data, operation, 0, 0, 0, gas_token, refund_receiver, b"\x01" * 65],
    )
    return SAFE_EXEC_SELECTOR + args.hex()


def multisend_payload(calls: list[tuple[int, str, int, bytes]]) -> bytes:
    packed = b"".join(
        bytes([operation]) + bytes.fromhex(to[2:]) + value.to_bytes(32, "big") + len(data).to_bytes(32, "big") + data
        for operation, to, value, data in calls
    )
    return bytes.fromhex(enr.MULTISEND_SELECTOR[2:]) + eth_abi_encode(["bytes"], [packed])


@pytest.fixture()
def protocol(db_session):
    row = Protocol(name="decode-corpus", chains=["ethereum"])
    db_session.add(row)
    db_session.commit()
    return row


@pytest.fixture()
def make_mc(db_session, protocol):
    def make(*, address: str, contract_type: str = "safe", chain: str = "ethereum") -> MonitoredContract:
        contract = Contract(protocol_id=protocol.id, address=address, chain=chain)
        db_session.add(contract)
        db_session.flush()
        mc = MonitoredContract(
            id=uuid.uuid4(),
            address=address,
            chain=chain,
            protocol_id=protocol.id,
            contract_id=contract.id,
            contract_type=contract_type,
            monitoring_config={},
            last_known_state={},
            enrollment_block=1,
            is_active=True,
        )
        db_session.add(mc)
        db_session.commit()
        return mc

    return make


@pytest.fixture()
def safe(make_mc):
    return make_mc(address=SAFE)


@pytest.fixture()
def known_target(db_session, protocol):

    def make(address: str, selector: str, signature: str) -> Contract:
        contract = db_session.query(Contract).filter_by(address=address, chain="ethereum").one_or_none()
        if contract is None:
            contract = Contract(protocol_id=protocol.id, address=address, chain="ethereum")
            db_session.add(contract)
            db_session.flush()
        db_session.add(
            EffectiveFunction(
                contract_id=contract.id,
                function_name=signature.split("(")[0],
                selector=selector,
                abi_signature=signature,
            )
        )
        db_session.commit()
        return contract

    return make


def seed_event(db_session, mc, event_type: str, tx_hash: str, *, data: dict | None = None, log_index: int = 0):
    """Mint-time salience included, so assertions are about what enrichment changed."""
    payload = dict(data or {})
    level, basis = sal.assign_salience(db_session, event_type, payload, mc)
    payload["salience"] = level
    payload["salience_basis"] = basis
    event = MonitoredEvent(
        id=uuid.uuid4(),
        monitored_contract_id=mc.id,
        event_type=event_type,
        block_number=100,
        tx_hash=tx_hash,
        log_index=log_index,
        data=payload,
    )
    db_session.add(event)
    db_session.commit()
    return event


def run(
    db_session,
    events,
    txs: dict[str, dict] | None = None,
    *,
    calls_out: list | None = None,
    rpc_by_chain: dict[str, str] | None = None,
):

    def fake_batch(rpc_url, calls, headers=None, *, chain_id=None):
        if calls_out is not None:
            calls_out.append({"rpc_url": rpc_url, "calls": list(calls), "chain_id": chain_id})
        out = []
        for _method, params in calls:
            tx = (txs or {}).get(params[0])
            out.append((tx, "ok") if tx is not None else (None, "transport"))
        return out

    with patch("services.monitoring.enrichment.rpc_batch_request_classified", side_effect=fake_batch):
        enr.enrich_events(db_session, list(events), rpc_by_chain or {"ethereum": "https://rpc.invalid/eth"})
    db_session.commit()
    db_session.expire_all()
    return [db_session.get(MonitoredEvent, event.id).data for event in events]


def tx(*, to: str, input_hex: str, tx_hash: str) -> dict:
    return {"hash": tx_hash, "to": to, "from": ADDR(1), "input": input_hex, "value": "0x0"}


# ---------------------------------------------------------------------------
# the direct call
# ---------------------------------------------------------------------------


def test_a_direct_exec_transaction_publishes_the_witnessed_call(db_session, safe, known_target):
    known_target(TARGET, SET_FEE, "setFee(uint256)")
    tx_hash = "0x" + "11" * 32
    event = seed_event(db_session, safe, "safe_tx_executed", tx_hash)

    (data,) = run(
        db_session,
        [event],
        {
            tx_hash: tx(
                to=SAFE,
                tx_hash=tx_hash,
                input_hex=exec_transaction_input(to=TARGET, value=7, data=bytes.fromhex(SET_FEE[2:]) + b"\x00" * 32),
            )
        },
    )

    block = data["safe_exec"]
    assert block["status"] == "decoded"
    assert block["to"] == TARGET
    assert block["value"] == "7"
    assert block["selector"] == SET_FEE
    assert block["data_length"] == 36
    assert block["operation"] == 0
    assert block["operation_label"] == "call"
    assert block["gas_token"] == ZERO
    assert block["refund_receiver"] == ZERO
    assert block[sal.SAFE_EXEC_KEY_MULTISEND_RECOGNIZED] is False
    # Signature resolution is display only — the level below is the ``operation == 0``
    # floor either way.
    assert block["target_function"] == {
        "selector": SET_FEE,
        "signature": "setFee(uint256)",
        "source": "effective_functions",
    }
    assert data["salience"] == sal.SALIENCE_NOTABLE
    assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_CALL]


# ---------------------------------------------------------------------------
# the top-level-call check
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "make_tx",
    [
        # Guessing the inner call from the outer input is the unwitnessed inference the overhaul removed.
        pytest.param(
            lambda h: tx(to=RELAYER, tx_hash=h, input_hex="0xdeadbeef" + "00" * 32),
            id="relayer_wrapped_execution",
        ),
        pytest.param(
            lambda h: tx(to=SAFE, tx_hash=h, input_hex="0x468721a7" + "00" * 32),
            id="right_target_wrong_selector",
        ),
        pytest.param(lambda h: {"hash": h, "to": None, "input": "0x6080"}, id="contract_creation"),
    ],
)
def test_a_call_that_is_not_this_safes_own_is_not_a_top_level_call(db_session, safe, make_tx):
    tx_hash = "0x" + "21" * 32
    event = seed_event(db_session, safe, "safe_tx_executed", tx_hash)

    (data,) = run(db_session, [event], {tx_hash: make_tx(tx_hash)})

    assert data["safe_exec"] == {"status": "not_top_level_call"}
    assert data["salience"] == sal.SALIENCE_ROUTINE
    assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_INDIRECT]


def test_undecodable_arguments_state_the_gap_rather_than_leaving_the_block_absent(db_session, safe):
    tx_hash = "0x" + "24" * 32
    event = seed_event(db_session, safe, "safe_tx_executed", tx_hash)

    (data,) = run(
        db_session, [event], {tx_hash: tx(to=SAFE, tx_hash=tx_hash, input_hex=SAFE_EXEC_SELECTOR + "00" * 32)}
    )

    assert data["safe_exec"] == {"status": enr.SAFE_EXEC_STATUS_ARGS_UNDECODABLE}
    assert data["salience"] == sal.SALIENCE_NOT_DETERMINED
    # A rule did examine this row, so the basis names the enrichment gap.
    assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_NOT_ENRICHED]


@pytest.mark.parametrize(
    "fixture",
    [{"hash": "x"}, {"hash": "x", "to": SAFE}, {"hash": "x", "input": "0x"}],
    ids=["neither-field", "no-input", "no-to-key"],
)
def test_a_transaction_object_missing_its_fields_mints_no_finding(db_session, safe, fixture):
    """``not_top_level_call`` demotes the row, so it may only come from fields the response carried."""
    tx_hash = "0x" + "26" * 32
    event = seed_event(db_session, safe, "safe_tx_executed", tx_hash)

    (data,) = run(db_session, [event], {tx_hash: dict(fixture, hash=tx_hash)})

    assert "safe_exec" not in data
    assert data["salience"] == sal.SALIENCE_NOT_DETERMINED
    assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_NOT_ENRICHED]


# ---------------------------------------------------------------------------
# delegatecall, the design-critical trap
# ---------------------------------------------------------------------------


def test_delegatecall_to_an_unrecognized_target_alerts(db_session, safe):
    """Not proven MultiSend, nor proven malicious, so the level goes up."""
    tx_hash = "0x" + "31" * 32
    event = seed_event(db_session, safe, "safe_tx_executed", tx_hash)

    (data,) = run(
        db_session,
        [event],
        {
            tx_hash: tx(
                to=SAFE,
                tx_hash=tx_hash,
                input_hex=exec_transaction_input(to=UNKNOWN_LIB, operation=1, data=bytes.fromhex(SET_FEE[2:])),
            )
        },
    )

    block = data["safe_exec"]
    assert block["operation"] == 1
    assert block["operation_label"] == "delegatecall"
    assert block[sal.SAFE_EXEC_KEY_MULTISEND_RECOGNIZED] is False
    assert "batch" not in block and "batch_status" not in block
    assert data["salience"] == sal.SALIENCE_ALERT
    assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_DELEGATECALL_UNRECOGNIZED]


@pytest.mark.parametrize("library", [MULTISEND_1_3_0, MULTISEND_CALL_ONLY_1_4_1])
def test_a_pinned_multisend_batch_is_expanded(db_session, safe, known_target, library):
    """The Safe UI batches by delegatecalling MultiSend, which a naive ``operation == 1`` rule would alert on."""
    known_target(TARGET, SET_FEE, "setFee(uint256)")
    tx_hash = "0x" + "32" * 32
    event = seed_event(db_session, safe, "safe_tx_executed", tx_hash)
    payload = multisend_payload(
        [
            (0, TARGET, 0, bytes.fromhex(SET_FEE[2:]) + b"\x00" * 32),
            (0, ADDR(0xFEE2), 5, bytes.fromhex(PAUSE[2:])),
        ]
    )

    (data,) = run(
        db_session,
        [event],
        {
            tx_hash: tx(
                to=SAFE, tx_hash=tx_hash, input_hex=exec_transaction_input(to=library, operation=1, data=payload)
            )
        },
    )

    block = data["safe_exec"]
    assert block[sal.SAFE_EXEC_KEY_MULTISEND_RECOGNIZED] is True
    assert "batch_status" not in block
    assert [call["to"] for call in block["batch"]] == [TARGET, ADDR(0xFEE2)]
    assert block["batch"][0]["signature"] == "setFee(uint256)"
    assert block["batch"][0]["signature_source"] == "effective_functions"
    assert block["batch"][0]["data_length"] == 36
    assert block["batch"][1]["value"] == "5"
    assert block["batch"][1]["signature"] is None
    assert block["batch"][1]["selector"] == PAUSE
    assert data["salience"] == sal.SALIENCE_NOTABLE
    assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_MULTISEND]


def _decode_batch(db_session, safe_mc, tx_hash: str, payload: bytes) -> dict:
    event = seed_event(db_session, safe_mc, "safe_tx_executed", tx_hash)
    return run(
        db_session,
        [event],
        {
            tx_hash: tx(
                to=safe_mc.address,
                tx_hash=tx_hash,
                input_hex=exec_transaction_input(to=MULTISEND_1_3_0, operation=1, data=payload),
            )
        },
    )[0]


def test_a_batch_nested_past_the_depth_cap_states_the_gap(db_session, safe):
    """The cap bounds an adversarial payload's cost; exceeding it is a stated gap."""
    payload = multisend_payload([(0, TARGET, 0, b"")])
    for _ in range(enr.MAX_MULTISEND_DEPTH):
        payload = multisend_payload([(1, MULTISEND_1_3_0, 0, payload)])

    data = _decode_batch(db_session, safe, "0x" + "39" * 32, payload)

    block = data["safe_exec"]
    assert block["batch_status"] == "undecodable"
    assert block["batch_status_reason"] == enr.BATCH_REASON_DEPTH_EXCEEDED
    assert "batch" not in block
    assert data["salience"] == sal.SALIENCE_NOT_DETERMINED
    assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_BATCH_UNDECODABLE]


def test_the_depth_cap_admits_exactly_max_depth_layers(db_session, safe):
    payload = multisend_payload([(0, TARGET, 0, b"")])
    for _ in range(enr.MAX_MULTISEND_DEPTH - 1):
        payload = multisend_payload([(1, MULTISEND_1_3_0, 0, payload)])

    data = _decode_batch(db_session, safe, "0x" + "3a" * 32, payload)

    assert "batch_status" not in data["safe_exec"]
    assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_MULTISEND]


def test_the_salience_rules_refuse_an_unexpanded_nested_batch(db_session, make_mc):
    """Defence in depth for a shape the decoder can no longer produce."""
    data = {
        "safe_exec": {
            "status": "decoded",
            "operation": 1,
            "to": MULTISEND_1_3_0,
            sal.SAFE_EXEC_KEY_MULTISEND_RECOGNIZED: True,
            "batch": [{"operation": 1, "to": MULTISEND_CALL_ONLY_1_4_1, sal.SAFE_EXEC_KEY_MULTISEND_RECOGNIZED: True}],
        }
    }
    level, basis = sal.assign_salience(db_session, "safe_tx_executed", data, make_mc(address=ADDR(0x5AF1)))
    assert level == sal.SALIENCE_NOT_DETERMINED
    assert basis == [sal.BASIS_SAFE_EXEC_MULTISEND, sal.BASIS_SAFE_EXEC_NOT_ENRICHED]


@pytest.mark.parametrize(
    "payload,why",
    [
        (
            bytes.fromhex(enr.MULTISEND_SELECTOR[2:]) + eth_abi_encode(["bytes"], [b"\x00" * 40]),
            "entry header overruns",
        ),
        (
            bytes.fromhex(enr.MULTISEND_SELECTOR[2:])
            + eth_abi_encode(
                ["bytes"],
                [
                    bytes([0])
                    + bytes.fromhex(TARGET[2:])
                    + (0).to_bytes(32, "big")
                    + (99).to_bytes(32, "big")
                    + b"\x01\x02"
                ],
            ),
            "declared length overruns",
        ),
        (bytes.fromhex(SET_FEE[2:]) + b"\x00" * 32, "not multiSend at all"),
        (b"", "no calldata"),
    ],
    ids=["header-overrun", "length-overrun", "wrong-selector", "empty"],
)
def test_a_malformed_batch_publishes_undecodable_and_no_partial_list(db_session, safe, payload, why):
    """A truncated batch would understate what the Safe did."""
    tx_hash = "0x" + "35" * 32
    event = seed_event(db_session, safe, "safe_tx_executed", tx_hash)

    (data,) = run(
        db_session,
        [event],
        {
            tx_hash: tx(
                to=SAFE,
                tx_hash=tx_hash,
                input_hex=exec_transaction_input(to=MULTISEND_1_3_0, operation=1, data=payload),
            )
        },
    )

    block = data["safe_exec"]
    assert block["batch_status"] == "undecodable", why
    assert "batch" not in block
    assert data["salience"] == sal.SALIENCE_NOT_DETERMINED
    assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_BATCH_UNDECODABLE]


def test_every_decoded_batch_entry_is_a_mapping(db_session, safe):
    calls, reason = enr._decode_multisend(multisend_payload([(0, TARGET, 1, b"\x01"), (1, UNKNOWN_LIB, 0, b"")]))
    assert calls is not None and reason is None
    assert all(isinstance(call, dict) for call in calls)
    truncated, reason = enr._decode_multisend(multisend_payload([(0, TARGET, 1, b"\x01")])[:-3])
    assert truncated is None
    assert reason == enr.BATCH_REASON_MALFORMED


def test_the_budget_is_spent_once_across_every_chain_in_the_pass(db_session, make_mc, monkeypatch):
    """The window transaction is per pass, not per chain."""
    monkeypatch.setenv(enr.ENRICH_TX_BUDGET_ENV, "1")
    on_ethereum = make_mc(address=ADDR(0x5A20))
    on_base = make_mc(address=ADDR(0x5A21), chain="base")
    hashes = ["0x" + "b8" * 32, "0x" + "b9" * 32]
    events = [
        seed_event(db_session, on_ethereum, "safe_tx_executed", hashes[0]),
        seed_event(db_session, on_base, "safe_tx_executed", hashes[1]),
    ]
    txs = {
        h: tx(to=mc.address, tx_hash=h, input_hex=exec_transaction_input(to=TARGET))
        for mc, h in zip((on_ethereum, on_base), hashes)
    }

    calls: list[dict] = []
    with patch(
        "services.monitoring.enrichment.chain_id_for", side_effect=lambda chain: 1 if chain == "ethereum" else 8453
    ):
        payloads = run(
            db_session,
            events,
            txs,
            calls_out=calls,
            rpc_by_chain={"ethereum": "https://eth.invalid", "base": "https://base.invalid"},
        )

    assert sum(len(call["calls"]) for call in calls) == 1
    statuses = {payload["safe_exec"]["status"] for payload in payloads}
    assert statuses == {"decoded", "over_budget"}


def test_a_skipped_chain_does_not_consume_the_budget(db_session, make_mc, monkeypatch):
    monkeypatch.setenv(enr.ENRICH_TX_BUDGET_ENV, "1")
    unresolvable = make_mc(address=ADDR(0x5A30), chain="nosuchchain")
    resolvable = make_mc(address=ADDR(0x5A31))
    hashes = ["0x" + "ba" * 32, "0x" + "bb" * 32]
    events = [
        seed_event(db_session, unresolvable, "safe_tx_executed", hashes[0]),
        seed_event(db_session, resolvable, "safe_tx_executed", hashes[1]),
    ]
    txs = {
        h: tx(to=mc.address, tx_hash=h, input_hex=exec_transaction_input(to=TARGET))
        for mc, h in zip((unresolvable, resolvable), hashes)
    }

    def only_ethereum(chain):
        if chain != "ethereum":
            raise ValueError(f"unknown chain {chain}")
        return 1

    with patch("services.monitoring.enrichment.chain_id_for", side_effect=only_ethereum):
        payloads = run(
            db_session,
            events,
            txs,
            rpc_by_chain={"ethereum": "https://eth.invalid", "nosuchchain": "https://nope.invalid"},
        )

    assert "safe_exec" not in payloads[0]
    assert payloads[1]["safe_exec"]["status"] == "decoded"


def test_two_executions_of_one_safe_in_one_tx_refuse_attribution(db_session, safe):
    """One tx holds one set of ``execTransaction`` arguments, so publishing it on both executions would state another
    execution's call as fact.
    """
    tx_hash = "0x" + "a5" * 32
    events = [
        seed_event(db_session, safe, "safe_tx_executed", tx_hash, log_index=414),
        seed_event(db_session, safe, "safe_tx_executed", tx_hash, log_index=416),
    ]
    calls: list[dict] = []

    payloads = run(
        db_session,
        events,
        {tx_hash: tx(to=SAFE, tx_hash=tx_hash, input_hex=exec_transaction_input(to=TARGET, value=9))},
        calls_out=calls,
    )

    for data in payloads:
        assert data["safe_exec"] == {"status": enr.SAFE_EXEC_STATUS_AMBIGUOUS_ATTRIBUTION}
        # The refusal is not_determined, and the witnessed sibling correlation floors the pair at notable.
        assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_NOT_ENRICHED, sal.BASIS_CORRELATED_CAUSE]
        assert data["salience"] == sal.SALIENCE_NOTABLE
    assert sal.assign_salience(db_session, "safe_tx_executed", {"safe_exec": payloads[0]["safe_exec"]}, safe) == (
        sal.SALIENCE_NOT_DETERMINED,
        [sal.BASIS_SAFE_EXEC_NOT_ENRICHED],
    )
    assert len(calls) == 1


def test_only_needs_tx_types_go_on_the_wire(db_session, safe, make_mc):
    timelock = make_mc(address=ADDR(0x71E), contract_type="timelock")
    event = seed_event(
        db_session,
        timelock,
        "timelock_scheduled",
        "0x" + "a4" * 32,
        data={"target": TARGET, "selector": SET_FEE},
    )
    calls: list[dict] = []

    run(db_session, [event], {}, calls_out=calls)

    assert calls == []


# ---------------------------------------------------------------------------
# the timelock namespace
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# the correlation join, both directions
# ---------------------------------------------------------------------------


def test_an_effect_row_keeps_the_level_it_was_minted_with(db_session, safe, make_mc):
    """The effect is linked, not re-rated: re-rating would let the reinitialization rule see the row being rated."""
    proxy = make_mc(address=ADDR(0x9711), contract_type="proxy")
    tx_hash = "0x" + "c7" * 32
    cause = seed_event(db_session, safe, "safe_tx_executed", tx_hash, log_index=1)
    first_init = seed_event(db_session, proxy, "initialized", tx_hash, data={"version": 1}, log_index=0)
    assert (first_init.data or {})["salience_basis"] == [sal.BASIS_NO_RULE]

    _cause_data, effect_data = run(db_session, [cause, first_init], {})

    assert effect_data["caused_by"]["event_id"] == str(cause.id)
    assert effect_data["salience_basis"] == [sal.BASIS_NO_RULE]
    assert effect_data["salience"] == sal.SALIENCE_NOT_DETERMINED


def test_a_correlated_entry_publishes_a_normalized_address(db_session, safe, make_mc):
    victim = make_mc(address=ADDR(0xC0FFEA).upper().replace("0X", "0x"), contract_type="regular")
    tx_hash = "0x" + "ca" * 32
    cause = seed_event(db_session, safe, "safe_tx_executed", tx_hash, log_index=1)
    seed_event(db_session, victim, "paused", tx_hash, data={"account": ADDR(3)}, log_index=0)

    (cause_data,) = run(db_session, [cause], {})

    address = cause_data["correlated_events"][0]["contract_address"]
    assert address == address.lower()


def test_the_corpus_covers_every_alert_the_decode_rules_can_mint(db_session, safe, make_mc):
    """Part 8's gate: a new alert from an unlisted shape fails here, not in front of an operator."""
    victim = make_mc(address=ADDR(0xC0FFE4), contract_type="regular")

    def decode(event, tx_input: str) -> dict:
        tx_hash = event.tx_hash
        return run(db_session, [event], {tx_hash: tx(to=SAFE, tx_hash=tx_hash, input_hex=tx_input)})[0]

    outer = decode(
        seed_event(db_session, safe, "safe_tx_executed", "0x" + "e1" * 32),
        exec_transaction_input(to=UNKNOWN_LIB, operation=1),
    )
    inner = decode(
        seed_event(db_session, safe, "safe_tx_executed", "0x" + "e2" * 32),
        exec_transaction_input(to=MULTISEND_1_3_0, operation=1, data=multisend_payload([(1, UNKNOWN_LIB, 0, b"")])),
    )
    nested = decode(
        seed_event(db_session, safe, "safe_tx_executed", "0x" + "e5" * 32),
        exec_transaction_input(
            to=MULTISEND_1_3_0,
            operation=1,
            data=multisend_payload([(1, MULTISEND_CALL_ONLY_1_4_1, 0, multisend_payload([(1, UNKNOWN_LIB, 0, b"")]))]),
        ),
    )
    failure = decode(
        seed_event(db_session, safe, "safe_tx_failed", "0x" + "e3" * 32),
        exec_transaction_input(to=TARGET),
    )

    correlated_hash = "0x" + "e4" * 32
    cause = seed_event(db_session, safe, "safe_tx_executed", correlated_hash, log_index=1)
    seed_event(db_session, victim, "upgraded", correlated_hash, data={"implementation": ADDR(7)}, log_index=0)
    correlated = run(
        db_session,
        [cause],
        {correlated_hash: tx(to=SAFE, tx_hash=correlated_hash, input_hex=exec_transaction_input(to=ADDR(0xC0FFE4)))},
    )[0]

    minted = {
        "outer delegatecall, unrecognized": (outer["salience"], tuple(outer["salience_basis"])),
        "inner delegatecall, unrecognized": (inner["salience"], tuple(inner["salience_basis"])),
        "nested inner delegatecall, unrecognized": (nested["salience"], tuple(nested["salience_basis"])),
        "execution failure": (failure["salience"], tuple(failure["salience_basis"])),
        "correlated cause": (correlated["salience"], tuple(correlated["salience_basis"])),
    }

    assert minted == {
        "outer delegatecall, unrecognized": (sal.SALIENCE_ALERT, (sal.BASIS_SAFE_EXEC_DELEGATECALL_UNRECOGNIZED,)),
        "inner delegatecall, unrecognized": (
            sal.SALIENCE_ALERT,
            (sal.BASIS_SAFE_EXEC_MULTISEND, sal.BASIS_SAFE_EXEC_DELEGATECALL_UNRECOGNIZED),
        ),
        "nested inner delegatecall, unrecognized": (
            sal.SALIENCE_ALERT,
            (sal.BASIS_SAFE_EXEC_MULTISEND, sal.BASIS_SAFE_EXEC_DELEGATECALL_UNRECOGNIZED),
        ),
        "execution failure": (sal.SALIENCE_ALERT, (sal.BASIS_EXECUTION_FAILURE,)),
        "correlated cause": (sal.SALIENCE_ALERT, (sal.BASIS_SAFE_EXEC_CALL, sal.BASIS_CORRELATED_CAUSE)),
    }
    for _shape, (_level, basis) in minted.items():
        assert set(basis) <= sal.SALIENCE_BASIS_VALUES


# ---------------------------------------------------------------------------
# The Discord embed
# ---------------------------------------------------------------------------


def embed_fields(db_session, event) -> dict[str, str]:
    from services.monitoring.notifier import _format_governance_embed

    row = db_session.get(MonitoredEvent, event.id)
    return {field["name"]: field["value"] for field in _format_governance_embed(row, db_session)["fields"]}


def test_the_embed_renders_the_decoded_call(db_session, safe, known_target):
    known_target(TARGET, SET_FEE, "setFee(uint256)")
    tx_hash = "0x" + "f1" * 32
    event = seed_event(db_session, safe, "safe_tx_executed", tx_hash)
    run(
        db_session,
        [event],
        {
            tx_hash: tx(
                to=SAFE,
                tx_hash=tx_hash,
                input_hex=exec_transaction_input(to=TARGET, value=3, data=bytes.fromhex(SET_FEE[2:])),
            )
        },
    )

    fields = embed_fields(db_session, event)
    assert fields["Target"] == f"`{TARGET}`"
    assert fields["Function"] == "`setFee(uint256)`"
    assert fields["Value"] == "3 wei"
    assert fields["Operation"] == "call"


def test_the_embed_summarizes_a_batch_and_refuses_a_partial_one(db_session, safe, known_target):
    known_target(TARGET, SET_FEE, "setFee(uint256)")
    decoded_hash, undecodable_hash = "0x" + "f3" * 32, "0x" + "f4" * 32
    decoded = seed_event(db_session, safe, "safe_tx_executed", decoded_hash)
    undecodable = seed_event(db_session, safe, "safe_tx_executed", undecodable_hash)
    run(
        db_session,
        [decoded],
        {
            decoded_hash: tx(
                to=SAFE,
                tx_hash=decoded_hash,
                input_hex=exec_transaction_input(
                    to=MULTISEND_1_3_0,
                    operation=1,
                    data=multisend_payload([(0, TARGET, 0, bytes.fromhex(SET_FEE[2:])), (0, TARGET, 1, b"")]),
                ),
            )
        },
    )
    run(
        db_session,
        [undecodable],
        {
            undecodable_hash: tx(
                to=SAFE,
                tx_hash=undecodable_hash,
                input_hex=exec_transaction_input(to=MULTISEND_1_3_0, operation=1, data=b"\x00"),
            )
        },
    )

    assert embed_fields(db_session, decoded)["Batch"] == "2 call(s): setFee(uint256), ?"
    assert "did not decode" in embed_fields(db_session, undecodable)["Batch"]


def test_the_embed_renders_the_timelock_signature(db_session, make_mc, known_target):
    """The timelock resolution was otherwise rendered nowhere."""
    known_target(TARGET, SET_FEE, "setFee(uint256)")
    timelock = make_mc(address=ADDR(0x721), contract_type="timelock")
    event = seed_event(
        db_session,
        timelock,
        "timelock_scheduled",
        "0x" + "f6" * 32,
        data={"target": TARGET, "selector": SET_FEE},
    )
    run(db_session, [event], {})

    assert embed_fields(db_session, event)["Function"] == "`setFee(uint256)`"


def test_the_embed_names_the_ambiguous_attribution(db_session, safe):
    tx_hash = "0x" + "f7" * 32
    events = [
        seed_event(db_session, safe, "safe_tx_executed", tx_hash, log_index=0),
        seed_event(db_session, safe, "safe_tx_executed", tx_hash, log_index=1),
    ]
    run(db_session, events, {tx_hash: tx(to=SAFE, tx_hash=tx_hash, input_hex=exec_transaction_input(to=TARGET))})

    rendered = embed_fields(db_session, events[0])["Safe call"]
    assert "executed more than once in this transaction" in rendered
    assert "not witnessed" in rendered
