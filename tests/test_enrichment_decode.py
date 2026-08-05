"""The decode corpus — what a Safe execution SAYS once enrichment has run.

Every fixture here is a whole transaction: a real ``execTransaction`` calldata
built from the published Safe ABI, decoded by the real enricher, driven through
the real driver, and asserted on twice — once on the published enrichment block
and once on the salience level + basis the recompute assigned it. A test that
only checked the block would let a decode drift the operator's attention
without failing.

**Mechanical gate (spec Part 8):** every ``alert`` the decode rules can mint
appears below with its basis —

* ``safe_exec_delegatecall_unrecognized`` from an OUTER delegatecall to an
  address the pinned list cannot vouch for
  (:func:`test_delegatecall_to_an_unrecognized_target_alerts`);
* ``safe_exec_delegatecall_unrecognized`` from an INNER one inside an otherwise
  recognized MultiSend (:func:`test_an_inner_delegatecall_raises_the_whole_batch`);
* ``execution_failure`` on ``safe_tx_failed`` — decoded or not
  (:func:`test_a_failed_execution_is_an_alert_whatever_the_decode_says`);
* ``correlated_cause`` raising a decoded execution to its effect's level
  (:func:`test_a_correlated_effect_raises_its_cause`).

and :func:`test_the_corpus_covers_every_alert_the_decode_rules_can_mint` states
that list as an assertion rather than as a comment. The ``correlated_scope``
caveat is pinned by
:func:`test_an_empty_correlation_publishes_its_scope_not_an_earned_negative`.

The wire is stubbed throughout (fixture transaction objects through the
``rpc_batch_request_classified`` seam). Nothing here touches RPC: the offline
suite runs under netguard and this module must keep it hermetic.
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


# ---------------------------------------------------------------------------
# Calldata builders — the published ABI, encoded, not transcribed
# ---------------------------------------------------------------------------


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
    """``multiSend(bytes)`` calldata over packed
    ``(operation:1B, to:20B, value:32B, dataLength:32B, data)`` entries."""
    packed = b"".join(
        bytes([operation]) + bytes.fromhex(to[2:]) + value.to_bytes(32, "big") + len(data).to_bytes(32, "big") + data
        for operation, to, value, data in calls
    )
    return bytes.fromhex(enr.MULTISEND_SELECTOR[2:]) + eth_abi_encode(["bytes"], [packed])


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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
    """A target the fleet has itself analysed — E2's only (witnessed) source."""

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
    """A row exactly as the taxonomy wrote it: mint-time salience included, so
    every assertion below is about what enrichment CHANGED."""
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
    """Drive the real driver with the wire stubbed by fixture transactions."""

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
# E1 — the direct call
# ---------------------------------------------------------------------------


def test_a_direct_exec_transaction_publishes_the_witnessed_call(db_session, safe, known_target):
    """The prototype case: what the Safe was asked to do, decoded from the
    transaction's own bytes, and rated on the decode rather than on the type."""
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
    # E2, and it is display only — the level below is the ``operation == 0``
    # floor either way.
    assert block["target_function"] == {
        "selector": SET_FEE,
        "signature": "setFee(uint256)",
        "source": "effective_functions",
    }
    assert data["salience"] == sal.SALIENCE_NOTABLE
    assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_CALL]


def test_an_unresolved_selector_publishes_the_selector_and_a_null_signature(db_session, safe):
    """A raw selector is a real fact and renders fine; inventing a name would
    not. And the level is identical to the resolved case — a name is not a
    witness, so it may not move an operator's attention."""
    tx_hash = "0x" + "12" * 32
    event = seed_event(db_session, safe, "safe_tx_executed", tx_hash)

    (data,) = run(
        db_session,
        [event],
        {
            tx_hash: tx(
                to=SAFE, tx_hash=tx_hash, input_hex=exec_transaction_input(to=TARGET, data=bytes.fromhex(PAUSE[2:]))
            )
        },
    )

    assert data["safe_exec"]["target_function"] == {"selector": PAUSE, "signature": None}
    assert data["salience"] == sal.SALIENCE_NOTABLE
    assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_CALL]


def test_a_selector_two_analyses_disagree_about_stays_unresolved(db_session, safe, known_target):
    """Two contracts at one address disagreeing about a selector is an
    ambiguity. Picking one would publish a name no witness picked."""
    known_target(TARGET, SET_FEE, "setFee(uint256)")
    known_target(TARGET, SET_FEE, "somethingElse(uint256)")
    tx_hash = "0x" + "13" * 32
    event = seed_event(db_session, safe, "safe_tx_executed", tx_hash)

    (data,) = run(
        db_session,
        [event],
        {
            tx_hash: tx(
                to=SAFE, tx_hash=tx_hash, input_hex=exec_transaction_input(to=TARGET, data=bytes.fromhex(SET_FEE[2:]))
            )
        },
    )

    assert data["safe_exec"]["target_function"] == {"selector": SET_FEE, "signature": None}


def test_a_signature_from_another_chain_does_not_resolve(db_session, safe, protocol):
    """``effective_functions`` joins on (address, chain). The same address on
    another chain is another contract."""
    other = Contract(protocol_id=protocol.id, address=TARGET, chain="base")
    db_session.add(other)
    db_session.flush()
    db_session.add(
        EffectiveFunction(
            contract_id=other.id, function_name="setFee", selector=SET_FEE, abi_signature="setFee(uint256)"
        )
    )
    db_session.commit()

    tx_hash = "0x" + "14" * 32
    event = seed_event(db_session, safe, "safe_tx_executed", tx_hash)
    (data,) = run(
        db_session,
        [event],
        {
            tx_hash: tx(
                to=SAFE, tx_hash=tx_hash, input_hex=exec_transaction_input(to=TARGET, data=bytes.fromhex(SET_FEE[2:]))
            )
        },
    )

    assert data["safe_exec"]["target_function"]["signature"] is None


# ---------------------------------------------------------------------------
# E1 — the top-level-call check
# ---------------------------------------------------------------------------


def test_a_relayer_wrapped_execution_is_not_a_top_level_call(db_session, safe):
    """Common and legitimate — a relayer, a nested Safe, or two
    ``execTransaction`` calls inside one outer call. Guessing at the inner call
    from the outer input would be exactly the unwitnessed inference the
    overhaul removed, so the row states the finding and collapses."""
    tx_hash = "0x" + "21" * 32
    event = seed_event(db_session, safe, "safe_tx_executed", tx_hash)

    (data,) = run(
        db_session,
        [event],
        {tx_hash: tx(to=RELAYER, tx_hash=tx_hash, input_hex="0xdeadbeef" + "00" * 32)},
    )

    assert data["safe_exec"] == {"status": "not_top_level_call"}
    assert data["salience"] == sal.SALIENCE_ROUTINE
    assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_INDIRECT]


def test_the_right_target_with_the_wrong_selector_is_not_a_top_level_call(db_session, safe):
    """Both halves are required: a call TO the Safe that is not
    ``execTransaction`` proves nothing about an execution."""
    tx_hash = "0x" + "22" * 32
    event = seed_event(db_session, safe, "safe_tx_executed", tx_hash)

    (data,) = run(db_session, [event], {tx_hash: tx(to=SAFE, tx_hash=tx_hash, input_hex="0x468721a7" + "00" * 32)})

    assert data["safe_exec"] == {"status": "not_top_level_call"}
    assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_INDIRECT]


def test_the_top_level_check_is_case_insensitive_on_the_address(db_session, safe):
    tx_hash = "0x" + "23" * 32
    event = seed_event(db_session, safe, "safe_tx_executed", tx_hash)

    (data,) = run(
        db_session,
        [event],
        {
            tx_hash: tx(
                to=SAFE.upper().replace("0X", "0x"),
                tx_hash=tx_hash,
                input_hex=exec_transaction_input(to=TARGET).upper().replace("0X", "0x"),
            )
        },
    )

    assert data["safe_exec"]["status"] == "decoded"


def test_undecodable_arguments_state_the_gap_rather_than_leaving_the_block_absent(db_session, safe):
    """A proven ``execTransaction`` whose arguments are truncated. The status
    says which undecoded world this is, and the level stays VISIBLE."""
    tx_hash = "0x" + "24" * 32
    event = seed_event(db_session, safe, "safe_tx_executed", tx_hash)

    (data,) = run(
        db_session, [event], {tx_hash: tx(to=SAFE, tx_hash=tx_hash, input_hex=SAFE_EXEC_SELECTOR + "00" * 32)}
    )

    assert data["safe_exec"] == {"status": enr.SAFE_EXEC_STATUS_ARGS_UNDECODABLE}
    assert data["salience"] == sal.SALIENCE_NOT_DETERMINED
    # A rule DID examine this row, so the basis names the enrichment gap rather
    # than saying no rule considered it.
    assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_NOT_ENRICHED]


@pytest.mark.parametrize(
    "fixture",
    [{"hash": "x"}, {"hash": "x", "to": SAFE}, {"hash": "x", "input": "0x"}],
    ids=["neither-field", "no-input", "no-to-key"],
)
def test_a_transaction_object_missing_its_fields_mints_no_finding(db_session, safe, fixture):
    """``not_top_level_call`` is a positive finding that DEMOTES the row, so it
    may only be minted from fields the response actually carried. A response
    shape we cannot read is an unread transaction, not a proven indirect one."""
    tx_hash = "0x" + "26" * 32
    event = seed_event(db_session, safe, "safe_tx_executed", tx_hash)

    (data,) = run(db_session, [event], {tx_hash: dict(fixture, hash=tx_hash)})

    assert "safe_exec" not in data
    assert data["salience"] == sal.SALIENCE_NOT_DETERMINED
    assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_NOT_ENRICHED]


def test_a_contract_creation_is_witnessed_not_to_be_this_safes_call(db_session, safe):
    """``to: null`` is a field the response carried, and it proves the
    transaction called nobody — a finding, and the row collapses on it."""
    tx_hash = "0x" + "27" * 32
    event = seed_event(db_session, safe, "safe_tx_executed", tx_hash)

    (data,) = run(db_session, [event], {tx_hash: {"hash": tx_hash, "to": None, "input": "0x6080"}})

    assert data["safe_exec"] == {"status": "not_top_level_call"}
    assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_INDIRECT]


def test_a_transaction_that_was_never_fetched_publishes_no_block(db_session, safe):
    """ "Not fetched" is not a finding about the transaction. No block, and the
    salience rules read that as enrichment-absent: visible, never demoted."""
    tx_hash = "0x" + "25" * 32
    event = seed_event(db_session, safe, "safe_tx_executed", tx_hash)

    (data,) = run(db_session, [event], {})

    assert "safe_exec" not in data
    assert data["salience"] == sal.SALIENCE_NOT_DETERMINED
    assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_NOT_ENRICHED]


# ---------------------------------------------------------------------------
# E1 + E4 — delegatecall, the design-critical trap
# ---------------------------------------------------------------------------


def test_delegatecall_to_an_unrecognized_target_alerts(db_session, safe):
    """Not proven to be MultiSend. The address is not proven malicious either —
    which is precisely why the level goes UP rather than down."""
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
    """The routine shape the naive ``operation == 1 ⇒ alert`` rule would have
    fired on: the standard Safe UI batches by delegatecalling MultiSend."""
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


def test_an_inner_delegatecall_raises_the_whole_batch(db_session, safe):
    """Each inner call is evaluated by the same operation rules as the outer
    one, and the batch takes the max."""
    tx_hash = "0x" + "33" * 32
    event = seed_event(db_session, safe, "safe_tx_executed", tx_hash)
    payload = multisend_payload(
        [
            (0, TARGET, 0, bytes.fromhex(SET_FEE[2:])),
            (1, UNKNOWN_LIB, 0, bytes.fromhex(PAUSE[2:])),
        ]
    )

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
    assert block["batch"][1][sal.SAFE_EXEC_KEY_MULTISEND_RECOGNIZED] is False
    assert data["salience"] == sal.SALIENCE_ALERT
    assert data["salience_basis"] == [
        sal.BASIS_SAFE_EXEC_MULTISEND,
        sal.BASIS_SAFE_EXEC_DELEGATECALL_UNRECOGNIZED,
    ]


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


def test_a_nested_batch_is_expanded_and_its_inner_alert_propagates(db_session, safe):
    """One extra wrapping layer is not a reason to trust a payload. A
    recognized MultiSend INSIDE a recognized MultiSend is a batch in its own
    right and is expanded by the same rules — otherwise a hostile delegatecall
    would be hidden by nesting it, which is executable on-chain (the singleton
    guard passes in the Safe's delegatecall context)."""
    inner = multisend_payload([(1, UNKNOWN_LIB, 0, bytes.fromhex(PAUSE[2:]))])
    payload = multisend_payload([(0, TARGET, 0, b""), (1, MULTISEND_CALL_ONLY_1_4_1, 0, inner)])

    data = _decode_batch(db_session, safe, "0x" + "34" * 32, payload)

    nested = data["safe_exec"]["batch"][1]["batch"]
    assert [call["to"] for call in nested] == [UNKNOWN_LIB]
    assert nested[0][sal.SAFE_EXEC_KEY_MULTISEND_RECOGNIZED] is False
    assert data["salience"] == sal.SALIENCE_ALERT
    assert data["salience_basis"] == [
        sal.BASIS_SAFE_EXEC_MULTISEND,
        sal.BASIS_SAFE_EXEC_DELEGATECALL_UNRECOGNIZED,
    ]


def test_a_benign_nested_batch_stays_at_the_batch_floor(db_session, safe):
    """Expansion is not escalation: a nested batch that decodes and holds only
    calls earns the same floor a flat one does."""
    inner = multisend_payload([(0, TARGET, 0, bytes.fromhex(PAUSE[2:]))])
    payload = multisend_payload([(1, MULTISEND_CALL_ONLY_1_4_1, 0, inner)])

    data = _decode_batch(db_session, safe, "0x" + "37" * 32, payload)

    assert data["safe_exec"]["batch"][0]["batch"][0]["to"] == TARGET
    assert data["salience"] == sal.SALIENCE_NOTABLE
    assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_MULTISEND]


def test_a_nested_payload_that_will_not_decode_takes_the_whole_batch_with_it(db_session, safe):
    """No partial list, at any depth: an inner MultiSend that will not expand
    may not stand as an entry whose contents nobody read."""
    payload = multisend_payload([(0, TARGET, 0, b""), (1, MULTISEND_CALL_ONLY_1_4_1, 0, bytes.fromhex(PAUSE[2:]))])

    data = _decode_batch(db_session, safe, "0x" + "38" * 32, payload)

    block = data["safe_exec"]
    assert block["batch_status"] == "undecodable"
    assert block["batch_status_reason"] == enr.BATCH_REASON_MALFORMED
    assert "batch" not in block
    assert data["salience"] == sal.SALIENCE_NOT_DETERMINED
    assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_BATCH_UNDECODABLE]


def test_a_batch_nested_past_the_depth_cap_states_the_gap(db_session, safe):
    """The cap bounds an adversarially deep payload's cost. Exceeding it is a
    STATED gap on the WHOLE batch, never a quiet floor over calls nobody read."""
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
    """The boundary, pinned: MAX_MULTISEND_DEPTH layers decode, one more does
    not. A cap nobody measured is a cap that drifts."""
    payload = multisend_payload([(0, TARGET, 0, b"")])
    for _ in range(enr.MAX_MULTISEND_DEPTH - 1):
        payload = multisend_payload([(1, MULTISEND_1_3_0, 0, payload)])

    data = _decode_batch(db_session, safe, "0x" + "3a" * 32, payload)

    assert "batch_status" not in data["safe_exec"]
    assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_MULTISEND]


def test_the_salience_rules_refuse_an_unexpanded_nested_batch(db_session, make_mc):
    """Defence in depth for the shape the decoder can no longer produce: a
    batch entry claiming to be a MultiSend with no expansion and no stated
    failure rates ``not_determined``, not the ``notable`` floor. Asserted
    against the rules directly, since the decode path cannot build it."""
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
    """A truncated batch would UNDERSTATE what the Safe did, so there is no
    partial list — the failure itself is the publication, and the level refuses
    rather than guessing."""
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


def test_a_recognized_delegatecall_always_carries_a_batch_or_a_stated_failure(db_session, safe):
    """The shape that would otherwise rate ``safe_exec_not_enriched`` — a
    recognized MultiSend whose contents nobody examined and nobody said so — is
    non-occurring on the decode path, by construction."""
    payloads = [
        multisend_payload([(0, TARGET, 0, b"")]),
        multisend_payload([]),
        b"\x00\x01\x02",
    ]
    for index, payload in enumerate(payloads):
        tx_hash = "0x" + f"{index:02x}" * 32
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
        assert ("batch" in block) != ("batch_status" in block)
        assert data["salience_basis"] != [sal.BASIS_SAFE_EXEC_NOT_ENRICHED]


def test_every_decoded_batch_entry_is_a_mapping(db_session, safe):
    """The batch feeds a salience fold that can only rate a Mapping. The
    decoder never emits anything else — a shape it cannot build as one entry
    takes the whole batch to ``undecodable``."""
    calls, reason = enr._decode_multisend(multisend_payload([(0, TARGET, 1, b"\x01"), (1, UNKNOWN_LIB, 0, b"")]))
    assert calls is not None and reason is None
    assert all(isinstance(call, dict) for call in calls)
    truncated, reason = enr._decode_multisend(multisend_payload([(0, TARGET, 1, b"\x01")])[:-3])
    assert truncated is None
    assert reason == enr.BATCH_REASON_MALFORMED


def test_a_decoded_delegatecall_always_states_the_multisend_discriminator(db_session, safe):
    """The salience rules read ``multisend_recognized`` and treat its ABSENCE
    as not-proven-MultiSend. Publishing it on every decode is what keeps the
    loud direction from being an accident."""
    for index, (target, expected) in enumerate([(MULTISEND_1_3_0, True), (UNKNOWN_LIB, False), (TARGET, False)]):
        tx_hash = "0x" + f"{index + 0x40:02x}" * 32
        event = seed_event(db_session, safe, "safe_tx_executed", tx_hash)
        (data,) = run(
            db_session,
            [event],
            {
                tx_hash: tx(
                    to=SAFE,
                    tx_hash=tx_hash,
                    input_hex=exec_transaction_input(
                        to=target, operation=1, data=multisend_payload([(0, TARGET, 0, b"")])
                    ),
                )
            },
        )
        assert data["safe_exec"][sal.SAFE_EXEC_KEY_MULTISEND_RECOGNIZED] is expected


def test_a_failed_execution_is_an_alert_whatever_the_decode_says(db_session, safe):
    """``safe_tx_failed`` outranks every decode rule — but it is still decoded,
    because "which call reverted" is the first thing an operator asks."""
    tx_hash = "0x" + "36" * 32
    event = seed_event(db_session, safe, "safe_tx_failed", tx_hash)

    (data,) = run(
        db_session,
        [event],
        {
            tx_hash: tx(
                to=SAFE, tx_hash=tx_hash, input_hex=exec_transaction_input(to=TARGET, data=bytes.fromhex(SET_FEE[2:]))
            )
        },
    )

    assert data["safe_exec"]["to"] == TARGET
    assert data["salience"] == sal.SALIENCE_ALERT
    assert data["salience_basis"] == [sal.BASIS_EXECUTION_FAILURE]


# ---------------------------------------------------------------------------
# The per-pass budget
# ---------------------------------------------------------------------------


def test_over_budget_hashes_are_recorded_not_dropped(db_session, make_mc, monkeypatch):
    """The budget bounds how long the fetch holds the open window transaction.
    What it may not do is make a Safe execution look examined-and-boring."""
    monkeypatch.setenv(enr.ENRICH_TX_BUDGET_ENV, "1")
    safes = [make_mc(address=ADDR(0x5A00 + i)) for i in range(2)]
    hashes = ["0x" + "a1" * 32, "0x" + "a2" * 32]
    events = [seed_event(db_session, mc, "safe_tx_executed", h) for mc, h in zip(safes, hashes)]
    txs = {h: tx(to=mc.address, tx_hash=h, input_hex=exec_transaction_input(to=TARGET)) for mc, h in zip(safes, hashes)}

    calls: list[dict] = []
    payloads = run(db_session, events, txs, calls_out=calls)

    # Exactly one slot was requested; the other hash never went on the wire.
    assert len(calls) == 1
    assert [params[0] for _method, params in calls[0]["calls"]] == [hashes[0]]
    assert payloads[0]["safe_exec"]["status"] == "decoded"
    assert payloads[1]["safe_exec"] == {"status": "over_budget"}
    assert payloads[1]["salience"] == sal.SALIENCE_NOT_DETERMINED
    assert payloads[1]["salience_basis"] == [sal.BASIS_SAFE_EXEC_NOT_ENRICHED]


def test_the_budget_is_spent_once_across_every_chain_in_the_pass(db_session, make_mc, monkeypatch):
    """The seam the budget protects — the open window transaction — is
    per-pass, not per-chain, so a fleet on N chains may not spend N×."""
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

    # One slot in the whole pass, and the second chain records the decline.
    assert sum(len(call["calls"]) for call in calls) == 1
    statuses = {payload["safe_exec"]["status"] for payload in payloads}
    assert statuses == {"decoded", "over_budget"}


def test_the_fetch_is_deduplicated_and_carries_the_chain_id(db_session, safe, make_mc):
    """Two executions in one transaction cost one fetch — the live feed already
    contains that shape — and the chain_id rides so the URL↔chain guard the
    rest of monitoring uses applies here too."""
    other = make_mc(address=ADDR(0x5A0F))
    tx_hash = "0x" + "a3" * 32
    events = [
        seed_event(db_session, safe, "safe_tx_executed", tx_hash, log_index=0),
        seed_event(db_session, other, "safe_tx_executed", tx_hash, log_index=1),
    ]
    calls: list[dict] = []

    run(
        db_session,
        events,
        {tx_hash: tx(to=SAFE, tx_hash=tx_hash, input_hex=exec_transaction_input(to=TARGET))},
        calls_out=calls,
    )

    assert len(calls) == 1
    assert len(calls[0]["calls"]) == 1
    assert calls[0]["chain_id"] == 1
    assert calls[0]["rpc_url"] == "https://rpc.invalid/eth"


def test_two_executions_of_one_safe_in_one_tx_refuse_attribution(db_session, safe):
    """The live feed's own shape (two ExecutionSuccess logs, one transaction,
    one Safe — spec appendix, log_index 414/416). The transaction holds ONE set
    of top-level ``execTransaction`` arguments, which describes at most one of
    the two executions; nothing in the transaction object witnesses which.
    Publishing it on both would state another execution's target, value and
    operation as a witnessed fact about this row."""
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
        # The refusal itself is not_determined; each row then also correlates
        # with its sibling execution (same transaction is a witnessed fact),
        # which floors the pair at notable. Neither code erases the other, and
        # nothing here is routine.
        assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_NOT_ENRICHED, sal.BASIS_CORRELATED_CAUSE]
        assert data["salience"] == sal.SALIENCE_NOTABLE
    assert sal.assign_salience(db_session, "safe_tx_executed", {"safe_exec": payloads[0]["safe_exec"]}, safe) == (
        sal.SALIENCE_NOT_DETERMINED,
        [sal.BASIS_SAFE_EXEC_NOT_ENRICHED],
    )
    # Still one fetch — refusing the attribution is not refusing to look.
    assert len(calls) == 1


def test_a_sibling_execution_from_an_earlier_window_still_contests(db_session, safe):
    """The contest is queried, not read off the window: a Safe whose second
    execution in the same transaction was inserted by an earlier pass must not
    be decoded now as though it were alone in it."""
    tx_hash = "0x" + "a6" * 32
    earlier = seed_event(db_session, safe, "safe_tx_executed", tx_hash, log_index=1)
    current = seed_event(db_session, safe, "safe_tx_executed", tx_hash, log_index=2)

    (data,) = run(
        db_session,
        [current],
        {tx_hash: tx(to=SAFE, tx_hash=tx_hash, input_hex=exec_transaction_input(to=TARGET))},
    )

    assert earlier.id != current.id
    assert data["safe_exec"] == {"status": enr.SAFE_EXEC_STATUS_AMBIGUOUS_ATTRIBUTION}


def test_a_contested_tx_that_is_not_this_safes_call_still_states_that(db_session, safe):
    """``not_top_level_call`` is a statement about the OBSERVED TRANSACTION and
    is true of every row in it, so the ambiguity — which is about attributing
    ARGUMENTS to one row — does not erase it."""
    tx_hash = "0x" + "a7" * 32
    events = [
        seed_event(db_session, safe, "safe_tx_executed", tx_hash, log_index=0),
        seed_event(db_session, safe, "safe_tx_executed", tx_hash, log_index=1),
    ]

    payloads = run(db_session, events, {tx_hash: tx(to=RELAYER, tx_hash=tx_hash, input_hex="0xdeadbeef")})

    for data in payloads:
        assert data["safe_exec"] == {"status": "not_top_level_call"}
        # The indirect finding stands; the sibling correlation rides beside it.
        assert data["salience_basis"][0] == sal.BASIS_SAFE_EXEC_INDIRECT
    assert sal.assign_salience(db_session, "safe_tx_executed", {"safe_exec": payloads[0]["safe_exec"]}, safe) == (
        sal.SALIENCE_ROUTINE,
        [sal.BASIS_SAFE_EXEC_INDIRECT],
    )


def test_two_executions_of_DIFFERENT_safes_in_one_tx_each_decode(db_session, safe, make_mc):
    """The contest is per (Safe, transaction). Two different Safes in one
    transaction are two different top-level calls only if each is the
    transaction's ``to`` — and the one that is gets its decode."""
    other = make_mc(address=ADDR(0x5A10))
    tx_hash = "0x" + "a8" * 32
    mine = seed_event(db_session, safe, "safe_tx_executed", tx_hash, log_index=0)
    theirs = seed_event(db_session, other, "safe_tx_executed", tx_hash, log_index=1)

    mine_data, theirs_data = run(
        db_session,
        [mine, theirs],
        {tx_hash: tx(to=SAFE, tx_hash=tx_hash, input_hex=exec_transaction_input(to=TARGET))},
    )

    assert mine_data["safe_exec"]["status"] == "decoded"
    assert theirs_data["safe_exec"] == {"status": "not_top_level_call"}


def test_only_needs_tx_types_go_on_the_wire(db_session, safe, make_mc):
    """A window with no Safe execution in it costs zero RPC."""
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
# E2 — the timelock namespace
# ---------------------------------------------------------------------------


def test_a_timelock_operation_resolves_its_selector_in_its_own_namespace(db_session, make_mc, known_target):
    """The timelock families' ``target``/``selector`` are already decoded at
    mint and are keys the taxonomy owns, so the resolution lands in a namespaced
    block of its own rather than beside them."""
    known_target(TARGET, SET_FEE, "setFee(uint256)")
    timelock = make_mc(address=ADDR(0x71F), contract_type="timelock")
    event = seed_event(
        db_session,
        timelock,
        "timelock_executed",
        "0x" + "b1" * 32,
        data={"target": TARGET, "selector": SET_FEE, "value": 0},
    )

    (data,) = run(db_session, [event], {})

    assert data["target_function"] == {
        "selector": SET_FEE,
        "signature": "setFee(uint256)",
        "source": "effective_functions",
    }
    # The taxonomy's own keys are untouched, and the level is the family's.
    assert data["target"] == TARGET
    assert data["selector"] == SET_FEE
    assert data["salience"] == sal.SALIENCE_NOTABLE
    assert data["salience_basis"] == [sal.BASIS_TIMELOCK_OPERATION]


def test_target_function_is_the_only_widening_of_the_additive_key_set(db_session, safe):
    """The allowlist stays closed: ``target_function`` is admitted, anything
    else an enricher invents is still loudly refused."""
    assert "target_function" in enr.ENRICHABLE_KEYS
    event = seed_event(db_session, safe, "safe_tx_executed", "0x" + "b2" * 32)

    with patch.dict(
        enr.ENRICHERS,
        {
            "safe_tx_executed": lambda *_a: {
                "target_function": {"selector": SET_FEE, "signature": None},
                "decoded_by": "me",
            }
        },
        clear=False,
    ):
        (data,) = run(db_session, [event], {})

    assert data["target_function"] == {"selector": SET_FEE, "signature": None}
    assert "decoded_by" not in data


def test_a_timelock_without_a_decoded_selector_publishes_nothing(db_session, make_mc):
    """A plain-value timelock call has no calldata. There is nothing to resolve
    and nothing to say — an invented empty block would say otherwise."""
    timelock = make_mc(address=ADDR(0x720), contract_type="timelock")
    event = seed_event(
        db_session,
        timelock,
        "timelock_scheduled",
        "0x" + "b3" * 32,
        data={"target": TARGET, "calldata_length": 0},
    )

    (data,) = run(db_session, [event], {})

    assert "target_function" not in data


# ---------------------------------------------------------------------------
# E3 — the correlation join, both directions
# ---------------------------------------------------------------------------


def test_a_correlated_effect_raises_its_cause(db_session, safe, make_mc):
    """Same transaction hash is a fact, not an inference — so both directions
    are published, and a decoded execution whose effect is an alert is at least
    an alert itself."""
    victim = make_mc(address=ADDR(0xC0FFEE), contract_type="regular")
    tx_hash = "0x" + "c1" * 32
    cause = seed_event(db_session, safe, "safe_tx_executed", tx_hash, log_index=1)
    effect = seed_event(db_session, victim, "ownership_transferred", tx_hash, data={"new_owner": ADDR(9)}, log_index=0)

    cause_data, effect_data = run(
        db_session,
        [cause, effect],
        {tx_hash: tx(to=SAFE, tx_hash=tx_hash, input_hex=exec_transaction_input(to=ADDR(0xC0FFEE)))},
    )

    assert cause_data["correlated_events"] == [
        {
            "event_id": str(effect.id),
            "event_type": "ownership_transferred",
            "contract_address": ADDR(0xC0FFEE),
            "salience": sal.SALIENCE_ALERT,
        }
    ]
    assert cause_data["correlated_scope"] == "monitored_only"
    assert cause_data["salience"] == sal.SALIENCE_ALERT
    assert cause_data["salience_basis"] == [sal.BASIS_SAFE_EXEC_CALL, sal.BASIS_CORRELATED_CAUSE]
    # The reciprocal, on the effect.
    assert effect_data["caused_by"] == {"event_id": str(cause.id), "event_type": "safe_tx_executed"}
    assert effect_data["salience"] == sal.SALIENCE_ALERT


def test_each_correlated_entry_carries_the_effects_own_level(db_session, safe, make_mc):
    """``assign_salience`` reads this list and does NOT query, so an entry
    without its level would silently under-rate the cause."""
    quiet = make_mc(address=ADDR(0xB0B), contract_type="regular")
    tx_hash = "0x" + "c2" * 32
    cause = seed_event(db_session, safe, "safe_tx_executed", tx_hash, log_index=1)
    seed_event(
        db_session,
        quiet,
        "state_changed_poll",
        tx_hash,
        data={"field": "rate", "signal_class": "metric", "signal_class_basis": "no_gate_provenance"},
        log_index=0,
    )

    (cause_data,) = run(
        db_session,
        [cause],
        {tx_hash: tx(to=SAFE, tx_hash=tx_hash, input_hex=exec_transaction_input(to=ADDR(0xB0B)))},
    )

    assert cause_data["correlated_events"][0]["salience"] == sal.SALIENCE_ROUTINE
    # A routine effect does not lower its cause: correlation is a MAX with a
    # notable floor, never a demotion.
    assert cause_data["salience"] == sal.SALIENCE_NOTABLE


def test_an_empty_correlation_publishes_its_scope_not_an_earned_negative(db_session, safe):
    """An empty list means "no monitored contract emitted in this transaction",
    never "this execution had no effect". The scope key is what stops a
    consumer from reading the second."""
    tx_hash = "0x" + "c3" * 32
    event = seed_event(db_session, safe, "safe_tx_executed", tx_hash)

    (data,) = run(
        db_session,
        [event],
        {tx_hash: tx(to=SAFE, tx_hash=tx_hash, input_hex=exec_transaction_input(to=TARGET))},
    )

    assert data["correlated_events"] == []
    assert data["correlated_scope"] == "monitored_only"
    # And it changed nothing about the level.
    assert data["salience_basis"] == [sal.BASIS_SAFE_EXEC_CALL]


def test_a_read_witnessed_row_never_joins(db_session, safe, make_mc):
    """Read-witnessed rows persist ``tx_hash = ''``. The empty string is not a
    transaction, and a join on it would correlate every poll diff in the fleet
    with every other one."""
    polled = make_mc(address=ADDR(0xDEAD1), contract_type="regular")
    cause = seed_event(db_session, safe, "safe_tx_executed", "")
    read_row = seed_event(db_session, polled, "value_changed:state_variable:owner", "", data={"field": "owner"})

    cause_data, read_data = run(db_session, [cause, read_row], {})

    assert "correlated_events" not in cause_data
    assert "caused_by" not in read_data


def test_two_executions_in_one_transaction_do_not_claim_a_direction(db_session, make_mc):
    """Which of two executions caused a given effect is NOT witnessed by the
    shared hash. The link still exists from each execution's side, so nothing
    is lost — only the unproven direction is withheld."""
    safe_a = make_mc(address=ADDR(0x5A01))
    safe_b = make_mc(address=ADDR(0x5A02))
    victim = make_mc(address=ADDR(0xC0FFE2), contract_type="regular")
    tx_hash = "0x" + "c4" * 32
    a = seed_event(db_session, safe_a, "safe_tx_executed", tx_hash, log_index=0)
    b = seed_event(db_session, safe_b, "safe_tx_executed", tx_hash, log_index=1)
    effect = seed_event(db_session, victim, "paused", tx_hash, data={"account": ADDR(3)}, log_index=2)

    a_data, b_data, effect_data = run(db_session, [a, b, effect], {})

    assert "caused_by" not in effect_data
    assert {entry["event_id"] for entry in a_data["correlated_events"]} == {str(b.id), str(effect.id)}
    assert {entry["event_id"] for entry in b_data["correlated_events"]} == {str(a.id), str(effect.id)}


def test_an_effect_row_keeps_the_level_it_was_minted_with(db_session, safe, make_mc):
    """``caused_by`` is read by no salience rule, so the effect side is linked
    and NOT re-rated. Re-rating it would not be the no-op it looks like: the
    reinitialization rule asks whether a prior ``initialized`` row exists, and
    by the time enrichment runs the row being rated is one of the rows that
    query can see."""
    proxy = make_mc(address=ADDR(0x9711), contract_type="proxy")
    tx_hash = "0x" + "c7" * 32
    cause = seed_event(db_session, safe, "safe_tx_executed", tx_hash, log_index=1)
    first_init = seed_event(db_session, proxy, "initialized", tx_hash, data={"version": 1}, log_index=0)
    assert (first_init.data or {})["salience_basis"] == [sal.BASIS_NO_RULE]

    _cause_data, effect_data = run(db_session, [cause, first_init], {})

    assert effect_data["caused_by"]["event_id"] == str(cause.id)
    assert effect_data["salience_basis"] == [sal.BASIS_NO_RULE]
    assert effect_data["salience"] == sal.SALIENCE_NOT_DETERMINED


def test_the_join_does_not_cross_protocols(db_session, safe):
    """Tenancy. The published entry names another row's id, address and level,
    and the API spreads ``data`` verbatim — so an unscoped join would hand one
    protocol's subscriber a row belonging to another."""
    stranger_protocol = Protocol(name="decode-corpus-other", chains=["ethereum"])
    db_session.add(stranger_protocol)
    db_session.flush()
    contract = Contract(protocol_id=stranger_protocol.id, address=ADDR(0xA11E7), chain="ethereum")
    db_session.add(contract)
    db_session.flush()
    stranger = MonitoredContract(
        id=uuid.uuid4(),
        address=ADDR(0xA11E7),
        chain="ethereum",
        protocol_id=stranger_protocol.id,
        contract_id=contract.id,
        contract_type="regular",
        monitoring_config={},
        last_known_state={},
        enrollment_block=1,
        is_active=True,
    )
    db_session.add(stranger)
    db_session.commit()

    tx_hash = "0x" + "c8" * 32
    cause = seed_event(db_session, safe, "safe_tx_executed", tx_hash, log_index=1)
    theirs = seed_event(
        db_session, stranger, "ownership_transferred", tx_hash, data={"new_owner": ADDR(9)}, log_index=0
    )

    cause_data, theirs_data = run(db_session, [cause, theirs], {})

    assert cause_data["correlated_events"] == []
    assert "caused_by" not in theirs_data


def test_an_effect_from_an_earlier_window_still_links(db_session, safe, make_mc):
    """DELIBERATE and additive, and recorded as a deviation: §3.4's query has
    no window restriction, so an effect already stored when its cause arrives
    still links. It is not the bounded look-back OQ4 declined to build — no
    extra lookup happens, the cause's own transaction hash is matched against
    what is already there — and it cannot re-notify a committed row. Pinned so
    nobody "fixes" it into a regression."""
    victim = make_mc(address=ADDR(0xC0FFE9), contract_type="regular")
    tx_hash = "0x" + "c9" * 32
    # Stored by an earlier pass: it is NOT in the list the driver receives.
    effect = seed_event(db_session, victim, "paused", tx_hash, data={"account": ADDR(3)}, log_index=0)
    cause = seed_event(db_session, safe, "safe_tx_executed", tx_hash, log_index=1)

    (cause_data,) = run(db_session, [cause], {})

    assert [entry["event_id"] for entry in cause_data["correlated_events"]] == [str(effect.id)]
    db_session.expire_all()
    assert db_session.get(MonitoredEvent, effect.id).data["caused_by"]["event_id"] == str(cause.id)


def test_a_correlated_entry_publishes_a_normalized_address(db_session, safe, make_mc):
    """One normal form for every published address, so a consumer never has to
    case-fold to compare two of this system's own facts."""
    victim = make_mc(address=ADDR(0xC0FFEA).upper().replace("0X", "0x"), contract_type="regular")
    tx_hash = "0x" + "ca" * 32
    cause = seed_event(db_session, safe, "safe_tx_executed", tx_hash, log_index=1)
    seed_event(db_session, victim, "paused", tx_hash, data={"account": ADDR(3)}, log_index=0)

    (cause_data,) = run(db_session, [cause], {})

    address = cause_data["correlated_events"][0]["contract_address"]
    assert address == address.lower()


def test_a_historical_row_is_never_enriched_by_the_join(db_session, safe, make_mc):
    """§3.0 rule 5. A pre-enrollment row is not a witness to anything this
    window did, in either direction."""
    victim = make_mc(address=ADDR(0xC0FFE3), contract_type="regular")
    tx_hash = "0x" + "c5" * 32
    cause = seed_event(db_session, safe, "safe_tx_executed", tx_hash, log_index=1)
    old = seed_event(db_session, victim, "paused", tx_hash, data={"historical": True}, log_index=0)

    cause_data, old_data = run(db_session, [cause, old], {})

    assert cause_data["correlated_events"] == []
    assert "caused_by" not in old_data


def test_the_join_does_not_cross_chains(db_session, safe, protocol):
    """Two chains can carry the same transaction hash. A cross-chain
    "correlation" would be a coincidence published as a cause."""
    contract = Contract(protocol_id=protocol.id, address=ADDR(0xBA5E), chain="base")
    db_session.add(contract)
    db_session.flush()
    other_chain = MonitoredContract(
        id=uuid.uuid4(),
        address=ADDR(0xBA5E),
        chain="base",
        protocol_id=protocol.id,
        contract_id=contract.id,
        contract_type="regular",
        monitoring_config={},
        last_known_state={},
        enrollment_block=1,
        is_active=True,
    )
    db_session.add(other_chain)
    db_session.commit()

    tx_hash = "0x" + "c6" * 32
    cause = seed_event(db_session, safe, "safe_tx_executed", tx_hash, log_index=0)
    elsewhere = seed_event(db_session, other_chain, "paused", tx_hash, data={"account": ADDR(3)}, log_index=0)

    cause_data, elsewhere_data = run(db_session, [cause, elsewhere], {})

    assert cause_data["correlated_events"] == []
    assert "caused_by" not in elsewhere_data


# ---------------------------------------------------------------------------
# The mechanical gate, stated as an assertion
# ---------------------------------------------------------------------------


def test_the_corpus_covers_every_alert_the_decode_rules_can_mint(db_session, safe, make_mc):
    """Part 8's gate: each alert-minting decode shape, with its basis, in one
    place. A rule that starts minting an alert from a shape not listed here
    fails this test rather than reaching an operator unannounced."""
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
    # Every code used above is in the closed vocabulary.
    for _shape, (_level, basis) in minted.items():
        assert set(basis) <= sal.SALIENCE_BASIS_VALUES


# ---------------------------------------------------------------------------
# §5a — the Discord embed
# ---------------------------------------------------------------------------


def embed_fields(db_session, event) -> dict[str, str]:
    from services.monitoring.notifier import _format_governance_embed

    row = db_session.get(MonitoredEvent, event.id)
    return {field["name"]: field["value"] for field in _format_governance_embed(row, db_session)["fields"]}


def test_the_embed_renders_the_decoded_call(db_session, safe, known_target):
    """The single highest-value operator-facing change in the spec: an embed
    that said "safe_tx_executed on 0x…" now says what was executed."""
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


def test_the_embed_names_an_unrecognized_delegatecall_as_one(db_session, safe):
    tx_hash = "0x" + "f2" * 32
    event = seed_event(db_session, safe, "safe_tx_executed", tx_hash)
    run(
        db_session,
        [event],
        {tx_hash: tx(to=SAFE, tx_hash=tx_hash, input_hex=exec_transaction_input(to=UNKNOWN_LIB, operation=1))},
    )

    fields = embed_fields(db_session, event)
    assert fields["Operation"] == "delegatecall (target NOT a pinned MultiSend)"


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
    """The timelock resolution was write-only until now: published, carried
    through the API, and rendered nowhere."""
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


def test_the_embed_states_an_undecoded_execution_rather_than_rendering_nothing(db_session, safe):
    """A recipient who sees no target must be able to tell "the Safe called
    nobody" from "we did not decode this"."""
    tx_hash = "0x" + "f5" * 32
    event = seed_event(db_session, safe, "safe_tx_executed", tx_hash)
    run(db_session, [event], {tx_hash: tx(to=RELAYER, tx_hash=tx_hash, input_hex="0xdeadbeef")})

    assert "not this Safe's own execTransaction" in embed_fields(db_session, event)["Safe call"]


def test_the_pinned_allowlist_is_the_published_deployment_set(db_session):
    """The list is a vendored witness, so its contents are pinned here: a
    silent addition would quiet a delegatecall nobody vouched for, and a silent
    removal would alert on every routine batch."""
    assert enr._SAFE_MULTISEND_ADDRESSES == {
        "0xa238cbeb142c10ef7ad8442c6d1f9e89e07e7761",
        "0x998739bfdaadde7c933b942a68053933098f9eda",
        "0x40a2accbd92bca938b02010e17a5b8929b49130d",
        "0xa1dabef33b3b82c7814b6d82a79e50f4ac44102b",
        "0x38869bf66a61cf6bdb996a6ae40d5853fd43b526",
        "0x9641d764fc13c8b624c04430c7356c1c7c8102e2",
    }
    assert all(address == address.lower() for address in enr._SAFE_MULTISEND_ADDRESSES)
    # Hashed from the published signature, not transcribed — the comment's
    # provenance claim is the code's behaviour.
    assert enr.MULTISEND_SELECTOR == "0x8d80ff0a"
