"""The published ``monitored_events.event_type`` may claim a controller
changed only when the tracking plan PROVES the write target gates callers.

Fixtures are verbatim tracked-controller entries from real persisted
tracking plans: an enrolled governance token whose ``_balances`` slot has
no ``authority_provenance`` (ordinary ERC-20 Transfer/Approval traffic),
and FiatTokenV2_2's ``pauser`` slot, which carries
``authority_provenance='caller_gate'``. The first must publish the neutral
type end-to-end; the second must keep the controller claim.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from eth_utils.crypto import keccak

from services.monitoring.event_topics import (  # noqa: E402
    _resolve_event_type,
    extract_governance_topics,
    parse_tracked_log,
)
from tests.conftest import requires_postgres  # noqa: E402


def _topic0(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()


TRANSFER_TOPIC0 = _topic0("Transfer(address,address,uint256)")
PAUSER_CHANGED_TOPIC0 = _topic0("PauserChanged(address)")

TOKEN_ADDRESS = "0x86b5780b606940eb59a062aa85a07959518c0161"
FIAT_TOKEN_ADDRESS = "0x43506849d7c04f9138d1a2050bbf3a0c054402dd"


def _erc20_balances_controller(*, authority_provenance: str | None = None) -> dict:
    """The ``state_variable:_balances`` tracked controller as persisted for
    the enrolled governance token — ordinary ERC-20/ERC-20Votes signatures
    bound to a mapping slot that never earned a gate proof. (The persisted
    plan binds five; three are carried here, Enter/Exit dropped as
    protocol-specific noise with the same shape.)"""
    tracked = {
        "controller_id": "state_variable:_balances",
        "label": "_balances",
        "source": "_balances",
        "kind": "state_variable",
        "read_spec": {
            "strategy": "getter_call",
            "target": "_balances",
            "kind": "state_variable",
            "state_variable_name": "_balances",
            "type": "mapping(address => uint256)",
            "type_kind": "mapping",
        },
        "tracking_mode": "event_plus_state",
        "event_watch": {
            "transport": "wss_logs",
            "contract_address": TOKEN_ADDRESS,
            "events": [
                {
                    "name": "Transfer",
                    "signature": "Transfer(address,address,uint256)",
                    "topic0": TRANSFER_TOPIC0,
                    "inputs": [
                        {"name": "from", "type": "address", "indexed": True},
                        {"name": "to", "type": "address", "indexed": True},
                        {"name": "value", "type": "uint256", "indexed": False},
                    ],
                    "effect_tags": {"writes": ["_allowances", "_balances", "_totalSupply"]},
                },
                {
                    "name": "Approval",
                    "signature": "Approval(address,address,uint256)",
                    "topic0": _topic0("Approval(address,address,uint256)"),
                    "inputs": [
                        {"name": "owner", "type": "address", "indexed": True},
                        {"name": "spender", "type": "address", "indexed": True},
                        {"name": "value", "type": "uint256", "indexed": False},
                    ],
                    "effect_tags": {"writes": ["_allowances", "_balances", "_totalSupply"]},
                },
                {
                    "name": "DelegateVotesChanged",
                    "signature": "DelegateVotesChanged(address,uint256,uint256)",
                    "topic0": _topic0("DelegateVotesChanged(address,uint256,uint256)"),
                    "inputs": [
                        {"name": "delegate", "type": "address", "indexed": True},
                        {"name": "previousBalance", "type": "uint256", "indexed": False},
                        {"name": "newBalance", "type": "uint256", "indexed": False},
                    ],
                    "effect_tags": {"writes": ["_allowances", "_balances", "_totalSupply"]},
                },
            ],
            "writer_functions": ["_transfer", "_approve"],
        },
        "polling_fallback": {
            "contract_address": TOKEN_ADDRESS,
            "polling_sources": ["_balances"],
            "cadence": "realtime_confirm",
            "notes": [],
        },
        "notes": [],
    }
    if authority_provenance is not None:
        tracked["authority_provenance"] = authority_provenance
    return tracked


def _fiat_token_pauser_controller() -> dict:
    """FiatTokenV2_2's ``pauser`` — a real controller variable: the plan
    proves a lowered predicate leaf gates callers on it."""
    return {
        "controller_id": "state_variable:pauser",
        "label": "pauser",
        "source": "pauser",
        "kind": "state_variable",
        "read_spec": {
            "strategy": "getter_call",
            "target": "pauser",
            "kind": "state_variable",
            "state_variable_name": "pauser",
            "type": "address",
            "type_kind": "address",
        },
        "tracking_mode": "event_plus_state",
        "event_watch": {
            "transport": "wss_logs",
            "contract_address": FIAT_TOKEN_ADDRESS,
            "events": [
                {
                    "name": "PauserChanged",
                    "signature": "PauserChanged(address)",
                    "topic0": PAUSER_CHANGED_TOPIC0,
                    "inputs": [{"name": "newAddress", "type": "address", "indexed": True}],
                    "effect_tags": {"writes": ["pauser"]},
                }
            ],
            "writer_functions": ["updatePauser"],
        },
        "polling_fallback": {
            "contract_address": FIAT_TOKEN_ADDRESS,
            "polling_sources": ["pauser"],
            "cadence": "realtime_confirm",
            "notes": [],
        },
        "notes": [],
        "authority_provenance": "caller_gate",
    }


def _plan(*controllers: dict) -> dict:
    return {
        "schema_version": "0.1",
        "contract_address": TOKEN_ADDRESS,
        "contract_name": "Fixture",
        "tracking_strategy": "event_first_with_polling_fallback",
        "tracked_controllers": list(controllers),
    }


def _transfer_log(*, block: int = 25634306) -> dict:
    return {
        "address": TOKEN_ADDRESS,
        "topics": [
            TRANSFER_TOPIC0,
            "0x" + "00" * 12 + "00" * 20,
            "0x" + "00" * 12 + "951af4267c8fbcd1c5a8c38e15b122768e44559a",
        ],
        "data": "0x" + format(22661724000000000000, "x").zfill(64),
        "blockNumber": hex(block),
        "transactionHash": "0x" + "11" * 32,
        "logIndex": "0x3",
    }


def _pauser_changed_log(*, block: int = 25634400) -> dict:
    return {
        "address": FIAT_TOKEN_ADDRESS,
        "topics": [
            PAUSER_CHANGED_TOPIC0,
            "0x" + "00" * 12 + "cd" * 20,
        ],
        "data": "0x",
        "blockNumber": hex(block),
        "transactionHash": "0x" + "22" * 32,
        "logIndex": "0x1",
    }


# ---------------------------------------------------------------------------
# Producer — the three provenance states
# ---------------------------------------------------------------------------


def test_erc20_traffic_on_enrolled_token_is_not_a_controller_claim():
    """Every signature bound to the unproven ``_balances`` slot publishes
    the neutral type. An ordinary token transfer is not a control change."""
    topics = extract_governance_topics(_plan(_erc20_balances_controller()))

    assert len(topics) == 3
    assert {t["event_type"] for t in topics} == {"state_changed:state_variable:_balances"}
    assert not any("controller_changed" in t["event_type"] for t in topics)
    # The controller_id still rides along — the neutral type drops the
    # control claim, not the identity of what was written.
    assert {t["controller_id"] for t in topics} == {"state_variable:_balances"}


def test_proven_caller_gate_target_keeps_the_controller_claim():
    """POSITIVE ARM: the plan proves ``pauser`` gates callers, so an event
    that writes it still publishes ``controller_changed``."""
    topics = extract_governance_topics(_plan(_fiat_token_pauser_controller()))

    assert len(topics) == 1
    assert topics[0]["event_type"] == "controller_changed:state_variable:pauser"


def test_call_target_provenance_does_not_earn_the_controller_claim():
    """DISCRIMINATING CONTROL: ``call_target`` is a PRESENT provenance
    value that is not the gate proof — "called, and no gate was proven".
    It must resolve exactly like an absent one."""
    topics = extract_governance_topics(_plan(_erc20_balances_controller(authority_provenance="call_target")))

    assert {t["event_type"] for t in topics} == {"state_changed:state_variable:_balances"}


def test_absent_and_call_target_agree_but_caller_gate_differs():
    """The three states of ``authority_provenance``, read straight off the
    resolver: only the proven gate mints the controller claim."""
    assert _resolve_event_type("state_variable:x") == "state_changed:state_variable:x"
    assert _resolve_event_type("state_variable:x", authority_provenance=None) == "state_changed:state_variable:x"
    assert (
        _resolve_event_type("state_variable:x", authority_provenance="call_target") == "state_changed:state_variable:x"
    )
    assert (
        _resolve_event_type("state_variable:x", authority_provenance="caller_gate")
        == "controller_changed:state_variable:x"
    )


def test_provenance_never_overrides_a_canonical_classification():
    """Steps 1 and 2 of the resolver still win over the terminal fallback
    when the event's own signature corroborates the canonical family,
    with or without the gate proof."""
    assert (
        _resolve_event_type(
            "state_variable:whatever",
            {"writes": ["owner"]},
            authority_provenance=None,
            signature="OwnershipTransferred(address,address)",
        )
        == "ownership_transferred"
    )
    assert (
        _resolve_event_type(
            "state_variable:owner",
            authority_provenance="caller_gate",
            signature="OwnerUpdated(address,address)",
        )
        == "ownership_transferred"
    )


def test_uncorroborated_canonical_claim_falls_to_the_earned_stem():
    """A canonical family type needs the event's OWN signature to
    corroborate it. Without that, writes donation and the legacy
    controller_id map fall to the terminal stem — which still honours
    the provenance three-state."""
    # Donated writes, uncorroborated name -> neutral.
    assert (
        _resolve_event_type(
            "state_variable:whatever",
            {"writes": ["owner"]},
            authority_provenance=None,
            signature="Initialized(uint8)",
        )
        == "state_changed:state_variable:whatever"
    )
    # Legacy controller_id map, uncorroborated name -> the stem earned by
    # provenance (proven gate -> controller_changed, not the canonical type).
    assert (
        _resolve_event_type(
            "state_variable:owner",
            authority_provenance="caller_gate",
            signature="Initialized(uint8)",
        )
        == "controller_changed:state_variable:owner"
    )
    # Not-determined signature (absent) cannot corroborate anything.
    assert (
        _resolve_event_type(
            "state_variable:whatever",
            {"writes": ["owner"]},
            authority_provenance=None,
        )
        == "state_changed:state_variable:whatever"
    )


def test_unclassified_spec_decodes_to_the_neutral_type():
    """A spec carrying no event_type at all was never classified — the
    decoder's own default must not invent the controller claim either."""
    spec = {
        "topic0": TRANSFER_TOPIC0,
        "signature": "Transfer(address,address,uint256)",
        "inputs": [
            {"name": "from", "type": "address", "indexed": True},
            {"name": "to", "type": "address", "indexed": True},
            {"name": "value", "type": "uint256", "indexed": False},
        ],
    }
    parsed = parse_tracked_log(_transfer_log(), spec)
    assert parsed is not None
    assert parsed["event_type"] == "state_changed"


def test_decoder_stamps_the_resolved_neutral_type_on_a_real_transfer():
    """End of the producer path: the decoded event that reaches the
    watcher's insert carries the neutral type."""
    spec = next(
        t for t in extract_governance_topics(_plan(_erc20_balances_controller())) if t["topic0"] == TRANSFER_TOPIC0
    )
    parsed = parse_tracked_log(_transfer_log(), spec)

    assert parsed is not None
    assert parsed["event_type"] == "state_changed:state_variable:_balances"
    assert parsed["to"] == "0x951af4267c8fbcd1c5a8c38e15b122768e44559a"
    assert parsed["value"] == 22661724000000000000


# ---------------------------------------------------------------------------
# Published surfaces — GET /api/protocols/{id}/events and /api/monitored-events
# ---------------------------------------------------------------------------


@pytest.fixture()
def served_rows(db_session):
    """Two MonitoredEvents built by running the real producer path over the
    two fixture plans, then inserted exactly as the watcher inserts them."""
    from db.models import MonitoredContract, MonitoredEvent, Protocol

    protocol = Protocol(name=f"prov-fixture-{uuid.uuid4().hex[:8]}")
    db_session.add(protocol)
    db_session.flush()

    rows = []
    contracts = []
    for address, plan, log in (
        (TOKEN_ADDRESS, _plan(_erc20_balances_controller()), _transfer_log()),
        (FIAT_TOKEN_ADDRESS, _plan(_fiat_token_pauser_controller()), _pauser_changed_log()),
    ):
        specs = {t["topic0"]: t for t in extract_governance_topics(plan)}
        parsed = parse_tracked_log(log, specs[log["topics"][0]])
        assert parsed is not None

        mc = MonitoredContract(
            id=uuid.uuid4(),
            address=address,
            chain="ethereum",
            protocol_id=protocol.id,
            contract_type="regular",
            monitoring_config={"tracked_topics": list(specs.values())},
            last_known_state={},
            last_scanned_block=0,
            is_active=True,
        )
        db_session.add(mc)
        db_session.flush()
        contracts.append(mc)

        event = MonitoredEvent(
            id=uuid.uuid4(),
            monitored_contract_id=mc.id,
            event_type=parsed["event_type"],
            block_number=parsed["block_number"],
            tx_hash=parsed["tx_hash"],
            log_index=parsed["log_index"],
            data={
                k: v
                for k, v in parsed.items()
                if k not in ("event_type", "block_number", "tx_hash", "log_index", "_emitter")
            },
            detected_at=datetime.now(timezone.utc),
        )
        db_session.add(event)
        rows.append(event)
    db_session.commit()

    try:
        yield {"protocol_id": protocol.id, "events": rows, "contracts": contracts}
    finally:
        for e in rows:
            db_session.delete(e)
        for mc in contracts:
            db_session.delete(mc)
        db_session.delete(protocol)
        db_session.commit()


@requires_postgres
def test_protocol_events_endpoint_serves_the_neutral_type(api_client, served_rows):
    resp = api_client.get(f"/api/protocols/{served_rows['protocol_id']}/events")
    assert resp.status_code == 200
    by_type = {e["event_type"] for e in resp.json()}

    assert "state_changed:state_variable:_balances" in by_type
    assert "controller_changed:state_variable:_balances" not in by_type
    # The earned claim is still served for the proven-gate write target.
    assert "controller_changed:state_variable:pauser" in by_type


@requires_postgres
def test_monitored_events_endpoint_serves_the_neutral_type(api_client, served_rows):
    resp = api_client.get("/api/monitored-events", params={"address": TOKEN_ADDRESS, "chain": "ethereum"})
    assert resp.status_code == 200
    body = resp.json()
    assert [e["event_type"] for e in body] == ["state_changed:state_variable:_balances"]

    # The event_type filter is a published query axis — the neutral type
    # has to be addressable by it.
    filtered = api_client.get(
        "/api/monitored-events",
        params={"event_type": "state_changed:state_variable:_balances"},
    )
    assert filtered.status_code == 200
    assert [e["id"] for e in filtered.json()] == [str(served_rows["events"][0].id)]
