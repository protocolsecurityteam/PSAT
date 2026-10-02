"""A canonical event_type needs the event's own signature to corroborate it; a multi-write emitter's donated slots
are not evidence. Fixtures are persisted RoleRegistry and EtherfiL1SyncPoolETH shapes.
"""

from __future__ import annotations

from eth_utils.crypto import keccak

from services.monitoring.event_topics import (
    _event_corroborates,
    _resolve_event_type,
    extract_governance_topics,
    parse_tracked_log,
)


def _topic0(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()


ROLE_REGISTRY = "0x3b44a093b9736af765f98f3245998f63bc757970"
SYNC_POOL = "0x5d310451276d28a90cc6910449052d29a41e3abd"


def _event(name: str, signature: str, inputs: list[dict], writes: list[str]) -> dict:
    return {
        "name": name,
        "signature": signature,
        "topic0": _topic0(signature),
        "inputs": inputs,
        "effect_tags": {"writes": writes},
    }


def _plan(address: str, *controllers: dict) -> dict:
    return {
        "schema_version": "0.1",
        "contract_address": address,
        "contract_name": "Fixture",
        "tracking_strategy": "event_first_with_polling_fallback",
        "tracked_controllers": list(controllers),
    }


def _role_registry_owner_controller() -> dict:
    """``initialize()`` writes the owner slots and emits ``Initialized(uint8)``, so that event carries them in its
    donated set.
    """
    writes = ["_initialized", "_initializing", "_owner", "_pendingOwner"]
    return {
        "controller_id": "state_variable:_owner",
        "label": "_owner",
        "source": "_owner",
        "kind": "state_variable",
        "tracking_mode": "event_plus_state",
        "event_watch": {
            "transport": "wss_logs",
            "contract_address": ROLE_REGISTRY,
            "events": [
                _event(
                    "Initialized",
                    "Initialized(uint8)",
                    [{"name": "version", "type": "uint8", "indexed": False}],
                    writes,
                )
            ],
            "writer_functions": ["initialize"],
        },
        "notes": [],
    }


def test_uncorroborated_event_fills_no_semantic_keys():
    """The old false type aliased unrelated args into ``new_owner``."""
    spec = extract_governance_topics(_plan(ROLE_REGISTRY, _role_registry_owner_controller()))[0]
    log = {
        "address": ROLE_REGISTRY,
        "topics": [spec["topic0"]],
        "data": "0x" + "01".zfill(64),
        "blockNumber": "0x186ead7",
        "transactionHash": "0x" + "ab" * 32,
        "logIndex": "0x0",
    }
    parsed = parse_tracked_log(log, spec)

    assert parsed is not None
    assert parsed["event_type"] == "initialized"
    assert "old_owner" not in parsed
    assert "new_owner" not in parsed
    assert parsed["version"] == 1


def test_corroborated_families_keep_their_canonical_types():
    cases = [
        (
            "AuthorityUpdated(address,address)",
            [
                {"name": "user", "type": "address", "indexed": True},
                {"name": "newAuthority", "type": "address", "indexed": True},
            ],
            ["authority"],
            "authority_updated",
        ),
        (
            "OwnerUpdated(address,address)",
            [
                {"name": "user", "type": "address", "indexed": True},
                {"name": "newOwner", "type": "address", "indexed": True},
            ],
            ["owner"],
            "ownership_transferred",
        ),
        (
            "OwnershipTransferRequested(address,address)",
            [
                {"name": "from", "type": "address", "indexed": True},
                {"name": "to", "type": "address", "indexed": True},
            ],
            ["pendingOwner"],
            "ownership_transfer_started",
        ),
        (
            "Initialized(uint64)",
            [{"name": "version", "type": "uint64", "indexed": False}],
            ["_initialized"],
            "initialized",
        ),
        (
            "ThresholdSet(uint256)",
            [{"name": "threshold", "type": "uint256", "indexed": False}],
            ["threshold"],
            "threshold_changed",
        ),
        (
            "CommitOwnership(address)",
            [{"name": "admin", "type": "address", "indexed": False}],
            ["future_admin"],
            "admin_changed",
        ),
    ]
    for signature, inputs, writes, expected in cases:
        name = signature.split("(", 1)[0]
        plan = _plan(
            ROLE_REGISTRY,
            {
                "controller_id": f"state_variable:{writes[0]}",
                "label": writes[0],
                "source": writes[0],
                "kind": "state_variable",
                "tracking_mode": "event_plus_state",
                "event_watch": {
                    "transport": "wss_logs",
                    "contract_address": ROLE_REGISTRY,
                    "events": [_event(name, signature, inputs, writes)],
                    "writer_functions": [],
                },
                "notes": [],
            },
        )
        topics = extract_governance_topics(plan)
        assert len(topics) == 1, signature
        assert topics[0]["event_type"] == expected, signature


def test_corroboration_arg_shape_is_required():
    assert not _event_corroborates("ownership_transferred", "OwnerFeeSet(uint256)")
    assert _event_corroborates("ownership_transferred", "OwnerFeeSet(address)")
    assert _event_corroborates("threshold_changed", "ThresholdSet(uint256)")
    assert not _event_corroborates("threshold_changed", "ThresholdSet(address)")
    assert _event_corroborates("initialized", "Initialized()")


def test_absent_signature_is_not_determined_and_cannot_corroborate():
    assert not _event_corroborates("ownership_transferred", None)
    assert not _event_corroborates("ownership_transferred", "")
    assert not _event_corroborates("initialized", None)


def test_initializer_flag_fallback_is_also_gated():
    assert (
        _resolve_event_type("state_variable:x", {"is_initializer": True, "writes": ["x"]}, signature="FeeSet(address)")
        == "state_changed:state_variable:x"
    )
    assert (
        _resolve_event_type(
            "state_variable:x", {"is_initializer": True, "writes": ["x"]}, signature="Initialized(uint8)"
        )
        == "initialized"
    )
    assert (
        _resolve_event_type("state_variable:x", {"delegates": True, "writes": ["x"]}, signature="FeeSet(address)")
        == "state_changed:state_variable:x"
    )
    assert (
        _resolve_event_type("state_variable:x", {"delegates": True, "writes": ["x"]}, signature="Upgraded(address)")
        == "upgraded"
    )
