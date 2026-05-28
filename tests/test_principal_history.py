from __future__ import annotations

import json
from pathlib import Path

from eth_utils.crypto import keccak

from services.policy.principal_history import _external_authority_checks, build_role_authority_history

AUTHORITY = "0x" + "aa" * 20
TARGET = "0x" + "bb" * 20
USER = "0x" + "cc" * 20
SELECTOR = "0x12345678"
_SOLMATE_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "solmate"


def _topic(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()


def _address_topic(address: str) -> str:
    return "0x" + address[2:].rjust(64, "0")


def _uint_topic(value: int) -> str:
    return "0x" + hex(value)[2:].rjust(64, "0")


def _bytes4_topic(selector: str) -> str:
    return "0x" + selector[2:].ljust(64, "0")


def _bool_word(value: bool) -> str:
    return "0x" + ("1" if value else "0").rjust(64, "0")


def _log(topic0: str, topics: list[str], enabled: bool, block: int, log_index: int) -> dict:
    return {
        "blockNumber": hex(block),
        "transactionIndex": "0x0",
        "logIndex": hex(log_index),
        "transactionHash": "0x" + f"{block:064x}",
        "topics": [topic0, *topics],
        "data": _bool_word(enabled),
    }


def test_role_authority_history_uses_event_shapes_not_names():
    """The history reducer keys off indexed ABI shape, not event names."""
    abi = [
        {
            "type": "event",
            "name": "WhateverA",
            "inputs": [
                {"type": "address", "indexed": True},
                {"type": "uint8", "indexed": True},
                {"type": "bool", "indexed": False},
            ],
        },
        {
            "type": "event",
            "name": "WhateverB",
            "inputs": [
                {"type": "uint8", "indexed": True},
                {"type": "address", "indexed": True},
                {"type": "bytes4", "indexed": True},
                {"type": "bool", "indexed": False},
            ],
        },
        {
            "type": "event",
            "name": "WhateverC",
            "inputs": [
                {"type": "address", "indexed": True},
                {"type": "bytes4", "indexed": True},
                {"type": "bool", "indexed": False},
            ],
        },
    ]
    user_role_topic = _topic("WhateverA(address,uint8,bool)")
    role_cap_topic = _topic("WhateverB(uint8,address,bytes4,bool)")
    public_cap_topic = _topic("WhateverC(address,bytes4,bool)")

    logs_by_topic = {
        user_role_topic: [
            _log(user_role_topic, [_address_topic(USER), _uint_topic(5)], True, 12, 0),
            _log(user_role_topic, [_address_topic(USER), _uint_topic(5)], False, 20, 0),
            _log(user_role_topic, [_address_topic(USER), _uint_topic(5)], True, 25, 0),
        ],
        role_cap_topic: [
            _log(role_cap_topic, [_uint_topic(5), _address_topic(TARGET), _bytes4_topic(SELECTOR)], True, 10, 0),
            _log(role_cap_topic, [_uint_topic(5), _address_topic(TARGET), _bytes4_topic(SELECTOR)], False, 30, 0),
        ],
        public_cap_topic: [],
    }

    payload = build_role_authority_history(
        authority_address=AUTHORITY,
        chain_id=1,
        functions={(TARGET, SELECTOR): "pause()"},
        abi=abi,
        logs_by_topic=logs_by_topic,
    )

    assert payload["source"]["status"] == "ok"
    assert payload["source"]["event_topics"] == {
        "user_role": user_role_topic,
        "role_capability": role_cap_topic,
        "public_capability": public_cap_topic,
    }

    permissions = payload["function_permissions"]
    assert len(permissions) == 2
    assert permissions[0]["function"] == "pause()"
    assert permissions[0]["principal"] == USER
    assert permissions[0]["roles"] == [5]
    assert permissions[0]["granted_at_block"] == 12
    assert permissions[0]["revoked_at_block"] == 20
    assert permissions[0]["status"] == "revoked"
    assert permissions[1]["granted_at_block"] == 25
    assert permissions[1]["revoked_at_block"] == 30

    role_intervals = payload["role_membership"]
    assert [item["status"] for item in role_intervals] == ["revoked", "active"]
    assert role_intervals[1]["principal"] == USER
    assert role_intervals[1]["role"] == 5


def test_external_authority_checks_uses_canonical_selector_for_contract_type_params():
    # The predicate-tree key is Slither's full_name ``addAsset(ERC20)``, but the
    # RolesAuthority ``RoleCapabilityUpdated`` event the timeline replays against
    # carries the canonical EVM selector ``addAsset(address)`` (0x298410e5), NOT
    # keccak("addAsset(ERC20)") (0x4fdd72aa). A non-canonical selector here never
    # matches the on-chain event, so the contract-type-param function would show
    # no controller in the capability timeline (the canCall selector bug).
    data = json.loads((_SOLMATE_FIXTURES / "teller_predicate_trees.json").read_text())
    checks = _external_authority_checks(
        contract_address=data["contract"],
        predicate_trees={"trees": {"addAsset(ERC20)": data["trees"]["addAsset(ERC20)"]}},
        state_var_values={"authority": "0x3994741a5b29c60d0ab318de1024f9256fe959dc"},
    )
    assert len(checks) == 1
    assert checks[0]["function"] == "addAsset(ERC20)"
    # Canonical keccak("addAsset(address)") — the real msg.sig the event keys on.
    assert checks[0]["selector"] == "0x298410e5"
    assert checks[0]["selector"] != "0x4fdd72aa"
