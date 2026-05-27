"""The event-log indexer enrolls Solmate RolesAuthority role events directly off
a ``canCall`` descriptor — so the under-resolution fix works even on
``predicate_trees`` materialized before the enumeration-hint pass existed (the
bytecode-keyed materialization cache won't carry the hints until rebuilt).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eth_utils.crypto import keccak  # noqa: E402

from workers.event_log_indexer import (  # noqa: E402
    _SOLMATE_ROLE_TOPICS,
    _is_solmate_cancall_descriptor,
)


def test_recognizes_cancall_by_signature():
    assert _is_solmate_cancall_descriptor(
        {"kind": "external_set", "callee_signature": "canCall(address,address,bytes4)"}
    )


def test_recognizes_cancall_by_selector():
    selector = "0x" + keccak(text="canCall(address,address,bytes4)").hex()[:8]
    assert _is_solmate_cancall_descriptor({"kind": "external_set", "callee_selector": selector})


def test_rejects_non_cancall_external_set():
    assert not _is_solmate_cancall_descriptor(
        {"kind": "external_set", "callee_signature": "permitted(address,bytes32)"}
    )


def test_rejects_non_external_set_descriptor():
    assert not _is_solmate_cancall_descriptor(
        {"kind": "mapping_membership", "callee_signature": "canCall(address,address,bytes4)"}
    )


def test_role_topics_are_the_three_solmate_events():
    assert _SOLMATE_ROLE_TOPICS == [
        "0x" + keccak(text="RoleCapabilityUpdated(uint8,address,bytes4,bool)").hex(),
        "0x" + keccak(text="PublicCapabilityUpdated(address,bytes4,bool)").hex(),
        "0x" + keccak(text="UserRoleUpdated(address,uint8,bool)").hex(),
    ]
