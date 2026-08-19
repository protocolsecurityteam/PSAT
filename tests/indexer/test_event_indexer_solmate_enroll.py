"""The event-log indexer enrolls Solmate RolesAuthority role events directly off
a ``canCall`` descriptor — so the under-resolution fix works even on
``predicate_trees`` materialized before the enumeration-hint pass existed (the
bytecode-keyed materialization cache won't carry the hints until rebuilt).
"""

from __future__ import annotations

from types import SimpleNamespace  # noqa: E402
from typing import Any, cast  # noqa: E402

from eth_utils.crypto import keccak  # noqa: E402

from workers.event_log_indexer import (  # noqa: E402
    _SOLMATE_ROLE_TOPICS,
    _event_address_for_descriptor,
    _is_solmate_cancall_descriptor,
)

_CANCALL_DESCRIPTOR = {
    "kind": "external_set",
    "callee_signature": "canCall(address,address,bytes4)",
    "authority_contract": {"address_source": {"source": "state_variable", "state_variable_name": "authority"}},
}
_PROTECTED = "0x" + "11" * 20  # the job's protected contract (NOT the authority)
_AUTHORITY = "0x" + "a2" * 20


def _job():
    return cast(Any, SimpleNamespace(address=_PROTECTED))


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


# F2: the Solmate enroll path resolves the authority strictly — it must never
# enroll the role events at the protected contract (job.address), which can't
# emit them.


def test_solmate_enroll_does_not_fall_back_to_job_address():
    job = _job()
    # Authority unresolved (not in ControllerValue feed) + no job fallback → None.
    assert _event_address_for_descriptor(_CANCALL_DESCRIPTOR, {}, job, {}, allow_job_fallback=False) is None


def test_generic_path_still_falls_back_to_job_address():
    # The generic enroll path (mapping events on the contract itself) keeps the
    # job.address fallback — only the Solmate authority path opts out.
    job = _job()
    assert _event_address_for_descriptor(_CANCALL_DESCRIPTOR, {}, job, {}, allow_job_fallback=True) == _PROTECTED


def test_solmate_enroll_uses_resolved_authority_when_available():
    job = _job()
    addr = _event_address_for_descriptor(
        _CANCALL_DESCRIPTOR, {}, job, {"authority": _AUTHORITY}, allow_job_fallback=False
    )
    assert addr == _AUTHORITY
