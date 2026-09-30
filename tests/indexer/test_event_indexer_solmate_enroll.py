"""The event-log indexer enrolls Solmate RolesAuthority role events directly off a ``canCall`` descriptor,
so it works on ``predicate_trees`` materialized before the enumeration-hint pass existed (the bytecode-keyed cache lacks
the hints)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest
from eth_utils.crypto import keccak

from workers.event_log_indexer import (
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


_CANCALL_SIGNATURE = "canCall(address,address,bytes4)"


@pytest.mark.parametrize(
    "descriptor, expected",
    [
        pytest.param({"kind": "external_set", "callee_signature": _CANCALL_SIGNATURE}, True, id="cancall-by-signature"),
        pytest.param(
            {"kind": "external_set", "callee_selector": "0x" + keccak(text=_CANCALL_SIGNATURE).hex()[:8]},
            True,
            id="cancall-by-selector",
        ),
        pytest.param(
            {"kind": "external_set", "callee_signature": "permitted(address,bytes32)"},
            False,
            id="rejects-non-cancall-external-set",
        ),
        pytest.param(
            {"kind": "mapping_membership", "callee_signature": _CANCALL_SIGNATURE},
            False,
            id="rejects-non-external-set-descriptor",
        ),
    ],
)
def test_is_solmate_cancall_descriptor(descriptor, expected):
    assert _is_solmate_cancall_descriptor(descriptor) is expected


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
