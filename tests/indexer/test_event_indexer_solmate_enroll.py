"""Enrolls directly off a ``canCall`` descriptor, so it works on trees materialized before enumeration hints existed."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest
from eth_utils.crypto import keccak

from workers.event_log_indexer import (
    _is_solmate_cancall_descriptor,
)

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


# F2: never at the protected contract, which can't emit role events.
