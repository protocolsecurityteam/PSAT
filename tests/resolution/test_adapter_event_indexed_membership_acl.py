"""Caller-keyed boolean mapping-ACL recovery from events (FA-R2).

A truthiness read like ``allowedForwardedEigenpodCalls[msg.sender][selector]`` is a
``mapping_membership`` descriptor with a ``set``-direction hint carrying
``value_position`` but no ``value_predicate``; the adapter treats it as an implicit
``{value != 0}`` and folds latest-value-per-CALLER. Drives the real fold
(``enumerate_mapping_values``); only the HyperSync wire is stubbed.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, cast

import pytest

import services.resolution.mapping_enumerator as mapping_enumerator
from services.resolution.adapters import EvaluationContext
from services.resolution.adapters.event_indexed import (
    EventIndexedAdapter,
    _caller_event_arg_position,
    _implicit_membership_value_predicate,
)

CONTRACT = "0x789cbbe0739f1458905c9ca6d6e74f7997622a9b"
CALLER_A = "0x7835fb36a8143a014a2c381363cd1a4dee586d2a"
CALLER_B = "0xcd425f44758a08baab3c4908f3e3de5776e45d7a"


def _topic0(signature: str) -> str:
    return mapping_enumerator._event_topic0(signature)


def _indexed(addr_or_word: str) -> str:
    return "0x" + addr_or_word[2:].rjust(64, "0")


def _bool_word(value: bool) -> str:
    return "0x" + ("1".rjust(64, "0") if value else "0" * 64)


class _FakeFieldEnumMeta(type):
    _members = ("address", "topic0", "data", "block_number")

    def __iter__(cls):
        for name in cls._members:
            yield cls(name)


class _FakeFieldEnum(metaclass=_FakeFieldEnumMeta):
    def __init__(self, name: str):
        self.value = name


class _FakeHypersyncModule:
    Query = SimpleNamespace
    LogSelection = SimpleNamespace
    FieldSelection = SimpleNamespace
    LogField = _FakeFieldEnum


def _client(logs: list[Any]):
    class _C:
        async def get(self, _query):
            return SimpleNamespace(data=logs, next_block=None)

    return _C()


def _patched_value_fold(monkeypatch, logs: list[Any]) -> None:
    """Route the value fold through ``enumerate_mapping_values`` with a stubbed HyperSync
    client so the real fold runs over ``logs``; the scan floor is stubbed to a known
    block so the live fold runs (not defers) without Etherscan or the cursor table."""
    import services.resolution.creation_block_floor as floor_mod

    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "resolve_scan_floor", lambda *_a, **_k: 0)

    orig = mapping_enumerator.enumerate_mapping_values

    async def fake(contract_address, writer_specs, **kwargs):
        kwargs.pop("client", None)
        kwargs.pop("hypersync_module", None)
        return await orig(
            contract_address,
            writer_specs,
            client=_client(logs),
            hypersync_module=_FakeHypersyncModule(),
            **kwargs,
        )

    monkeypatch.setattr(mapping_enumerator, "enumerate_mapping_values", fake)
    mapping_enumerator._VALUE_CACHE.clear()


# allowedForwardedEigenpodCalls[msg.sender][selector] — caller is indexed arg 0,
# selector indexed arg 1, value (bool) in data at arg 2.
def _eigenpod_descriptor() -> dict:
    return {
        "kind": "mapping_membership",
        "storage_var": "allowedForwardedEigenpodCalls",
        "key_sources": [
            {"source": "msg_sender"},
            {"source": "parameter", "parameter_index": 1, "parameter_name": "data"},
        ],
        "enumeration_hint": [
            {
                "topic0": _topic0("UserAllowedForwardedEigenpodCallsUpdated(address,bytes4,bool)"),
                "topics_to_keys": {"1": 0, "2": 1},
                "data_to_keys": {},
                "direction": "set",
                "event_signature": "UserAllowedForwardedEigenpodCallsUpdated(address,bytes4,bool)",
                "event_name": "UserAllowedForwardedEigenpodCallsUpdated",
                "mapping_name": "allowedForwardedEigenpodCalls",
                "key_position": 1,
                "indexed_positions": [0, 1],
                "value_position": 2,
                "writer_function": "updateAllowedForwardedEigenpodCalls(address,bytes4,bool)",
            }
        ],
    }


def _eigenpod_log(caller: str, selector: str, value: bool, *, block: int, log_index: int = 0) -> SimpleNamespace:
    return SimpleNamespace(
        topics=[
            _topic0("UserAllowedForwardedEigenpodCallsUpdated(address,bytes4,bool)"),
            _indexed(caller),
            "0x" + selector[2:].ljust(64, "0"),
        ],
        data=_bool_word(value),
        block_number=block,
        log_index=log_index,
    )


def test_implicit_predicate_fires_for_caller_keyed_membership_with_value_set_hint():
    pred = _implicit_membership_value_predicate(_eigenpod_descriptor())
    assert pred == {"op": "any_nonzero", "rhs_values": [], "value_type": "uint256"}


_COMPOSE_QUEUE_DESC = {
    "kind": "mapping_membership",
    "storage_var": "composeQueue",
    "key_sources": [{"source": "msg_sender"}],
    "enumeration_hint": [
        {
            "topic0": "0x" + "ab" * 32,
            "direction": "set",
            "value_position": None,
            "key_position": 0,
            "event_signature": "ComposeSent(address)",
            "indexed_positions": [0],
        }
    ],
}


@pytest.mark.parametrize(
    "desc",
    [
        # LayerZero composeQueue: a caller-keyed data-map with no value slot stays unsupported.
        pytest.param(_COMPOSE_QUEUE_DESC, id="value-position-absent"),
        pytest.param(
            {
                **_eigenpod_descriptor(),
                "key_sources": [{"source": "parameter", "parameter_index": 0, "parameter_name": "x"}],
            },
            id="not-caller-keyed",
        ),
        pytest.param(
            {k: v for k, v in _eigenpod_descriptor().items() if k != "enumeration_hint"}, id="without-any-hint"
        ),
        pytest.param(
            {**_eigenpod_descriptor(), "value_predicate": {"op": "eq", "rhs_values": ["3"], "value_type": "uint256"}},
            id="not-overriding-explicit-value-predicate",
        ),
        # WeETH recover* RoleRegistry hasRole is an external_set, a different shape.
        pytest.param(
            {
                "kind": "external_set",
                "key_sources": [{"source": "msg_sender"}],
                "enumeration_hint": [{"topic0": "0x" + "cd" * 32, "direction": "set", "value_position": 1}],
            },
            id="external-set",
        ),
    ],
)
def test_implicit_predicate_excluded(desc):
    assert _implicit_membership_value_predicate(desc) is None


@pytest.mark.parametrize(
    "desc, hint, expected",
    [
        # caller key index 0 maps to topic index 1 -> indexed_positions[0] == event arg 0.
        pytest.param(
            _eigenpod_descriptor(),
            _eigenpod_descriptor()["enumeration_hint"][0],
            0,
            id="resolves-caller-over-inner-key",
        ),
        # Caller key in event data (not a topic): key index 0 -> data slot 0, event arg 1
        # (arg 0 is the indexed selector).
        pytest.param(
            {"kind": "mapping_membership", "storage_var": "consumers", "key_sources": [{"source": "msg_sender"}]},
            {"topics_to_keys": {}, "data_to_keys": {"0": 0}, "indexed_positions": [0], "value_position": 2},
            1,
            id="from-non-indexed-data-arg",
        ),
        pytest.param(
            {"kind": "mapping_membership", "key_sources": [{"source": "parameter", "parameter_index": 0}]},
            {"topics_to_keys": {"1": 0}, "indexed_positions": [0]},
            None,
            id="none-when-no-caller-key",
        ),
    ],
)
def test_caller_event_arg_position(desc, hint, expected):
    assert _caller_event_arg_position(desc, hint) == expected


@pytest.mark.parametrize(
    "desc, expected",
    [
        pytest.param(_eigenpod_descriptor(), 55, id="scores-caller-keyed-membership-without-value-predicate"),
        # The adapter must not claim the composeQueue shape.
        pytest.param(
            {
                "kind": "mapping_membership",
                "storage_var": "composeQueue",
                "key_sources": [{"source": "msg_sender"}],
                "enumeration_hint": [
                    {"topic0": "0x" + "ab" * 32, "direction": "set", "value_position": None, "key_position": 0}
                ],
            },
            0,
            id="zero-for-composeQueue-value-position-none",
        ),
    ],
)
def test_matches_score(desc, expected):
    assert EventIndexedAdapter.matches(desc, EvaluationContext(chain_id=1)) == expected


@pytest.mark.parametrize(
    "logs, expected_members",
    [
        pytest.param([_eigenpod_log(CALLER_A, "0x88676cad", True, block=100)], [CALLER_A], id="truthy-caller"),
        # Same caller, three selectors, all true (audited forwardEigenPodCall) -> one principal.
        pytest.param(
            [
                _eigenpod_log(CALLER_A, "0x88676cad", True, block=100, log_index=0),
                _eigenpod_log(CALLER_A, "0xf074ba62", True, block=100, log_index=1),
                _eigenpod_log(CALLER_A, "0x3f65cf19", True, block=100, log_index=2),
            ],
            [CALLER_A],
            id="multiple-selectors-fold-to-single-caller",
        ),
        pytest.param(
            [
                _eigenpod_log(CALLER_A, "0x88676cad", True, block=100),
                _eigenpod_log(CALLER_B, "0xeea9064b", True, block=200),
            ],
            [CALLER_A, CALLER_B],
            id="two-distinct-callers",
        ),
        # Added then removed (latest false) -> not a member (AvsOperatorManager admin, latest AdminUpdated 0).
        pytest.param(
            [
                _eigenpod_log(CALLER_A, "0x88676cad", True, block=100, log_index=0),
                _eigenpod_log(CALLER_A, "0x88676cad", False, block=200, log_index=0),
            ],
            [],
            id="drops-caller-whose-latest-value-is-false",
        ),
    ],
)
def test_enumerate_value_fold(monkeypatch, logs, expected_members):
    _patched_value_fold(monkeypatch, logs)
    ctx = EvaluationContext(chain_id=1, contract_address=CONTRACT)
    cap = EventIndexedAdapter().enumerate(_eigenpod_descriptor(), ctx)
    assert cap.kind == "finite_set"
    assert sorted(cap.members or []) == sorted(m.lower() for m in expected_members)


def _run(coro):
    return asyncio.run(coro)


def test_value_fold_keys_on_caller_not_inner_selector(monkeypatch):
    # With the caller-arg key override, two selectors for one caller collapse to one caller key.
    desc = _eigenpod_descriptor()
    hint = desc["enumeration_hint"][0]
    spec = {
        "mapping_name": "allowedForwardedEigenpodCalls",
        "event_signature": hint["event_signature"],
        "event_name": hint["event_name"],
        "key_position": _caller_event_arg_position(desc, hint),
        "indexed_positions": list(hint["indexed_positions"]),
        "direction": "set",
        "writer_function": hint["writer_function"],
        "value_position": hint["value_position"],
    }
    logs = [
        _eigenpod_log(CALLER_A, "0x88676cad", True, block=100, log_index=0),
        _eigenpod_log(CALLER_A, "0xf074ba62", True, block=100, log_index=1),
    ]
    result = _run(
        mapping_enumerator.enumerate_mapping_values(
            CONTRACT,
            cast(Any, [spec]),
            from_block=0,
            client=_client(logs),
            hypersync_module=_FakeHypersyncModule(),
        )
    )
    keys = {e["key"] for e in result["entries"]}
    assert keys == {CALLER_A.lower()}
