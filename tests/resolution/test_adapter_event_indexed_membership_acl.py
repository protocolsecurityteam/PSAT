"""Caller-keyed boolean mapping-ACL recovery from events (FA-R2).

A leaf like ``allowedForwardedEigenpodCalls[msg.sender][selector]`` read for
truthiness is emitted as a ``mapping_membership`` descriptor with a
``set``-direction enumeration_hint carrying a ``value_position`` but no
``value_predicate``. The adapter treats the truthy read as an implicit
``{value != 0}`` predicate and folds latest-value-per-CALLER, keeping callers
whose latest stored value is nonzero.

These drive the production adapter through the real value-aware fold
(``enumerate_mapping_values``); only the HyperSync wire (``client.get``) is
stubbed, matching the on-chain log shapes of the audited run.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, cast

import services.resolution.mapping_enumerator as mapping_enumerator  # noqa: E402
from services.resolution.adapters import AdapterRegistry, EvaluationContext  # noqa: E402
from services.resolution.adapters.event_indexed import (  # noqa: E402
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
    """Route the adapter's value fold through ``enumerate_mapping_values`` with
    a stubbed HyperSync client, so the real latest-value-per-key fold runs over
    ``logs``. Only the wire is replaced; the scan-floor lookup is stubbed to a
    known floor so the live fold runs (rather than deferring) without reaching
    Etherscan or the cursor table offline."""
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


def test_implicit_predicate_excluded_when_value_position_absent():
    # LayerZero composeQueue (sendCompose): a caller-keyed data-map with no
    # value slot must stay unsupported here.
    desc = {
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
    assert _implicit_membership_value_predicate(desc) is None


def test_implicit_predicate_excluded_when_not_caller_keyed():
    desc = _eigenpod_descriptor()
    desc["key_sources"] = [{"source": "parameter", "parameter_index": 0, "parameter_name": "x"}]
    assert _implicit_membership_value_predicate(desc) is None


def test_implicit_predicate_excluded_without_any_hint():
    desc = _eigenpod_descriptor()
    del desc["enumeration_hint"]
    assert _implicit_membership_value_predicate(desc) is None


def test_implicit_predicate_not_overriding_explicit_value_predicate():
    desc = _eigenpod_descriptor()
    desc["value_predicate"] = {"op": "eq", "rhs_values": ["3"], "value_type": "uint256"}
    assert _implicit_membership_value_predicate(desc) is None


def test_implicit_predicate_excluded_for_external_set():
    # WeETH recover* RoleRegistry hasRole is an external_set, a different shape.
    desc = {
        "kind": "external_set",
        "key_sources": [{"source": "msg_sender"}],
        "enumeration_hint": [{"topic0": "0x" + "cd" * 32, "direction": "set", "value_position": 1}],
    }
    assert _implicit_membership_value_predicate(desc) is None


def test_caller_event_arg_position_resolves_caller_over_inner_key():
    desc = _eigenpod_descriptor()
    hint = desc["enumeration_hint"][0]
    # caller key index 0 maps to topic index 1 → indexed_positions[0] == event arg 0.
    assert _caller_event_arg_position(desc, hint) == 0


def test_caller_event_arg_position_from_non_indexed_data_arg():
    # Caller key carried in event data (not a topic): caller key index 0 maps
    # to data slot 0, event arg position 1 (arg 0 is the indexed selector).
    desc = {
        "kind": "mapping_membership",
        "storage_var": "consumers",
        "key_sources": [{"source": "msg_sender"}],
    }
    hint = {
        "topics_to_keys": {},
        "data_to_keys": {"0": 0},
        "indexed_positions": [0],
        "value_position": 2,
    }
    assert _caller_event_arg_position(desc, hint) == 1


def test_caller_event_arg_position_none_when_no_caller_key():
    desc = {"kind": "mapping_membership", "key_sources": [{"source": "parameter", "parameter_index": 0}]}
    hint = {"topics_to_keys": {"1": 0}, "indexed_positions": [0]}
    assert _caller_event_arg_position(desc, hint) is None


def test_matches_scores_caller_keyed_membership_without_value_predicate():
    score = EventIndexedAdapter.matches(_eigenpod_descriptor(), EvaluationContext(chain_id=1))
    assert score == 55


def test_matches_zero_for_composeQueue_value_position_none():
    desc = {
        "kind": "mapping_membership",
        "storage_var": "composeQueue",
        "key_sources": [{"source": "msg_sender"}],
        "enumeration_hint": [
            {"topic0": "0x" + "ab" * 32, "direction": "set", "value_position": None, "key_position": 0}
        ],
    }
    assert EventIndexedAdapter.matches(desc, EvaluationContext(chain_id=1)) == 0


def test_matches_zero_for_no_hint_admins_membership():
    desc = {
        "kind": "mapping_membership",
        "storage_var": "admins",
        "key_sources": [{"source": "msg_sender"}],
    }
    assert EventIndexedAdapter.matches(desc, EvaluationContext(chain_id=1)) == 0


def test_registry_picks_event_indexed_for_caller_keyed_membership(monkeypatch):
    registry = AdapterRegistry()
    registry.register(EventIndexedAdapter)
    picked = registry.pick(_eigenpod_descriptor(), EvaluationContext(chain_id=1, contract_address=CONTRACT))
    assert picked is EventIndexedAdapter


def test_enumerate_recovers_truthy_caller(monkeypatch):
    # Single caller, value=true → recovered.
    logs = [_eigenpod_log(CALLER_A, "0x88676cad", True, block=100)]
    _patched_value_fold(monkeypatch, logs)
    ctx = EvaluationContext(chain_id=1, contract_address=CONTRACT)
    cap = EventIndexedAdapter().enumerate(_eigenpod_descriptor(), ctx)
    assert cap.kind == "finite_set"
    assert sorted(cap.members or []) == [CALLER_A.lower()]


def test_enumerate_folds_multiple_selectors_to_single_caller(monkeypatch):
    # Same caller, three selectors, all true (the audited forwardEigenPodCall
    # shape) → exactly one principal.
    logs = [
        _eigenpod_log(CALLER_A, "0x88676cad", True, block=100, log_index=0),
        _eigenpod_log(CALLER_A, "0xf074ba62", True, block=100, log_index=1),
        _eigenpod_log(CALLER_A, "0x3f65cf19", True, block=100, log_index=2),
    ]
    _patched_value_fold(monkeypatch, logs)
    ctx = EvaluationContext(chain_id=1, contract_address=CONTRACT)
    cap = EventIndexedAdapter().enumerate(_eigenpod_descriptor(), ctx)
    assert cap.kind == "finite_set"
    assert sorted(cap.members or []) == [CALLER_A.lower()]


def test_enumerate_recovers_two_distinct_callers(monkeypatch):
    logs = [
        _eigenpod_log(CALLER_A, "0x88676cad", True, block=100),
        _eigenpod_log(CALLER_B, "0xeea9064b", True, block=200),
    ]
    _patched_value_fold(monkeypatch, logs)
    ctx = EvaluationContext(chain_id=1, contract_address=CONTRACT)
    cap = EventIndexedAdapter().enumerate(_eigenpod_descriptor(), ctx)
    assert cap.kind == "finite_set"
    assert sorted(cap.members or []) == sorted([CALLER_A.lower(), CALLER_B.lower()])


def test_enumerate_drops_caller_whose_latest_value_is_false(monkeypatch):
    # Added then removed (latest value=false) → not a member. Mirrors the
    # AvsOperatorManager admin whose latest AdminUpdated value is 0.
    logs = [
        _eigenpod_log(CALLER_A, "0x88676cad", True, block=100, log_index=0),
        _eigenpod_log(CALLER_A, "0x88676cad", False, block=200, log_index=0),
    ]
    _patched_value_fold(monkeypatch, logs)
    ctx = EvaluationContext(chain_id=1, contract_address=CONTRACT)
    cap = EventIndexedAdapter().enumerate(_eigenpod_descriptor(), ctx)
    assert cap.kind == "finite_set"
    assert (cap.members or []) == []


def test_end_to_end_and_tree_recovers_membership_and_keeps_hasrole_external(monkeypatch):
    # AND[ membership(allowedForwardedEigenpodCalls), hasRole(...) ] — the
    # membership leaf resolves to the caller set and the roleRegistry.hasRole
    # sibling stays external_check_only (it is NOT the broken leaf). Pre-fix the
    # membership leaf is no_adapter and absorbs the whole AND.
    from services.resolution.predicate_evaluator import evaluate_tree_with_registry

    tree = {
        "op": "AND",
        "children": [
            {
                "op": "LEAF",
                "leaf": {
                    "kind": "membership",
                    "operator": "truthy",
                    "authority_role": "caller_authority",
                    "operands": [{"source": "msg_sender"}],
                    "set_descriptor": _eigenpod_descriptor(),
                },
            },
            {
                "op": "LEAF",
                "leaf": {
                    "kind": "external_bool",
                    "operator": "truthy",
                    "authority_role": "delegated_authority",
                    "callee_state_mutability": "view",
                    "callee_signature": "hasRole(bytes32,address)",
                    "expression": "hasRole(...)",
                    "operands": [{"source": "msg_sender"}],
                    "set_descriptor": {
                        "kind": "external_set",
                        "key_sources": [{"source": "msg_sender"}],
                        "authority_contract": {
                            "address_source": {"source": "state_variable", "state_variable_name": "roleRegistry"}
                        },
                        "callee_function": "hasRole",
                        "callee_signature": "hasRole(bytes32,address)",
                        "callee_selector": "0x91d14854",
                    },
                },
            },
        ],
    }
    logs = [_eigenpod_log(CALLER_A, "0x88676cad", True, block=100)]
    _patched_value_fold(monkeypatch, logs)
    registry = AdapterRegistry()
    registry.register(EventIndexedAdapter)
    cap = evaluate_tree_with_registry(
        cast(Any, tree), registry, EvaluationContext(chain_id=1, contract_address=CONTRACT)
    )

    assert cap.kind == "AND"
    children = cap.children or []
    finite = [c for c in children if c.kind == "finite_set"]
    external = [c for c in children if c.kind == "external_check_only"]
    assert len(finite) == 1
    assert sorted(finite[0].members or []) == [CALLER_A.lower()]
    assert len(external) == 1
    assert external[0].check is not None
    assert external[0].check.extra.get("callee_signature") == "hasRole(bytes32,address)"
    assert cap.unsupported_reason is None


def test_pre_fix_membership_leaf_absorbs_and(monkeypatch):
    # With the implicit predicate neutralized the membership leaf declines as
    # no_adapter and absorbs the AND (the bug this fix removes).
    import services.resolution.adapters.event_indexed as ei
    from services.resolution.predicate_evaluator import evaluate_tree_with_registry

    monkeypatch.setattr(ei, "_implicit_membership_value_predicate", lambda d: None)
    tree = {
        "op": "AND",
        "children": [
            {
                "op": "LEAF",
                "leaf": {
                    "kind": "membership",
                    "operator": "truthy",
                    "authority_role": "caller_authority",
                    "operands": [{"source": "msg_sender"}],
                    "set_descriptor": _eigenpod_descriptor(),
                },
            },
            {
                "op": "LEAF",
                "leaf": {
                    "kind": "equality",
                    "operator": "eq",
                    "authority_role": "caller_authority",
                    "operands": [
                        {"source": "msg_sender"},
                        {"source": "state_variable", "state_variable_name": "_owner"},
                    ],
                },
            },
        ],
    }
    registry = AdapterRegistry()
    registry.register(ei.EventIndexedAdapter)
    cap = evaluate_tree_with_registry(
        cast(Any, tree), registry, EvaluationContext(chain_id=1, contract_address=CONTRACT)
    )
    assert cap.kind == "unsupported"
    assert "no_adapter" in (cap.unsupported_reason or "")


def _run(coro):
    return asyncio.run(coro)


def test_resolve_scan_floor_caches_per_address(monkeypatch):
    # The floor memoizes per (address, chain) so a multi-key fold or sibling
    # functions never issue duplicate Etherscan lookups.
    import services.resolution.creation_block_floor as floor_mod

    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "_floor_from_cursor", lambda *_a, **_k: None)
    calls: list[str] = []

    def fake_lookup(addr, **_k):
        calls.append(addr)
        return 6_000_000

    monkeypatch.setattr(floor_mod, "get_contract_creation_block", fake_lookup)
    addr = "0x" + "ab" * 20
    assert floor_mod.resolve_scan_floor(addr, 1) == 6_000_000 - 1
    assert floor_mod.resolve_scan_floor(addr, 1) == 6_000_000 - 1
    assert calls == [addr]  # second call served from cache


def test_resolve_scan_floor_prefers_durable_cursor(monkeypatch):
    # A durable cursor floor is preferred over an Etherscan call (no rate limit).
    import services.resolution.creation_block_floor as floor_mod

    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "_floor_from_cursor", lambda *_a, **_k: 5_000_000)
    monkeypatch.setattr(
        floor_mod,
        "get_contract_creation_block",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("cursor floor must win, no Etherscan call")),
    )
    assert floor_mod.resolve_scan_floor("0x" + "cd" * 20, 1) == 5_000_000


def test_resolve_scan_floor_defers_on_unknown(monkeypatch):
    # No cursor + no creation block → DEFER (None), never fail-open to 0.
    import services.resolution.creation_block_floor as floor_mod

    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(floor_mod, "_floor_from_cursor", lambda *_a, **_k: None)
    monkeypatch.setattr(floor_mod, "get_contract_creation_block", lambda *_a, **_k: None)
    assert floor_mod.resolve_scan_floor("0x" + "ab" * 20, 1) is None


def test_resolve_scan_floor_none_for_zero_or_missing_address(monkeypatch):
    import services.resolution.creation_block_floor as floor_mod

    floor_mod.clear_scan_floor_cache()
    monkeypatch.setattr(
        floor_mod,
        "_floor_from_cursor",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("must not query for zero/invalid")),
    )
    assert floor_mod.resolve_scan_floor("0x" + "0" * 40, 1) is None
    assert floor_mod.resolve_scan_floor(None, 1) is None
    assert floor_mod.resolve_scan_floor("not-an-address", 1) is None


def test_value_fold_keys_on_caller_not_inner_selector(monkeypatch):
    # Direct fold check: with the caller-arg key override, two selectors for one
    # caller collapse to a single caller key (not two selector keys).
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
