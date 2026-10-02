"""Unit-level adversarial cases for member-witness, writer-hygiene,
and member-projection qualification.

The corpus test (``test_witness_corpus_completeness``) proves the whole derivation on compiled
Solidity; these pin judgements at shapes hard to reach from source: an OR-shaped gate, a
struct whose members are not word-projectable, an ambiguous correspondence.
"""

from __future__ import annotations

import pytest

from services.monitoring.event_topics import (
    WITNESS_TIER_ACTIVITY,
    WITNESS_TIER_HINT,
    extract_governance_topics,
    member_witness_mapping_var,
)
from services.monitoring.polling_plan import (
    _is_poll_decodable,
    _member_word_index,
    project_entry_return,
)
from services.static.contract_analysis_pipeline.tracking import (
    _writer_survives_hygiene,
)
from services.static.contract_analysis_pipeline.writer_openness import (
    openness_of_write_paths,
    restricted_function_signatures,
)
from utils.scoring_status import OPENNESS_NOT_DETERMINED, OPENNESS_RESTRICTED


def _leaf(**kwargs):
    leaf = {
        "kind": "equality",
        "operator": "eq",
        "authority_role": "caller_authority",
        "operands": [
            {"source": "msg_sender"},
            {"source": "state_variable", "state_variable_name": "owner"},
        ],
    }
    leaf.update(kwargs)
    return {"op": "LEAF", "leaf": leaf}


_OWNER_GATE = _leaf()
_BUSINESS = _leaf(authority_role="business")
# A cofinite denylist admits every unnamed address, yet carries an authority role.
_DENYLIST = _leaf(
    kind="membership",
    operator="falsy",
    operands=[],
    set_descriptor={"kind": "mapping_membership", "storage_var": "denied", "key_sources": [{"source": "msg_sender"}]},
)


def _trees(**named):
    return {"schema_version": "semantic", "trees": named}


@pytest.mark.parametrize(
    "tree,restricted",
    [
        (_OWNER_GATE, True),
        (_BUSINESS, False),
        (_DENYLIST, False),
        ({"op": "AND", "children": [_BUSINESS, _OWNER_GATE]}, True),
        ({"op": "OR", "children": [_OWNER_GATE, _BUSINESS]}, False),
        ({"op": "OR", "children": [_OWNER_GATE, _OWNER_GATE]}, True),
        ({"op": "OR", "children": [_OWNER_GATE, _DENYLIST]}, False),
        ({"op": "AND", "children": []}, False),
        ({"op": "LEAF", "leaf": None}, False),
    ],
)
def test_restriction_requires_every_path_to_pass_a_gate(tree, restricted):
    assert ("f()" in restricted_function_signatures(_trees(**{"f()": tree}))) is restricted


def test_a_value_movement_call_is_not_a_gate():
    """It moves the caller's own assets."""
    leaf = _leaf(
        kind="external_bool",
        operator="truthy",
        authority_role="delegated_authority",
        callee_state_mutability="nonview",
        gate_kind="require",
        callee_signature="transferFrom(address,address,uint256)",
        operands=[{"source": "msg_sender"}],
    )
    assert restricted_function_signatures(_trees(**{"f()": leaf})) == frozenset()


def test_a_function_without_a_tree_is_not_determined():
    assert restricted_function_signatures(None) == frozenset()
    assert restricted_function_signatures({"schema_version": "semantic", "error": "boom"}) == frozenset()


def test_one_unrestricted_path_demotes_the_event():
    restricted = frozenset({"a()", "b()"})
    assert openness_of_write_paths({"a()"}, {"a()"}, restricted) == OPENNESS_RESTRICTED
    assert openness_of_write_paths({"a()"}, {"a()", "b()"}, restricted) == OPENNESS_RESTRICTED
    assert openness_of_write_paths({"a()", "c()"}, {"a()", "c()"}, restricted) == OPENNESS_NOT_DETERMINED
    # This arm survives an emitter set the IR walk couldn't complete.
    assert openness_of_write_paths({"a()"}, {"a()", "c()"}, restricted) == OPENNESS_NOT_DETERMINED
    assert openness_of_write_paths(set(), {"a()"}, restricted) == OPENNESS_NOT_DETERMINED
    assert openness_of_write_paths({"a()"}, set(), restricted) == OPENNESS_NOT_DETERMINED


# ---------------------------------------------------------------------------
# Writer hygiene
# ---------------------------------------------------------------------------


def _fact(var="s", member=None, hygiene="normal", origin: str | None = "body"):
    return {
        "var": var,
        "member_path": list(member) if member else [],
        "granularity": "member" if member else "var",
        "hygiene_class": hygiene,
        "origin": origin,
    }


def _guard_write(var="s"):
    return _fact(var=var, hygiene="reentrancy_guard", origin="guard")


_IR_PROVEN = frozenset({"s"})


@pytest.mark.parametrize(
    "facts,member_path,survives",
    [
        (None, None, True),
        ([], None, True),
        ([_fact(var="other")], None, True),
        ([_guard_write()], None, False),
        ([_guard_write(), _fact()], None, True),
        # The class is variable-granular; the origin is not.
        ([_fact(hygiene="reentrancy_guard", origin="body")], None, True),
        ([_fact(hygiene="reentrancy_guard", origin=None)], None, True),
        ([_fact(member=["b"])], ("a",), False),
        ([_fact(member=["a"])], ("a",), True),
        ([_fact()], ("a",), True),
    ],
)
def test_writer_hygiene_subtracts_only_what_is_proven(facts, member_path, survives):
    assert _writer_survives_hygiene(facts, "s", member_path, _IR_PROVEN) is survives


def test_the_latch_class_alone_subtracts_nothing():
    """The name fallback has no IR behind it; the drop needs the IR-proven var and the modifier's own write."""
    guard = [_guard_write()]
    assert _writer_survives_hygiene(guard, "s", None, frozenset()) is True
    assert _writer_survives_hygiene(guard, "s", None, _IR_PROVEN) is False

    admin_setter = [_fact(hygiene="reentrancy_guard", origin="body")]
    assert _writer_survives_hygiene(admin_setter, "s", None, _IR_PROVEN) is True


def test_the_opaque_set_reads_both_shapes_the_artifact_records():
    from services.static.contract_analysis_pipeline.tracking import _unattributable_write_functions

    effects = {
        "functions": {
            "asm()": {"assembly_state_access": True, "sinks": []},
            "dc()": {"assembly_state_access": False, "sinks": [{"kind": "delegatecall", "target": "impl"}]},
            "plain()": {"assembly_state_access": False, "sinks": [{"kind": "state_write", "target": "m"}]},
            "call()": {"assembly_state_access": False, "sinks": [{"kind": "external_call", "target": "t"}]},
        }
    }
    assert _unattributable_write_functions(effects) == frozenset({"asm()", "dc()"})
    assert _unattributable_write_functions(None) == frozenset()


# ---------------------------------------------------------------------------
# Member projection
# ---------------------------------------------------------------------------


def _read_spec(components, member=("a",)):
    return {
        "strategy": "getter_call",
        "target": "parent",
        "state_variable_name": "parent",
        "type": "address",
        "type_kind": "address",
        "member_path": list(member),
        "components": components,
    }


_ADDRESS = {"name": "a", "type": "address", "abi_type": "address", "type_kind": "address"}
_UINT = {"name": "n", "type": "uint96", "abi_type": "uint96", "type_kind": "primitive"}


@pytest.mark.parametrize(
    "components,member,index",
    [
        ([_ADDRESS, _UINT], ("a",), 0),
        ([_UINT, _ADDRESS], ("a",), 1),
        # A dynamic member puts an offset in the head.
        ([_ADDRESS, {"name": "s", "type": "string", "abi_type": "string", "type_kind": "primitive"}], ("a",), None),
        ([_ADDRESS, {"name": "b", "type": "bytes", "abi_type": "bytes", "type_kind": "primitive"}], ("a",), None),
        # Auto-getters omit mapping and array members, shifting later indexes.
        ([_ADDRESS, {"name": "m", "type": "mapping", "abi_type": "mapping", "type_kind": "mapping"}], ("a",), None),
        ([_ADDRESS, {"name": "xs", "type": "uint256[]", "abi_type": "uint256[]", "type_kind": "array"}], ("a",), None),
        ([_ADDRESS, {"name": "t", "type": "T", "abi_type": "(address,uint96)", "type_kind": "struct"}], ("a",), None),
        ([_UINT], ("a",), None),
        ([], ("a",), None),
        ([_ADDRESS, _UINT], ("a", "b"), None),
    ],
)
def test_member_word_index_refuses_what_it_cannot_prove(components, member, index):
    read_spec = _read_spec(components, member)
    assert _member_word_index(read_spec) == index
    assert _is_poll_decodable(read_spec) is (index is not None)


@pytest.mark.parametrize(
    "entry,expected",
    [
        ({}, "0x" + "11" * 32 + "22" * 32),
        ({"member_word_index": 0}, "0x" + "11" * 32),
        ({"member_word_index": 1}, "0x" + "22" * 32),
        ({"member_word_index": 2}, None),
        # ``True`` is an int in Python.
        ({"member_word_index": True}, "0x" + "11" * 32 + "22" * 32),
        ({"member_word_index": -1}, "0x" + "11" * 32 + "22" * 32),
    ],
)
def test_projection_slices_exactly_one_word(entry, expected):
    assert project_entry_return("0x" + "11" * 32 + "22" * 32, entry) == expected


def test_projection_of_a_missing_answer_is_missing():
    assert project_entry_return(None, {"member_word_index": 0}) is None
    assert project_entry_return("0x", {"member_word_index": 0}) is None
    assert project_entry_return(None, {}) is None


def _plan_with(member_witness, openness="restricted"):
    event = {
        "name": "E",
        "signature": "E(address)",
        "topic0": "0x" + "ab" * 32,
        "inputs": [{"name": "user", "type": "address", "indexed": True}],
        "effect_tags": {"writes": ["m"]},
        "writer_openness": openness,
    }
    if member_witness is not None:
        event["member_witness"] = member_witness
    return {
        "tracked_controllers": [
            {
                "controller_id": "state_variable:m",
                "read_spec": None,
                "event_watch": {"events": [event]},
            }
        ]
    }


def test_a_record_naming_no_variable_mints_no_member_type():
    assert member_witness_mapping_var({"key_position": 0, "direction": "add"}) == ""
    spec = extract_governance_topics(_plan_with({"key_position": 0, "direction": "add"}))[0]
    assert spec["event_type"] == "state_changed:state_variable:m"
    # Guards key off the type, so a self-describing spec under the slot stem would put an entry key in
    # ``last_known_state``.
    assert spec["witness_tier"] == WITNESS_TIER_ACTIVITY
    assert "member_witness" not in spec


def test_a_key_outside_the_events_arg_list_mints_no_member_type():
    witness = {"mapping_name": "m", "key_position": 3, "direction": "add"}
    spec = extract_governance_topics(_plan_with(witness))[0]
    assert spec["event_type"] == "state_changed:state_variable:m"
    assert spec["witness_tier"] == WITNESS_TIER_ACTIVITY
    assert "member_witness" not in spec


def test_a_log_that_cannot_name_the_entry_publishes_nothing():
    spec = {
        "event_type": "member_changed:m",
        "inputs": [{"name": "user", "type": "address", "indexed": True}],
        "member_witness": {"mapping_name": "m", "key_position": 2, "direction": "add"},
    }
    log = {
        "topics": ["0x" + "ab" * 32, "0x" + "0" * 24 + "cd" * 20],
        "data": "0x",
        "blockNumber": "0x1",
        "transactionHash": "0x" + "ab" * 32,
        "logIndex": "0x0",
    }
    from services.monitoring.event_topics import parse_tracked_log

    assert parse_tracked_log(log, spec) is None


def test_one_topic0_on_two_controllers_resolves_by_evidence():
    """The winner used to be decided by alphabetical label order."""
    topic0 = "0x" + "ab" * 32
    weak = {
        "controller_id": "state_variable:aaa",
        "read_spec": None,
        "event_watch": {"events": [{"signature": "E(address)", "topic0": topic0, "inputs": []}]},
    }
    strong = {
        "controller_id": "state_variable:zzz",
        "read_spec": {"strategy": "getter_call", "type_kind": "address", "target": "zzz"},
        "event_watch": {"events": [{"signature": "E(address)", "topic0": topic0, "inputs": []}]},
    }
    for order in ([weak, strong], [strong, weak]):
        specs = extract_governance_topics({"tracked_controllers": order})
        assert len(specs) == 1
        assert specs[0]["witness_tier"] == WITNESS_TIER_HINT
        assert specs[0]["controller_id"] == "state_variable:zzz"
