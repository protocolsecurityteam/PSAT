"""Unit-level adversarial cases for the F3/F7/F8 qualification machinery.

The corpus test (``test_witness_corpus_completeness``) proves the whole
derivation on compiled Solidity; these pin the individual judgements at the
shapes that are hard or impossible to reach from source — an OR-shaped gate, a
struct whose members are not word-projectable, an ambiguous correspondence.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.monitoring.event_topics import (  # noqa: E402
    MAX_EVENT_TYPE_LENGTH,
    extract_governance_topics,
    is_member_changed_event_type,
    member_witness_mapping_var,
)
from services.monitoring.polling_plan import (  # noqa: E402
    _is_poll_decodable,
    _member_word_index,
    project_entry_return,
)
from services.static.contract_analysis_pipeline.tracking import (  # noqa: E402
    _writer_survives_hygiene,
)
from services.static.contract_analysis_pipeline.writer_openness import (  # noqa: E402
    WRITER_OPENNESS_NOT_DETERMINED,
    WRITER_OPENNESS_RESTRICTED,
    openness_of_emitters,
    restricted_function_signatures,
)

# ---------------------------------------------------------------------------
# writer_openness — "the gate holds on every path"
# ---------------------------------------------------------------------------


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
# ``require(!denied[msg.sender])`` — a cofinite denylist admits every address it
# has not named, which the resolution plane's earned-public projection calls
# open. It carries an authority role all the same.
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
        # One restricting conjunct is enough — the other conditions only narrow.
        ({"op": "AND", "children": [_BUSINESS, _OWNER_GATE]}, True),
        # An OR needs every branch to restrict: one open branch is an open path.
        ({"op": "OR", "children": [_OWNER_GATE, _BUSINESS]}, False),
        ({"op": "OR", "children": [_OWNER_GATE, _OWNER_GATE]}, True),
        # A denylist OR'd with a real gate is still reachable by everyone.
        ({"op": "OR", "children": [_OWNER_GATE, _DENYLIST]}, False),
        ({"op": "AND", "children": []}, False),
        ({"op": "LEAF", "leaf": None}, False),
    ],
)
def test_restriction_requires_every_path_to_pass_a_gate(tree, restricted):
    assert ("f()" in restricted_function_signatures(_trees(**{"f()": tree}))) is restricted


def test_a_value_movement_call_is_not_a_gate():
    """``require(token.transferFrom(msg.sender, …))`` taints from the caller and
    moves the caller's own assets. The gate-shape guard keeps it out."""
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
    """No tree means the gate question was never answered for it — which is not
    an answer of "no gate", and equally not one of "gated"."""
    assert restricted_function_signatures(None) == frozenset()
    assert restricted_function_signatures({"schema_version": "semantic", "error": "boom"}) == frozenset()


def test_one_unrestricted_emitter_demotes_the_event():
    restricted = frozenset({"a()", "b()"})
    assert openness_of_emitters({"a()"}, restricted) == WRITER_OPENNESS_RESTRICTED
    assert openness_of_emitters({"a()", "b()"}, restricted) == WRITER_OPENNESS_RESTRICTED
    assert openness_of_emitters({"a()", "c()"}, restricted) == WRITER_OPENNESS_NOT_DETERMINED
    # Nothing proven about a path we never found.
    assert openness_of_emitters(set(), restricted) == WRITER_OPENNESS_NOT_DETERMINED


# ---------------------------------------------------------------------------
# F7 — writer hygiene
# ---------------------------------------------------------------------------


def _fact(var="s", member=None, hygiene="normal"):
    return {
        "var": var,
        "member_path": list(member) if member else [],
        "granularity": "member" if member else "var",
        "hygiene_class": hygiene,
    }


@pytest.mark.parametrize(
    "facts,member_path,survives",
    [
        # Nothing recorded about this function — not determined, so kept.
        (None, None, True),
        ([], None, True),
        # Recorded, but about a different variable — this one is unconstrained.
        ([_fact(var="other")], None, True),
        # Every write here is the transient latch.
        ([_fact(hygiene="reentrancy_guard")], None, False),
        # One real write beside the latch keeps the writer.
        ([_fact(hygiene="reentrancy_guard"), _fact()], None, True),
        # Member-scoped: proven to write a sibling member only.
        ([_fact(member=["b"])], ("a",), False),
        ([_fact(member=["a"])], ("a",), True),
        # Var-granularity names no member, so it cannot prove this one was spared.
        ([_fact()], ("a",), True),
    ],
)
def test_writer_hygiene_subtracts_only_what_is_proven(facts, member_path, survives):
    assert _writer_survives_hygiene(facts, "s", member_path) is survives


# ---------------------------------------------------------------------------
# F8 — member projection
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
        # A dynamic member puts an OFFSET in the head, so no member's word index
        # is knowable from the declaration order any more.
        ([_ADDRESS, {"name": "s", "type": "string", "abi_type": "string", "type_kind": "primitive"}], ("a",), None),
        ([_ADDRESS, {"name": "b", "type": "bytes", "abi_type": "bytes", "type_kind": "primitive"}], ("a",), None),
        # An auto-getter OMITS mapping and array members, shifting every later
        # index — including, in general, this one's.
        ([_ADDRESS, {"name": "m", "type": "mapping", "abi_type": "mapping", "type_kind": "mapping"}], ("a",), None),
        ([_ADDRESS, {"name": "xs", "type": "uint256[]", "abi_type": "uint256[]", "type_kind": "array"}], ("a",), None),
        # Nested struct — a tuple head, same problem.
        ([_ADDRESS, {"name": "t", "type": "T", "abi_type": "(address,uint96)", "type_kind": "struct"}], ("a",), None),
        # The named member is not in the component list at all.
        ([_UINT], ("a",), None),
        ([], ("a",), None),
        # Deeper paths are not projected: only one hop is proven.
        ([_ADDRESS, _UINT], ("a", "b"), None),
    ],
)
def test_member_word_index_refuses_what_it_cannot_prove(components, member, index):
    read_spec = _read_spec(components, member)
    assert _member_word_index(read_spec) == index
    assert _is_poll_decodable(read_spec) is (index is not None)


def test_a_member_free_read_spec_is_unaffected():
    assert _member_word_index({"strategy": "getter_call", "target": "owner"}) is None
    assert _is_poll_decodable({"strategy": "getter_call", "target": "owner", "type_kind": "address"}) is True


@pytest.mark.parametrize(
    "entry,expected",
    [
        ({}, "0x" + "11" * 32 + "22" * 32),
        ({"member_word_index": 0}, "0x" + "11" * 32),
        ({"member_word_index": 1}, "0x" + "22" * 32),
        # Past the end of the answer: the member is not in it.
        ({"member_word_index": 2}, None),
        # ``True`` is an int in Python and must not read as word 1.
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


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------


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
    """A bare ``member_changed`` would say an entry moved somewhere."""
    assert member_witness_mapping_var({"key_position": 0, "direction": "add"}) == ""
    spec = extract_governance_topics(_plan_with({"key_position": 0, "direction": "add"}))[0]
    assert spec["event_type"] == "state_changed:state_variable:m"


def test_a_mapping_name_that_would_overflow_the_column_mints_no_member_type():
    """``monitored_events.event_type`` is the row's identity; a truncated one
    names a different mapping."""
    long_name = "m" * MAX_EVENT_TYPE_LENGTH
    spec = extract_governance_topics(_plan_with({"mapping_name": long_name, "key_position": 0, "direction": "add"}))[0]
    assert not is_member_changed_event_type(spec["event_type"])


@pytest.mark.parametrize("openness", ["open", "not_determined", None])
def test_an_unproven_writer_mints_no_member_type(openness):
    witness = {"mapping_name": "m", "key_position": 0, "direction": "add"}
    spec = extract_governance_topics(_plan_with(witness, openness))[0]
    assert spec["event_type"] == "state_changed:state_variable:m"


# ---------------------------------------------------------------------------
# The slot-shaped consumers skip the member vocabulary
# ---------------------------------------------------------------------------


def test_member_change_never_reflects_into_last_known_state():
    """One entry of a mapping is not the mapping's value. The stub has no
    SQLAlchemy identity, so a path that did NOT skip would raise on the write."""
    from services.monitoring.unified_watcher import _update_state_from_event

    mc = SimpleNamespace(last_known_state={"m": "before"})
    _update_state_from_event(
        mc,  # type: ignore[arg-type]
        {"event_type": "member_changed:m", "effect_tags": {"writes": ["m"]}, "key": "0xabc", "direction": "add"},
    )
    assert mc.last_known_state == {"m": "before"}


def test_member_change_never_writes_a_controller_value_row():
    """Same reason. ``session=None`` makes the skip provable: any row write
    would dereference it."""
    from services.monitoring.unified_watcher import _sync_relational_tables

    mc = SimpleNamespace(contract_id=1, address="0x" + "11" * 20, chain="ethereum")
    _sync_relational_tables(
        None,  # type: ignore[arg-type]
        mc,  # type: ignore[arg-type]
        {"event_type": "member_changed:m", "effect_tags": {"writes": ["m"]}, "key": "0xabc", "direction": "add"},
    )
