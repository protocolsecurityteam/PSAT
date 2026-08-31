"""Unit-level adversarial cases for the F3/F7/F8 qualification machinery.

The corpus test (``test_witness_corpus_completeness``) proves the whole
derivation on compiled Solidity; these pin the individual judgements at the
shapes that are hard or impossible to reach from source — an OR-shaped gate, a
struct whose members are not word-projectable, an ambiguous correspondence.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from services.monitoring.event_topics import (
    MAX_EVENT_TYPE_LENGTH,
    WITNESS_TIER_ACTIVITY,
    WITNESS_TIER_HINT,
    WITNESS_TIER_SELF_DESCRIBING,
    extract_governance_topics,
    is_member_changed_event_type,
    member_witness_mapping_var,
)
from services.monitoring.polling_plan import (
    _is_poll_decodable,
    _member_word_index,
    project_entry_return,
)
from services.static.static_analysis.tracking import (
    _writer_survives_hygiene,
)
from services.static.static_analysis.writer_openness import (
    openness_of_write_paths,
    restricted_function_signatures,
)
from utils.scoring_status import OPENNESS_NOT_DETERMINED, OPENNESS_RESTRICTED

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


def test_one_unrestricted_path_demotes_the_event():
    restricted = frozenset({"a()", "b()"})
    assert openness_of_write_paths({"a()"}, {"a()"}, restricted) == OPENNESS_RESTRICTED
    assert openness_of_write_paths({"a()"}, {"a()", "b()"}, restricted) == OPENNESS_RESTRICTED
    # An open EMITTER demotes.
    assert openness_of_write_paths({"a()", "c()"}, {"a()", "c()"}, restricted) == OPENNESS_NOT_DETERMINED
    # An open WRITER demotes even when every emitter we found is gated — this
    # is the arm that survives an emitter set the IR walk could not complete.
    assert openness_of_write_paths({"a()"}, {"a()", "c()"}, restricted) == OPENNESS_NOT_DETERMINED
    # Nothing proven about paths we never found.
    assert openness_of_write_paths(set(), {"a()"}, restricted) == OPENNESS_NOT_DETERMINED
    assert openness_of_write_paths({"a()"}, set(), restricted) == OPENNESS_NOT_DETERMINED


def test_the_kill_switch_cannot_promote(monkeypatch):
    """``PSAT_AUTHORITY_EARNED_PUBLIC=0`` turns the resolution plane's
    earned-public projection off, which there NARROWS what publishes. Here the
    same test only withholds a promotion, so honouring the switch would make it
    a promoter: a cofinite denylist would read as a proof of restriction."""
    for value in ("0", "1"):
        monkeypatch.setenv("PSAT_AUTHORITY_EARNED_PUBLIC", value)
        assert restricted_function_signatures(_trees(**{"f()": _DENYLIST})) == frozenset()


# ---------------------------------------------------------------------------
# F7 — writer hygiene
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
    """The modifier's own set-and-restore — the write the latch proof is about."""
    return _fact(var=var, hygiene="reentrancy_guard", origin="guard")


_IR_PROVEN = frozenset({"s"})


@pytest.mark.parametrize(
    "facts,member_path,survives",
    [
        # Nothing recorded about this function — not determined, so kept.
        (None, None, True),
        ([], None, True),
        # Recorded, but about a different variable — this one is unconstrained.
        ([_fact(var="other")], None, True),
        # Every write here is the modifier's own set-and-restore.
        ([_guard_write()], None, False),
        # One real write beside it keeps the writer.
        ([_guard_write(), _fact()], None, True),
        # The latch CLASS on a body write is an owner-controlled mutation of the
        # same variable: the class is variable-granular, the origin is not.
        ([_fact(hygiene="reentrancy_guard", origin="body")], None, True),
        # An origin that was never recorded is not the guard origin.
        ([_fact(hygiene="reentrancy_guard", origin=None)], None, True),
        # Member-scoped: proven to write a sibling member only.
        ([_fact(member=["b"])], ("a",), False),
        ([_fact(member=["a"])], ("a",), True),
        # Var-granularity names no member, so it cannot prove this one was spared.
        ([_fact()], ("a",), True),
    ],
)
def test_writer_hygiene_subtracts_only_what_is_proven(facts, member_path, survives):
    assert _writer_survives_hygiene(facts, "s", member_path, _IR_PROVEN) is survives


def test_the_latch_class_alone_subtracts_nothing():
    """``hygiene_class`` carries a name fallback ({locked, _status, *reentran*})
    with no IR behind it, and it is VARIABLE-granular — once a var is a proven
    latch every write of it is stamped, including an admin setter's. Neither may
    delete a controller on its own: the drop needs the var in the IR-proven set
    AND the write to be the modifier's own."""
    guard = [_guard_write()]
    assert _writer_survives_hygiene(guard, "s", None, frozenset()) is True
    assert _writer_survives_hygiene(guard, "s", None, _IR_PROVEN) is False

    admin_setter = [_fact(hygiene="reentrancy_guard", origin="body")]
    assert _writer_survives_hygiene(admin_setter, "s", None, _IR_PROVEN) is True


def test_the_opaque_set_reads_both_shapes_the_artifact_records():
    """Inline-assembly storage access and a delegatecall are the two
    unattributable write shapes ``effects`` records per function."""
    from services.static.static_analysis.tracking import _unattributable_write_functions

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
    # And the TIER falls with the type. A spec that publishes under the slot
    # stem while classified self_describing would carry an entry key into
    # last_known_state and a ControllerValue row as the slot's value: the
    # is_member_changed_event_type guards key off the type, so a promotion the
    # type refused must not survive.
    assert spec["witness_tier"] == WITNESS_TIER_ACTIVITY
    assert "member_witness" not in spec


def test_a_key_outside_the_events_arg_list_mints_no_member_type():
    """The type names the mapping; only ``data.key`` names the entry."""
    witness = {"mapping_name": "m", "key_position": 3, "direction": "add"}
    spec = extract_governance_topics(_plan_with(witness))[0]
    assert spec["event_type"] == "state_changed:state_variable:m"
    assert spec["witness_tier"] == WITNESS_TIER_ACTIVITY
    assert "member_witness" not in spec


def test_a_log_that_cannot_name_the_entry_publishes_nothing():
    """A spec that DID qualify, decoding a log whose args do not reach the
    proven key position: the row would claim "some entry of m moved" and name
    none. Refused, exactly as an undecodable log is."""
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
    assert spec["witness_tier"] == WITNESS_TIER_ACTIVITY
    assert "member_witness" not in spec


def test_one_topic0_on_two_controllers_resolves_by_evidence():
    """A donated topic0 can appear under several controllers. Which spec wins
    decided the published claim, and it used to be decided by the controllers'
    alphabetical label order."""
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


# ---------------------------------------------------------------------------
# The slot-shaped consumers skip the member vocabulary
# ---------------------------------------------------------------------------


def test_a_legacy_witness_under_a_slot_type_does_not_promote():
    """``_resolve_spec_tier`` re-classifies a spec persisted before the taxonomy.
    A record honoured there regardless of the published type would promote a row
    that publishes as ``state_changed:`` — and every slot-shaped consumer keys
    off the type, so the entry key would land in ``last_known_state`` and in a
    ``ControllerValue`` row as the slot's value."""
    from services.monitoring.unified_watcher import _resolve_spec_tier

    mc = SimpleNamespace(monitoring_config={"polling_plan": []})
    witness = {"mapping_name": "m", "key_position": 0, "direction": "add"}
    slot_typed = {
        "event_type": "state_changed:state_variable:m",
        "controller_id": "state_variable:m",
        "member_witness": witness,
        "writer_openness": "restricted",
    }
    assert _resolve_spec_tier(slot_typed, mc) == WITNESS_TIER_ACTIVITY  # pyright: ignore[reportArgumentType]

    member_typed = dict(slot_typed, event_type="member_changed:m")
    assert _resolve_spec_tier(member_typed, mc) == WITNESS_TIER_SELF_DESCRIBING  # pyright: ignore[reportArgumentType]


def test_member_change_never_reflects_into_last_known_state():
    """One entry of a mapping is not the mapping's value. The stub has no
    SQLAlchemy identity, so a path that did NOT skip would raise on the write."""
    from services.monitoring.unified_watcher import _update_state_from_event

    mc = SimpleNamespace(last_known_state={"m": "before"})
    _update_state_from_event(
        mc,  # pyright: ignore[reportArgumentType]
        {"event_type": "member_changed:m", "effect_tags": {"writes": ["m"]}, "key": "0xabc", "direction": "add"},
    )
    assert mc.last_known_state == {"m": "before"}


def test_member_change_never_writes_a_controller_value_row():
    """Same reason. ``session=None`` makes the skip provable: any row write
    would dereference it."""
    from services.monitoring.unified_watcher import _sync_relational_tables

    mc = SimpleNamespace(contract_id=1, address="0x" + "11" * 20, chain="ethereum")
    _sync_relational_tables(
        None,  # pyright: ignore[reportArgumentType]
        mc,  # pyright: ignore[reportArgumentType]
        {"event_type": "member_changed:m", "effect_tags": {"writes": ["m"]}, "key": "0xabc", "direction": "add"},
    )
