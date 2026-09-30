from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from services.static.contract_analysis_pipeline.mapping_events import (
    discover_mapping_writer_events,
)


def _named(cls_name: str, **attrs: Any) -> SimpleNamespace:
    subclass = type(cls_name, (SimpleNamespace,), {})
    subclass.__name__ = cls_name
    return subclass(**attrs)


def _mapping(name: str, value_type: str = "uint256") -> SimpleNamespace:
    subclass = type("StateVariable", (SimpleNamespace,), {})
    subclass.__name__ = "StateVariable"
    return subclass(name=name, type=f"mapping(address => {value_type})")


def _local(name: str, type_str: str = "address") -> SimpleNamespace:
    subclass = type("LocalVariable", (SimpleNamespace,), {})
    subclass.__name__ = "LocalVariable"
    return subclass(name=name, type=type_str)


def _tmp(name: str, type_str: str = "uint256") -> SimpleNamespace:
    subclass = type("TemporaryVariable", (SimpleNamespace,), {})
    subclass.__name__ = "TemporaryVariable"
    return subclass(name=name, type=type_str)


def _constant(value: Any, type_str: str = "uint256") -> SimpleNamespace:
    subclass = type("Constant", (SimpleNamespace,), {})
    subclass.__name__ = "Constant"
    return subclass(name=str(value), type=type_str, value=value)


def _index(base: Any, key: Any, lvalue: Any) -> SimpleNamespace:
    return _named("Index", variable_left=base, variable_right=key, lvalue=lvalue)


def _assignment(lvalue: Any, rvalue: Any) -> SimpleNamespace:
    return _named("Assignment", lvalue=lvalue, rvalue=rvalue)


def _delete(lvalue: Any) -> SimpleNamespace:
    return _named("Delete", lvalue=lvalue)


def _event_call(signature: str, arguments: list[Any]) -> SimpleNamespace:
    return _named("EventCall", name=signature, arguments=arguments)


def _event_decl(name: str, inputs: list[tuple[str, str, bool]]) -> SimpleNamespace:
    elems = [SimpleNamespace(name=arg_name, type=arg_type, indexed=indexed) for arg_name, arg_type, indexed in inputs]
    full_name = f"{name}({','.join(arg_type for _, arg_type, _ in inputs)})"
    return SimpleNamespace(name=name, full_name=full_name, elems=elems)


def _node(irs: list[Any]) -> SimpleNamespace:
    return SimpleNamespace(irs=irs, node_id=0)


def _function(
    name: str,
    nodes: list[Any],
    *,
    written: list[Any] | None = None,
    is_constructor: bool = False,
) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        full_name=f"{name}(address)",
        nodes=nodes,
        all_state_variables_written=lambda w=(written or []): w,
        is_constructor=is_constructor,
    )


def _contract(functions: list[Any], events: list[Any] | None = None) -> SimpleNamespace:
    return SimpleNamespace(name="TestContract", functions=functions, inheritance=[], events=events or [])


def test_makerdao_rely_adds_to_wards():
    wards = _mapping("wards")
    guy = _local("guy")
    index_lv = _tmp("TMP_0")
    rely_fn = _function(
        "rely",
        nodes=[
            _node(
                [
                    _index(wards, guy, index_lv),
                    _assignment(index_lv, _constant(1)),
                    _event_call("Rely(address)", [guy]),
                ]
            )
        ],
        written=[wards],
    )
    specs = discover_mapping_writer_events(_contract([rely_fn]))
    assert len(specs) == 1
    s = specs[0]
    assert s["mapping_name"] == "wards"
    assert s["event_signature"] == "Rely(address)"
    assert s["event_name"] == "Rely"
    assert s["direction"] == "add"
    assert s["key_position"] == 0


def test_event_call_name_as_constant_does_not_crash():
    """Slither types ``EventCall.name`` as ``str | Constant``; a Constant (seen on Morpho) raised ``AttributeError:
    'Constant' object has no attribute 'split'``.
    """

    class _ConstantName:  # like Slither's Constant: str(...) yields the event sig
        def __init__(self, s: str) -> None:
            self._s = s

        def __str__(self) -> str:
            return self._s

    wards = _mapping("wards")
    guy = _local("guy")
    index_lv = _tmp("TMP_0")
    rely_fn = _function(
        "rely",
        nodes=[
            _node(
                [
                    _index(wards, guy, index_lv),
                    _assignment(index_lv, _constant(1)),
                    _event_call(_ConstantName("Rely(address)"), [guy]),  # pyright: ignore[reportArgumentType]
                ]
            )
        ],
        written=[wards],
    )
    specs = discover_mapping_writer_events(_contract([rely_fn]))
    assert len(specs) == 1
    assert isinstance(specs[0]["event_signature"], str)
    assert specs[0]["event_signature"] == "Rely(address)"
    assert specs[0]["event_name"] == "Rely"


@pytest.mark.parametrize(
    ("fn_name", "mapping_name", "value_type", "write", "event_sig", "expected_direction"),
    [
        pytest.param(
            "deny",
            "wards",
            "uint256",
            lambda lv: _assignment(lv, _constant(0)),
            "Deny(address)",
            "remove",
            id="makerdao_deny_zero_write",
        ),
        pytest.param(
            "whitelist_user",
            "whitelist",
            "bool",
            lambda lv: _assignment(lv, _constant(True, type_str="bool")),
            "Whitelisted(address)",
            "add",
            id="bool_true",
        ),
        pytest.param(
            "unwhitelist",
            "whitelist",
            "bool",
            lambda lv: _assignment(lv, _constant(False, type_str="bool")),
            "Unwhitelisted(address)",
            "remove",
            id="bool_false",
        ),
        pytest.param("denyViaDelete", "wards", "uint256", _delete, "Deny(address)", "remove", id="delete"),
    ],
)
def test_write_direction(fn_name, mapping_name, value_type, write, event_sig, expected_direction):
    mapping = _mapping(mapping_name, value_type=value_type)
    key = _local("guy")
    lv = _tmp("TMP_0", type_str=value_type)
    fn = _function(
        fn_name,
        nodes=[_node([_index(mapping, key, lv), write(lv), _event_call(event_sig, [key])])],
        written=[mapping],
    )
    specs = discover_mapping_writer_events(_contract([fn]))
    assert len(specs) == 1
    assert specs[0]["direction"] == expected_direction


def test_write_with_no_emit_is_skipped():
    wards = _mapping("wards")
    guy = _local("guy")
    lv = _tmp("T0")
    fn = _function(
        "relyQuiet",
        nodes=[_node([_index(wards, guy, lv), _assignment(lv, _constant(1))])],
        written=[wards],
    )
    assert discover_mapping_writer_events(_contract([fn])) == []


def test_emit_without_matching_key_arg_is_skipped():
    wards = _mapping("wards")
    guy = _local("guy")
    other = _local("other")
    lv = _tmp("T0")
    fn = _function(
        "rely_odd",
        nodes=[
            _node(
                [
                    _index(wards, guy, lv),
                    _assignment(lv, _constant(1)),
                    _event_call("SomeOther(address)", [other]),
                ]
            )
        ],
        written=[wards],
    )
    assert discover_mapping_writer_events(_contract([fn])) == []


def test_non_address_keyed_mapping_writer_event_is_tracked():
    subclass = type("StateVariable", (SimpleNamespace,), {})
    subclass.__name__ = "StateVariable"
    role_mapping = subclass(name="roleByIndex", type="mapping(uint256 => bool)")
    key = _local("key", type_str="uint256")
    lv = _tmp("T0", type_str="bool")
    fn = _function(
        "setRole",
        nodes=[
            _node(
                [
                    _index(role_mapping, key, lv),
                    _assignment(lv, _constant(True, type_str="bool")),
                    _event_call("RoleSet(uint256)", [key]),
                ]
            )
        ],
        written=[role_mapping],
    )
    assert discover_mapping_writer_events(_contract([fn])) == [
        {
            "mapping_name": "roleByIndex",
            "event_signature": "RoleSet(uint256)",
            "event_name": "RoleSet",
            "key_position": 0,
            "indexed_positions": [],
            "key_positions_by_index": {0: 0},
            "direction": "add",
            "value_position": None,
            "writer_function": "setRole(address)",
        }
    ]


def test_constructor_skipped():
    wards = _mapping("wards")
    guy = _local("guy")
    lv = _tmp("T0")
    fn = _function(
        "constructor",
        nodes=[
            _node(
                [
                    _index(wards, guy, lv),
                    _assignment(lv, _constant(1)),
                    _event_call("Rely(address)", [guy]),
                ]
            )
        ],
        written=[wards],
        is_constructor=True,
    )
    assert discover_mapping_writer_events(_contract([fn])) == []


def test_non_literal_value_emits_set_direction():
    """Emitting ``direction="set"`` lets the indexer decode the value at index time."""
    wards = _mapping("wards")
    guy = _local("guy")
    some = _local("someValue", "uint256")
    lv = _tmp("T0")
    fn = _function(
        "setWard",
        nodes=[
            _node(
                [
                    _index(wards, guy, lv),
                    _assignment(lv, some),
                    _event_call("WardSet(address)", [guy]),
                ]
            )
        ],
        written=[wards],
    )
    specs = discover_mapping_writer_events(_contract([fn]))
    assert len(specs) == 1
    assert specs[0]["direction"] == "set"
    assert specs[0]["mapping_name"] == "wards"
    assert specs[0]["key_position"] == 0


@pytest.mark.parametrize(
    ("fn_name", "value_type", "assigned", "args", "event_sig", "event_inputs", "expected"),
    [
        pytest.param(
            "setWard",
            "uint256",
            _constant(1),
            [("id", "uint256"), ("guy", "address")],
            "UserSet(uint256,address)",
            None,
            {"key_position": 1},
            id="multi_arg_event_with_key_not_first",
        ),
        pytest.param(
            "rely",
            "uint256",
            _constant(1),
            [("guy", "address")],
            "Rely",
            [("guy", "address", True)],
            {"indexed_positions": [0]},
            id="indexed_positions_come_from_event_declaration",
        ),
        pytest.param(
            "setWhitelisted",
            "bool",
            _constant(True, type_str="bool"),
            [("guy", "address"), ("enabled", "bool")],
            "SetWhitelisted",
            [("guy", "address", False), ("enabled", "bool", False)],
            {"key_position": 0, "indexed_positions": []},
            id="non_indexed_key_position",
        ),
        pytest.param(
            "setWard",
            "uint256",
            _constant(1),
            [("tier", "uint256"), ("guy", "address")],
            "Foo",
            [("tier", "uint256", True), ("guy", "address", False)],
            {"key_position": 1, "indexed_positions": [0]},
            id="indexed_position_before_key",
        ),
    ],
)
def test_key_and_indexed_positions(fn_name, value_type, assigned, args, event_sig, event_inputs, expected):
    mapping = _mapping("whitelist" if value_type == "bool" else "wards", value_type=value_type)
    arg_vars = [_local(name, type_str) for name, type_str in args]
    key = next(v for v in arg_vars if v.name == "guy")
    lv = _tmp("T0", type_str=value_type)
    fn = _function(
        fn_name,
        nodes=[_node([_index(mapping, key, lv), _assignment(lv, assigned), _event_call(event_sig, arg_vars)])],
        written=[mapping],
    )
    events = None if event_inputs is None else [_event_decl(event_sig, event_inputs)]
    specs = discover_mapping_writer_events(_contract([fn], events=events))
    assert len(specs) == 1
    assert {k: specs[0][k] for k in expected} == expected


def test_dedupes_on_mapping_event_direction():
    wards = _mapping("wards")
    guy_a = _local("guy_a")
    guy_b = _local("guy_b")
    lv1 = _tmp("T1")
    lv2 = _tmp("T2")
    fn_a = _function(
        "relyFromAdmin",
        nodes=[
            _node(
                [
                    _index(wards, guy_a, lv1),
                    _assignment(lv1, _constant(1)),
                    _event_call("Rely(address)", [guy_a]),
                ]
            )
        ],
        written=[wards],
    )
    fn_b = _function(
        "relyFromGovernor",
        nodes=[
            _node(
                [
                    _index(wards, guy_b, lv2),
                    _assignment(lv2, _constant(1)),
                    _event_call("Rely(address)", [guy_b]),
                ]
            )
        ],
        written=[wards],
    )
    specs = discover_mapping_writer_events(_contract([fn_a, fn_b]))
    assert len(specs) == 1


def test_bare_event_name_in_ir_resolves_to_canonical_signature():
    wards = _mapping("wards")
    guy = _local("guy")
    index_lv = _tmp("TMP_0")
    rely_fn = _function(
        "rely",
        nodes=[
            _node(
                [
                    _index(wards, guy, index_lv),
                    _assignment(index_lv, _constant(1)),
                    _event_call("Rely", [guy]),
                ]
            )
        ],
        written=[wards],
    )
    rely_event_decl = SimpleNamespace(name="Rely", full_name="Rely(address)")
    contract = SimpleNamespace(name="TestContract", functions=[rely_fn], inheritance=[], events=[rely_event_decl])
    specs = discover_mapping_writer_events(contract)
    assert len(specs) == 1
    assert specs[0]["event_signature"] == "Rely(address)"
    assert specs[0]["event_name"] == "Rely"
