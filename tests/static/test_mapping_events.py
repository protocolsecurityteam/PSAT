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


def _conversion(lvalue: Any, variable: Any) -> SimpleNamespace:
    return _named("TypeConversion", lvalue=lvalue, variable=variable)


def _converted_write_spec(source: Any) -> dict[str, Any]:
    # MasterMinter ``removeController``: Slither assigns ``address(0)`` through ``TMP = CONVERT 0 to address``.
    controllers = _mapping("controllers", value_type="address")
    key = _local("_controller")
    ref = _tmp("REF_1", type_str="address")
    converted = _tmp("TMP_1", type_str="address")
    fn = _function(
        "removeController",
        nodes=[
            _node(
                [
                    _index(controllers, key, ref),
                    _conversion(converted, source),
                    _assignment(ref, converted),
                    _event_call("ControllerRemoved(address)", [key]),
                ]
            )
        ],
        written=[controllers],
    )
    specs = discover_mapping_writer_events(_contract([fn]))
    assert len(specs) == 1
    return dict(specs[0])


def test_address_zero_through_type_conversion_is_a_removal():
    spec = _converted_write_spec(_constant(0))
    assert spec["direction"] == "remove"
    assert spec["value_position"] is None


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(_constant(1), id="nonzero_constant"),
        pytest.param(_local("newWorker"), id="variable"),
    ],
)
def test_type_conversion_of_anything_but_zero_stays_a_set(source):
    assert _converted_write_spec(source)["direction"] == "set"


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
