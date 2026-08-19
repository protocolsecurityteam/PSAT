"""Structural doubles that mimic the getattr surface the effects normalizer reads
on a Slither Function/Modifier (nodes -> irs -> read/lvalue/function).

Extracted verbatim from ``test_effects_hashing``.
"""

from __future__ import annotations

import types


def _var(role_cls: str, name: str = "") -> object:
    v = type(role_cls, (), {})()
    v.name = name  # pyright: ignore[reportAttributeAccessIssue]
    return v


def _ir(op: str, *, read=(), lvalue=None, function=None) -> object:
    inst = type(op, (), {})()
    inst.read = list(read)  # pyright: ignore[reportAttributeAccessIssue]
    inst.lvalue = lvalue  # pyright: ignore[reportAttributeAccessIssue]
    inst.function = function  # pyright: ignore[reportAttributeAccessIssue]
    return inst


def _node(node_type: str, irs) -> object:
    return types.SimpleNamespace(type=node_type, irs=list(irs))


def _fn(name: str, nodes, modifiers=()) -> object:
    return types.SimpleNamespace(
        canonical_name=name,
        full_name=name,
        nodes=list(nodes),
        modifiers=list(modifiers),
    )
