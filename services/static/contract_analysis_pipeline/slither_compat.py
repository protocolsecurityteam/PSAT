"""Single guarded import boundary for the Slither IR symbols the pipeline uses.

Slither is optional at import time: every pass gates its analysis on
``SLITHER_AVAILABLE`` and publishes ``not_determined`` when it is false, so the
pipeline modules must import cleanly on a machine without it. Routing the names
through one module keeps that one ``try``/``except`` instead of seven, and keeps
the names unconditionally bound for consumers.

When Slither is absent, attribute lookups on this module hand back a placeholder
class that raises on any use. A guard-less use therefore still fails loudly, the
way the previous ``NameError`` did — it must never resolve to a silent
``isinstance`` False, which would publish an unwitnessed negative.
"""

from __future__ import annotations

from typing import Any

try:
    from slither.core.cfg.node import NodeType
    from slither.core.declarations import SolidityVariable
    from slither.core.solidity_types.mapping_type import MappingType
    from slither.core.solidity_types.user_defined_type import UserDefinedType
    from slither.core.variables import Variable
    from slither.core.variables.local_variable import LocalVariable
    from slither.core.variables.state_variable import StateVariable
    from slither.slithir.operations import (
        Assignment,
        Binary,
        BinaryType,
        Condition,
        Delete,
        HighLevelCall,
        Index,
        InternalCall,
        Length,
        LibraryCall,
        LowLevelCall,
        Member,
        NewArray,
        NewContract,
        NewElementaryType,
        OperationWithLValue,
        Phi,
        Return,
        Send,
        SolidityCall,
        Transfer,
        TypeConversion,
        Unary,
        UnaryType,
        Unpack,
    )
    from slither.slithir.variables import Constant, ReferenceVariable, TemporaryVariable

    SLITHER_AVAILABLE = True
except Exception:  # pragma: no cover - only when slither is not installed
    SLITHER_AVAILABLE = False

    class _AbsentMeta(type):
        def __getattr__(cls, name: str) -> Any:
            raise RuntimeError(f"slither is not installed: {cls.__name__}.{name}")

        def __instancecheck__(cls, instance: object) -> bool:
            raise RuntimeError(f"slither is not installed: isinstance(..., {cls.__name__})")

        def __subclasscheck__(cls, subclass: type) -> bool:
            raise RuntimeError(f"slither is not installed: issubclass(..., {cls.__name__})")

    def __getattr__(name: str) -> Any:
        if name.startswith("__"):
            raise AttributeError(name)
        return _AbsentMeta(name, (), {})


__all__ = [
    "SLITHER_AVAILABLE",
    "Assignment",
    "Binary",
    "BinaryType",
    "Condition",
    "Constant",
    "Delete",
    "HighLevelCall",
    "Index",
    "InternalCall",
    "Length",
    "LibraryCall",
    "LocalVariable",
    "LowLevelCall",
    "MappingType",
    "Member",
    "NewArray",
    "NewContract",
    "NewElementaryType",
    "NodeType",
    "OperationWithLValue",
    "Phi",
    "ReferenceVariable",
    "Return",
    "Send",
    "SolidityCall",
    "SolidityVariable",
    "StateVariable",
    "TemporaryVariable",
    "Transfer",
    "TypeConversion",
    "Unary",
    "UnaryType",
    "Unpack",
    "UserDefinedType",
    "Variable",
]
