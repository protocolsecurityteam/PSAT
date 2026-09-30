"""The one guarded import of the Slither IR symbols the pipeline uses; passes gate on ``SLITHER_AVAILABLE`` and
publish ``not_determined`` when it is false. (Slither is imported unguarded elsewhere, so in practice it's always
true.)

Without Slither, each name resolves to the same placeholder class, which raises on any use including ``isinstance``, so
a guard-less use fails loudly instead of silently returning False.
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

        def __call__(cls, *args: Any, **kwargs: Any) -> Any:
            raise RuntimeError(f"slither is not installed: {cls.__name__}(...)")

    _placeholders: dict[str, type] = {}

    def __getattr__(name: str) -> Any:
        if name.startswith("__"):
            raise AttributeError(name)
        placeholder = _placeholders.get(name)
        if placeholder is None:
            placeholder = _placeholders[name] = _AbsentMeta(name, (), {})
        return placeholder


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
