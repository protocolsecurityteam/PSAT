"""Common schema aliases shared across PSAT services."""

from __future__ import annotations

from typing import Any, TypeAlias

Address: TypeAlias = str
AbiSignature: TypeAlias = str
BlockNumber: TypeAlias = int
ChainId: TypeAlias = int
ChainName: TypeAlias = str
FunctionSelector: TypeAlias = str
HexString: TypeAlias = str
StorageSlot: TypeAlias = str
TxHash: TypeAlias = str

JsonScalar: TypeAlias = str | int | float | bool | None
JsonArray: TypeAlias = list[Any]
JsonObject: TypeAlias = dict[str, Any]
JsonValue: TypeAlias = JsonScalar | JsonArray | JsonObject

__all__ = [
    "AbiSignature",
    "Address",
    "BlockNumber",
    "ChainId",
    "ChainName",
    "FunctionSelector",
    "HexString",
    "JsonArray",
    "JsonObject",
    "JsonScalar",
    "JsonValue",
    "StorageSlot",
    "TxHash",
]
