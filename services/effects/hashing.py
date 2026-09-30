"""Behavioural-hash identity for effects dedup.

Three of four ladder rungs; the bytecode-region lifter needs EVM CFG recovery we don't have.

The ``PausableUntil`` mixin is byte-identical across 11 contracts, but eETH/weETH override ``pauseUntil()`` with
stricter gating, so the key is the hash of the resolved (executing) function, never a name or file hash.

Function access is duck-typed so tests can use structural doubles instead of Slither objects.
"""

from __future__ import annotations

import hashlib
from typing import Any

# Bump to invalidate stored hashes when normalization changes.
_HASH_SCHEMA_VERSION = 1

_SEP = "\x1f"


def _digest(domain: str, payload: str) -> str:
    h = hashlib.sha256()
    h.update(f"{domain}:{_HASH_SCHEMA_VERSION}:".encode())
    h.update(payload.encode("utf-8"))
    return h.hexdigest()


# Item 1: normalized resolved-IR/CFG hash of the resolved function.


def _fn_key(fn: Any) -> Any:
    return getattr(fn, "canonical_name", None) or getattr(fn, "full_name", None) or id(fn)


def _has_body(fn: Any) -> bool:
    return bool(getattr(fn, "nodes", None))


def _var_role(v: Any) -> str:
    """An operand's structural role with names and literals stripped.

    Solidity builtins keep their name (semantic identity). Constants become a nameless token so per-deployment
    immutables don't split a kernel. Everything else contributes only its variable class.
    """
    cls = type(v).__name__
    if cls.startswith("SolidityVariable"):
        return "sol:" + str(getattr(v, "name", "") or "")
    if cls == "Constant":
        return "const"
    return cls


def _normalize_ir(ir: Any, visited: frozenset[Any]) -> list[str]:
    op = type(ir).__name__
    toks = ["I:" + op]
    # Inline internal/library callees; external calls are opaque edges represented only by their op token.
    if op in ("InternalCall", "InternalDynamicCall", "LibraryCall"):
        callee = getattr(ir, "function", None)
        if _has_body(callee):
            toks.append("(")
            toks.extend(_normalize_unit(callee, visited))
            toks.append(")")
    for v in getattr(ir, "read", []) or []:
        toks.append("r:" + _var_role(v))
    lval = getattr(ir, "lvalue", None)
    if lval is not None:
        toks.append("w:" + _var_role(lval))
    return toks


def _normalize_unit(unit: Any, visited: frozenset[Any]) -> list[str]:
    """Canonical token stream for a body plus inlined callees.

    ``visited`` is copied per descent so recursion terminates without collapsing siblings.
    """
    key = _fn_key(unit)
    if key in visited:
        return ["<rec>"]
    visited = visited | {key}
    toks: list[str] = []
    # Modifiers are hashed with the body, so a stricter-gated override diverges from its mixin default.
    for mod in getattr(unit, "modifiers", []) or []:
        toks.append("MOD:")
        toks.extend(_normalize_unit(mod, visited))
    for node in getattr(unit, "nodes", []) or []:
        toks.append("N:" + str(getattr(node, "type", "") or ""))
        for ir in getattr(node, "irs", []) or []:
            toks.extend(_normalize_ir(ir, visited))
    return toks


def resolved_function_hash(function: Any) -> str:
    """The primary key: the normalized resolved-IR/CFG hash.

    The caller passes the override-resolved function.
    """
    payload = _SEP.join(_normalize_unit(function, frozenset()))
    return _digest("rfh", payload)


# Item 2: metadata-stripped runtime bytecode hash plus selector (fallback).


def _to_bytes(bytecode: str | bytes) -> bytes:
    if isinstance(bytecode, bytes):
        return bytecode
    s = bytecode[2:] if bytecode.startswith(("0x", "0X")) else bytecode
    if len(s) % 2:
        s = "0" + s
    return bytes.fromhex(s)


def _strip_metadata(code: bytes) -> bytes:
    """Drop the trailing CBOR metadata (``<cbor><2-byte length>``) so recompiles hash equal.

    Unrecognized trailers are left alone (only under-dedups).
    """
    if len(code) < 2:
        return code
    length = int.from_bytes(code[-2:], "big")
    if 0 < length <= len(code) - 2:
        return code[: -(length + 2)]
    return code


def _mask_immutables(code: bytes, immutable_references: dict[str, Any] | None) -> bytes:
    """Zero immutable byte ranges so per-deployment immutables don't split shared behaviour.

    ``immutable_references`` is solc's ``{astId: [{start, length}]}``, verified contracts only.
    """
    if not immutable_references:
        return code
    ba = bytearray(code)
    for entries in immutable_references.values():
        for entry in entries or []:
            try:
                start = int(entry["start"])
                length = int(entry["length"])
            except (KeyError, TypeError, ValueError):
                continue
            for i in range(start, min(start + length, len(ba))):
                ba[i] = 0
    return bytes(ba)


def bytecode_fallback_hash(
    runtime_bytecode: str | bytes,
    selector: str | None,
    *,
    immutable_references: dict[str, Any] | None = None,
) -> str:
    """The unverified fallback: stripped runtime bytecode plus selector.

    Sound (identical bytecode means identical behaviour) but under-dedups. Pass ``immutable_references`` on verified
    contracts.
    """
    code = _mask_immutables(_to_bytes(runtime_bytecode), immutable_references)
    code = _strip_metadata(code)
    return _digest("bfh", f"{selector or ''}:{code.hex()}")


def contract_surface_hash(
    runtime_bytecode: str | bytes,
    *,
    immutable_references: dict[str, Any] | None = None,
) -> str:
    """Stripped runtime bytecode hash of the whole contract, the projection-level key.

    No selector, since projections cover the whole entry surface.
    """
    code = _mask_immutables(_to_bytes(runtime_bytecode), immutable_references)
    code = _strip_metadata(code)
    return _digest("csh", code.hex())
