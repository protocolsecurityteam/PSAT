"""Behavioral-hash identity for effects dedup (EFFECTS_RESOLUTION_SPEC §7).

Three of the four ladder rungs. The bytecode-region lifter (§7 item 4) needs an
EVM CFG recovery pass this repo does not have and is explicitly out — nothing
here assumes it.

The naming trap this defends against: the ``PausableUntil`` mixin is
byte-identical across 11 contracts, but eETH/weETH *override* ``pauseUntil()``
for stricter gating. Same name, same inherited file, different gate — so the
sound key is the hash of the *resolved* function (what executes), never a
declared-name or file hash (inv. 2). The override and the mixin default must
hash apart.

All function-shaped access is duck-typed via ``getattr`` (mirroring
``contract_analysis_pipeline/effects/build.py``), so the normalizer runs on real
Slither ``Function``/``Modifier`` objects in production and on lightweight
structural doubles in the offline suite without a solc compile.
"""

from __future__ import annotations

import hashlib
from typing import Any

# Bump to invalidate every stored behavioral hash when the normalization below
# changes (older cache rows then miss and re-simulate rather than transfer a
# hash computed under different rules).
_HASH_SCHEMA_VERSION = 1

_SEP = "\x1f"


def _digest(domain: str, payload: str) -> str:
    h = hashlib.sha256()
    h.update(f"{domain}:{_HASH_SCHEMA_VERSION}:".encode())
    h.update(payload.encode("utf-8"))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Item 1 — normalized resolved-IR/CFG hash of the resolved function.
# ---------------------------------------------------------------------------


def _fn_key(fn: Any) -> Any:
    return getattr(fn, "canonical_name", None) or getattr(fn, "full_name", None) or id(fn)


def _has_body(fn: Any) -> bool:
    return bool(getattr(fn, "nodes", None))


def _var_role(v: Any) -> str:
    """Structural role of an operand with *names and literal values stripped*.

    Solidity builtins (``msg.sender``, ``block.timestamp``) keep their name —
    that is semantic identity, not a user-chosen label — so a caller-gate and a
    time check stay distinguishable. ``Constant`` collapses to a nameless token
    so an immutable/literal value never enters the hash (a per-deployment
    immutable must not split a shared kernel). Everything else contributes only
    its variable *class* (state vs local vs temporary), never its name.
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
    # Inline internal/library callees (the compiler does; behavior is theirs).
    # External/high-level calls are opaque cross-contract edges and are NOT
    # inlined — only their op token participates.
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
    """Canonical token stream for a function/modifier body + inlined callees.

    ``visited`` is threaded as an immutable set copied per descent so mutual
    recursion terminates without collapsing independent sibling calls."""
    key = _fn_key(unit)
    if key in visited:
        return ["<rec>"]
    visited = visited | {key}
    toks: list[str] = []
    # Modifier gates are behavioral and are what the override tightens — hash
    # them alongside the body so a stricter-gated override diverges from its
    # mixin default even when the two bodies match.
    for mod in getattr(unit, "modifiers", []) or []:
        toks.append("MOD:")
        toks.extend(_normalize_unit(mod, visited))
    for node in getattr(unit, "nodes", []) or []:
        toks.append("N:" + str(getattr(node, "type", "") or ""))
        for ir in getattr(node, "irs", []) or []:
            toks.extend(_normalize_ir(ir, visited))
    return toks


def resolved_function_hash(function: Any) -> str:
    """§7 item 1 — the primary key: the normalized resolved-IR/CFG hash.

    Compiled-structure-derived, name- and literal-free. The caller is
    responsible for override resolution (passing the *resolved* function object
    for the target contract); this hashes what that function executes, inlining
    internal callees and folding in modifier gates."""
    payload = _SEP.join(_normalize_unit(function, frozenset()))
    return _digest("rfh", payload)


# ---------------------------------------------------------------------------
# Item 2 — metadata-stripped whole-runtime-bytecode hash + selector (fallback).
# ---------------------------------------------------------------------------


def _to_bytes(bytecode: str | bytes) -> bytes:
    if isinstance(bytecode, bytes):
        return bytecode
    s = bytecode[2:] if bytecode.startswith(("0x", "0X")) else bytecode
    if len(s) % 2:
        s = "0" + s
    return bytes.fromhex(s)


def _strip_metadata(code: bytes) -> bytes:
    """Drop the trailing CBOR metadata block.

    Solidity appends ``<cbor metadata (L bytes)><2-byte big-endian L>``; the
    same source compiled at different times or with a different --metadata hash
    differs only there, so removing it recovers legitimate dedup hits. Left
    untouched when the trailer doesn't look like a length-prefixed block
    (unverified/exotic bytecode just hashes whole — sound, only under-dedups)."""
    if len(code) < 2:
        return code
    length = int.from_bytes(code[-2:], "big")
    if 0 < length <= len(code) - 2:
        return code[: -(length + 2)]
    return code


def _mask_immutables(code: bytes, immutable_references: dict[str, Any] | None) -> bytes:
    """Zero every immutable byte-range so per-deployment immutables (baked into
    the runtime bytecode) don't over-split an otherwise-shared behavior.

    ``immutable_references`` is the solc metadata shape:
    ``{astId: [{"start": int, "length": int}, ...]}`` with offsets into the
    deployed/runtime bytecode. Only available on verified contracts — a
    ``None``/empty arg just leaves the immutables in place (safe over-split)."""
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
    """§7 item 2 — the unverified fallback: metadata-stripped whole-runtime-
    bytecode hash + selector.

    Sound by construction: identical whole bytecode => identical dispatch =>
    identical per-selector behavior. It under-dedups (a contract sharing F but
    differing elsewhere hashes apart) — extra simulations, never a wrong
    transfer. On verified contracts pass ``immutable_references`` to mask
    immutables and recover the hits they would otherwise split."""
    code = _mask_immutables(_to_bytes(runtime_bytecode), immutable_references)
    code = _strip_metadata(code)
    return _digest("bfh", f"{selector or ''}:{code.hex()}")


def contract_surface_hash(
    runtime_bytecode: str | bytes,
    *,
    immutable_references: dict[str, Any] | None = None,
) -> str:
    """Metadata-stripped whole-runtime-bytecode hash of the *contract* — the
    projection-level cache key (§7). One hasher serves both cache levels; the
    only difference from ``bytecode_fallback_hash`` is that no selector
    participates, because a projection (blast radius, authorization delta) is a
    property of the whole entry-point surface, not one function."""
    code = _mask_immutables(_to_bytes(runtime_bytecode), immutable_references)
    code = _strip_metadata(code)
    return _digest("csh", code.hex())
