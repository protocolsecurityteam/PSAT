"""Bytecode and standardized-kernel identities for effects deduplication."""

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
