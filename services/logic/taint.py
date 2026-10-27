"""Which parts of a success formula depend on who calls.

The caller's identity enters a function as ``msg.sender``, ``tx.origin`` or a signature's signer. A callee's own
``msg.sender`` is this contract, but its ``tx.origin`` is still the caller's: ``verdict`` inlines a followed callee
that reads it, so the root shows in the formula, and a callee not followed is never taken to be free of it
(``decide``). Within the formula, a term counts as depending on the caller when one of those roots occurs in it, when
the lowering couldn't express it and didn't mark it alike for every caller (``loop:N:anyone``, ``loop:N:nobody``),
when it is a memory word read back from where the lowering lost track (``mload``), or when it is of a kind this module
doesn't know: what isn't shown free of the caller counts as depending on it. Whatever else the formula requires holds
for every caller alike.
"""

from __future__ import annotations

from typing import Any

from .terms import IDENTITY_KINDS, Term, conjuncts, stable, subterms


def singles_out_nobody(unknown_term: Term) -> bool:
    """An unknown the lowering marked as the same for every caller (``loop:N:anyone``, the same for every argument
    too; ``loop:N:nobody``, steered by the arguments alone)."""
    return isinstance(unknown_term[1], str) and unknown_term[1].endswith((":anyone", ":nobody"))


# Term kinds whose dependence on the caller is their operands'. Not ``delegate``: the code it runs sees this caller.
_KINDS = frozenset(
    {
        "this", "sig", "callvalue", "calldatasize", "arg", "const", "time", "load", "rawload", "hash", "enc",
        "call", "immutable", "item", "abi", "ok", "caught", "len", "elem", "slice", "op", "conv", "ite", "cmp", "not",
        "and", "or", "opaque", "assumed", "retsize", "codesize", "balance", "codehash", "code", "constant", "array",
        "struct", "slot",
    }
)  # fmt: skip


def tainted(t: Term) -> bool:
    """Whether ``t`` may read otherwise for another caller, everything else the same."""
    if not isinstance(t, tuple) or not t:
        return False
    cache = t.__dict__ if isinstance(t, Term) else None
    if cache is not None and "_tainted" in cache:
        return cache["_tainted"]
    kind = t[0]
    if not isinstance(kind, str) or (not isinstance(t, Term) and kind not in _KINDS | IDENTITY_KINDS | {"unknown"}):
        result = any(tainted(x) for x in _parts(t))  # a plain tuple holding terms (a path, an argument list)
    elif kind in IDENTITY_KINDS:
        result = True
    elif kind == "unknown":
        result = not singles_out_nobody(t)
    elif kind == "opaque" and str(t[1]).startswith("mload"):
        result = True
    elif kind not in _KINDS:
        result = True
    else:
        result = any(tainted(x) for x in _parts(t[1:]))
    if cache is not None:
        cache["_tainted"] = result
    return result


def _parts(items: Any) -> list:
    out: list = []
    for item in items:
        if isinstance(item, frozenset):
            out.extend(item)
        elif isinstance(item, tuple):
            out.append(item)
    return out


def split(formula: Term) -> tuple[tuple[Term, ...], tuple[Term, ...]]:
    """The top-level conjuncts of ``formula`` that depend on who calls (the core), and those that don't."""
    parts = sorted((c for c in conjuncts(formula) if c[0] != "const"), key=stable)
    return tuple(c for c in parts if tainted(c)), tuple(c for c in parts if not tainted(c))


def unknown_gap(label: Any) -> str:
    """An unknown's label as a gap: ``unknown:<label>``, but a call ``verdict`` kept from being read as the same for
    everyone by its own name (``origin:<sig>``, ``unfollowed:<sig>``, ``read_failed:call_target:<sig>``,
    ``unknown:call_target:<why>:<sig>``)."""
    text = str(label)
    named = ("origin:", "unfollowed:", "read_failed:", "unknown:call_target:")
    return text if text.startswith(named) else f"unknown:{text}"


def unknown_labels(t: Term) -> list[str]:
    """What the lowering couldn't express in ``t``, by its labels."""
    return [unknown_gap(u[1]) for u in subterms(t, "unknown")] + [f"unknown:{o[1]}" for o in subterms(t, "opaque")]
