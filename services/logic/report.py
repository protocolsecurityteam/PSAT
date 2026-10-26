"""Readings of terms for reports: what a verdict says in words, never what decides it."""

from __future__ import annotations

from typing import Any


def openness_label(verdict: Any) -> str:
    """A verdict's openness in words: ``open`` only for an open proved for every unconfigured address,
    ``open_witnessed`` for one resting on what sampled strangers showed (``Verdict.witnessed``: never read as the
    proof), else ``restricted`` or ``not_determined``."""
    if verdict.openness == "open" and getattr(verdict, "witnessed", False):
        return "open_witnessed"
    return verdict.openness


def render(t: Any, depth: int = 0) -> str:
    """A short reading of a term, for reporting a gate."""
    if not isinstance(t, tuple) or not t:
        return repr(t)
    if depth > 5:
        return "..."
    if not isinstance(t[0], str):
        return "(" + ", ".join(render(x, depth + 1) for x in t) + ")"
    kind = t[0]
    sub = lambda x: render(x, depth + 1)  # noqa: E731
    if kind == "const":
        v = t[1]
        return hex(v) if isinstance(v, int) and not isinstance(v, bool) and v > 2**64 else repr(v)
    if kind in ("and", "or"):
        return "(" + f" {kind} ".join(sorted(sub(x) for x in t[1])) + ")"
    if kind == "not":
        return "!" + sub(t[1])
    if kind == "cmp":
        return f"{sub(t[2])} {t[1]} {sub(t[3])}"
    if kind == "load":
        name = t[2] if isinstance(t[2], str) else f"namespaced:{t[2][-1]}"
        return name + "".join(f"[{sub(s)}]" if k == "k" else f".{s}" for k, s in t[3])
    if kind == "arg":
        return str(t[1])
    if kind in ("caller", "origin", "this"):
        return kind
    if kind == "call":
        return f"{sub(t[1])}.{t[2]}({', '.join(sub(a) for a in t[3])})"
    if kind in ("ok", "caught", "conv"):
        return sub(t[1] if kind != "conv" else t[2])
    if kind == "op":
        return f"{t[1]}({', '.join(sub(a) for a in t[2])})"
    if kind == "hash":
        return f"H({', '.join(sub(a) for a in t[2])})"
    return f"{kind}(" + ", ".join(sub(x) for x in t[1:]) + ")"
