"""Which parts of a success formula depend on who calls.

The caller's identity enters a function only as ``msg.sender``, ``tx.origin`` or a signature's signer, and reaches
another contract only through what is handed to it: inside, ``msg.sender`` is this contract. So a term depends on
the identity exactly when one of those roots occurs in it, a call's answer through its target and arguments alone,
and a term the lowering couldn't express counts unless the lowering marked it the same for every caller
(``loop:N:anyone``, ``loop:N:nobody``; an ``opaque`` value carries the roots it was built from). Whatever else the
formula requires holds for every caller alike: a condition on the call, not part of who may make it.
"""

from __future__ import annotations

from .terms import IDENTITY_KINDS, Term, conjuncts, contains, stable, subterms


def singles_out_nobody(unknown_term: Term) -> bool:
    """An unknown the lowering marked as the same for every caller (``loop:N:anyone``, the same for every argument
    too; ``loop:N:nobody``, steered by the arguments alone)."""
    return isinstance(unknown_term[1], str) and unknown_term[1].endswith((":anyone", ":nobody"))


def tainted(t: Term) -> bool:
    """Whether ``t`` may read otherwise for another caller, everything else the same."""
    return contains(t, IDENTITY_KINDS) or any(not singles_out_nobody(u) for u in subterms(t, "unknown"))


def split(formula: Term) -> tuple[tuple[Term, ...], tuple[Term, ...]]:
    """The top-level conjuncts of ``formula`` that depend on who calls (the core), and those that don't."""
    parts = sorted((c for c in conjuncts(formula) if c[0] != "const"), key=stable)
    return tuple(c for c in parts if tainted(c)), tuple(c for c in parts if not tainted(c))


def unknown_labels(t: Term) -> list[str]:
    """What the lowering couldn't express in ``t``, by its labels."""
    return [f"unknown:{u[1]}" for u in subterms(t, "unknown")] + [f"unknown:{o[1]}" for o in subterms(t, "opaque")]
