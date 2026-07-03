"""``pause.set`` / ``pause.unset`` — the contract toggles a flag that blocks or
unblocks its own state-changing entry points.

Two tiers share one derivation:

* **standard_exact** — OZ ``Pausable``: ``pause()`` + ``unpause()`` siblings and
  a canonical ``{paused,isPaused,_paused}`` flag (or a ``paused()``/``isPaused()``
  view), matched on those two functions.
* **idiom_structural** — the PauseAnalyzer idiom with its four fixes, read off
  Plane-0 facts: the flag is a ``bool`` state-write (member-path facts recover
  struct-member and inherited-private flags) that another entry point reads as a
  *mandatory* revert gate (kills a branch-mode selector such as OneSig
  ``executorRequired``), the writer is caller/authority-gated, and it is not a
  one-shot initializer latch.
"""

from __future__ import annotations

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import ClaimEvidence
from . import _facts

_CANONICAL_FLAG_NAMES = frozenset({"paused", "isPaused", "_paused"})


def _oz_pausable_standard(ctx: ClaimContext) -> bool:
    if not ctx.has_functions("pause", "unpause"):
        return False
    if any(var in _CANONICAL_FLAG_NAMES and member is None for var, member in _facts.pause_targets(ctx)):
        return True
    return ctx.has_functions("paused") or ctx.has_functions("isPaused")


def _pause_evidence(ctx: ClaimContext, function: str, want: str) -> ClaimEvidence | None:
    targets = _facts.function_pause_targets(ctx, function)
    if not targets:
        return None
    tree = ctx.predicate_tree(function)
    if tree is None or not _facts.tree_is_authority_gated(tree) or _facts.tree_is_one_shot(tree):
        return None

    fn = _facts.contract_function(ctx, function)
    matched: list[dict[str, str | None]] = []
    for var, member in sorted(targets, key=lambda pair: (pair[0], pair[1] or "")):
        polarity = _facts.toggle_polarity(fn, var, member) if fn is not None else "both"
        if polarity in (want, "both"):
            matched.append({"var": var, "member": member})
    if not matched:
        return None

    standard = _oz_pausable_standard(ctx) and function in ("pause()", "unpause()")
    return ClaimEvidence(
        tier="standard_exact" if standard else "idiom_structural",
        witness={"kind": "pause_flag", "flags": matched, "polarity": want},
    )


@claim_matcher(
    claim_id="pause.set",
    sentence="sets a flag that blocks other state-changing entry points of this contract (pauses it)",
    legacy_projection="pause_toggle",
    consumer_family="control_plane",
)
def pause_set(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    return _pause_evidence(ctx, function, "set")


@claim_matcher(
    claim_id="pause.unset",
    sentence="clears a flag that blocks other state-changing entry points of this contract (unpauses it)",
    legacy_projection="pause_toggle",
    consumer_family="control_plane",
)
def pause_unset(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    return _pause_evidence(ctx, function, "unset")
