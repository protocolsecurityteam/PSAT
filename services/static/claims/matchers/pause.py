"""``pause.set`` / ``pause.unset``: toggling a flag that blocks the contract's own entry points.

standard_exact: the full OZ Pausable ABI (``pause()``, ``unpause()``, ``paused()``, where a public bool counts), never
the flag's name. idiom_structural: a guarded write to a bool that another entry point reads as a mandatory revert gate,
excluding one-shot initializer latches.
"""

from __future__ import annotations

from ..context import ClaimContext, abi_selector
from ..decorator import claim_matcher
from ..types import ClaimEvidence
from . import _facts

PAUSE = abi_selector("pause()")
UNPAUSE = abi_selector("unpause()")
PAUSED = abi_selector("paused()")
_TOGGLE_SELECTORS = frozenset({PAUSE, UNPAUSE})


def _oz_pausable_standard(ctx: ClaimContext) -> bool:
    return ctx.has_selectors(PAUSE, UNPAUSE, PAUSED)


def _pause_evidence(ctx: ClaimContext, function: str, want: str) -> ClaimEvidence | None:
    targets = _facts.function_pause_targets(ctx, function)
    if not targets:
        return None
    tree = ctx.predicate_tree(function)
    if tree is None or not _facts.tree_is_authority_gated(tree) or _facts.tree_is_one_shot(tree):
        return None

    fn = _facts.contract_function(ctx, function)
    gate_reads = _facts.mandatory_gate_reads(ctx)
    namespaced = _facts.namespaced_write_vars(ctx, function)
    matched: list[dict[str, str | None]] = []
    for var, member in sorted(targets, key=lambda pair: (pair[0], pair[1] or "")):
        # Namespaced latches are written through a storage pointer; the member the guard reads identifies the flag.
        aliases = frozenset(m for v, m in gate_reads if v == var and m) if member is None else frozenset()
        polarity = _facts.toggle_polarity(fn, var, member, alias_members=aliases) if fn is not None else "both"
        if var in namespaced and polarity == "both":
            # An ERC-7201 slot holds a whole struct, so writing it proves nothing; only a constant-bool toggle of a
            # guard-read member counts.
            continue
        if polarity in (want, "both"):
            matched.append({"var": var, "member": member})
    if not matched:
        return None

    standard = ctx.canonical_selector(function) in _TOGGLE_SELECTORS and _oz_pausable_standard(ctx)
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
