"""``pause.set`` / ``pause.unset`` — the contract toggles a flag that blocks or
unblocks its own state-changing entry points.

Two tiers share one derivation:

* **standard_exact** — OZ ``Pausable``: the contract publishes the standard's
  full entry set (``pause()`` + ``unpause()`` + the ``paused()`` view), and the
  claim is on one of the two toggles. A ``bool public paused`` counts: Solidity
  publishes ``paused()`` for it, so this is the contract's ABI, not its
  vocabulary. Nothing here inspects what the flag variable is *called* — a
  pauser whose latch is named anything else still reaches standard_exact, and a
  contract that merely spells a flag ``paused`` without the standard's ABI does
  not.
* **idiom_structural** — the PauseAnalyzer idiom with its four fixes, read off
  Plane-0 facts: the flag is a ``bool`` state-write (member-path facts recover
  struct-member and inherited-private flags) that another entry point reads as a
  *mandatory* revert gate (kills a branch-mode selector such as OneSig
  ``executorRequired``), the writer is caller/authority-gated, and it is not a
  one-shot initializer latch.
"""

from __future__ import annotations

from ..context import ClaimContext, abi_selector
from ..decorator import claim_matcher
from ..types import MatchedEvidence
from . import _facts

# OpenZeppelin Pausable's published ABI.
PAUSE = abi_selector("pause()")
UNPAUSE = abi_selector("unpause()")
PAUSED = abi_selector("paused()")
_TOGGLE_SELECTORS = frozenset({PAUSE, UNPAUSE})


def _oz_pausable_standard(ctx: ClaimContext) -> bool:
    return ctx.has_selectors(PAUSE, UNPAUSE, PAUSED)


def _pause_evidence(ctx: ClaimContext, function: str, want: str) -> MatchedEvidence | None:
    targets = _facts.function_pause_targets(ctx, function)
    if not targets:
        return None
    tree = ctx.predicate_tree(function)
    # Effect detection is independent of authority. An unguarded pauser is a
    # public capability, not an absence. Authority resolution is a later claim.
    if tree is not None and _facts.tree_is_one_shot(tree):
        return None

    fn = _facts.contract_function(ctx, function)
    gate_reads = _facts.mandatory_gate_reads(ctx)
    namespaced = _facts.namespaced_write_vars(ctx, function)
    matched: list[dict[str, str | None]] = []
    for var, member in sorted(targets, key=lambda pair: (pair[0], pair[1] or "")):
        # A namespaced latch is written through a local storage pointer, so the
        # member the GUARD reads on this slot is the only handle on which flag
        # the assignment touched.
        aliases = frozenset(m for v, m in gate_reads if v == var and m) if member is None else frozenset()
        polarity = _facts.toggle_polarity(fn, var, member, alias_members=aliases) if fn is not None else "both"
        if var in namespaced and member is None:
            # Resolve the exact member written through the local storage
            # pointer. A namespaced slot also carries owner/admin fields; a
            # memberless witness makes their authority guards look like pause
            # victims merely because they share the slot.
            matched.extend(
                {"var": var, "member": alias}
                for alias in sorted(aliases)
                if fn is not None and _facts.toggle_polarity(fn, var, None, alias_members=frozenset({alias})) == want
            )
            continue
        declared_types = _facts.pause_target_declared_types(ctx, function, (var, member))
        if polarity == "both" and declared_types & {"uint8", "uint256"}:
            # Parameter-driven bitmap writes need a directional proof. A sibling
            # constant writer such as pauseAll() can still establish pause.set;
            # this ambiguous function establishes neither direction by itself.
            continue
        if polarity in (want, "both"):
            matched.append({"var": var, "member": member})
    if not matched:
        return None

    standard = ctx.canonical_selector(function) in _TOGGLE_SELECTORS and _oz_pausable_standard(ctx)
    return MatchedEvidence(
        tier="standard_exact" if standard else "idiom_structural",
        witness={
            "kind": "pause_flag",
            "flags": matched,
            "polarity": want,
            "affected_functions": _facts.pause_affected_functions(ctx, targets),
        },
    )


@claim_matcher(
    claim_id="pause.set",
    sentence="sets a flag that blocks other state-changing entry points of this contract (pauses it)",
    legacy_projection="pause_toggle",
    consumer_family="control_plane",
)
def pause_set(ctx: ClaimContext, function: str) -> MatchedEvidence | None:
    return _pause_evidence(ctx, function, "set")


@claim_matcher(
    claim_id="pause.unset",
    sentence="clears a flag that blocks other state-changing entry points of this contract (unpauses it)",
    legacy_projection="pause_toggle",
    consumer_family="control_plane",
)
def pause_unset(ctx: ClaimContext, function: str) -> MatchedEvidence | None:
    return _pause_evidence(ctx, function, "unset")
