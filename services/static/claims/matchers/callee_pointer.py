"""``callee_pointer.rotate`` — the contract changes a code pointer that another
of its entry points invokes at runtime (the measured-clean half of the retired
``hook_update`` class).

Use-link on IR destination *identity*, not name strings: the function writes a
callable scalar pointer ``X`` (address/contract-typed, hygiene-normal), and some
sibling entry point resolves a call destination to the same ``X`` state variable
and also moves value or writes a mapping (the ``transfer``-invokes-``hook``
shape). A bare mapping/allowance setter (ERC-20 ``approve``) writes no scalar
pointer, and an OZ-v5 namespaced pseudo-slot setter (``setLockBox``) is not
hygiene-normal — neither links to a sibling call, so neither fires.

First-time installs are excluded as setup: OZ initializer-family latches via
``tree_is_one_shot``, and manual ``require(pointer == address(0))`` latches
(a re-initializer that sets a pointer once) via ``writes_first_time_set_pointer``.
"""

from __future__ import annotations

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import MatchedEvidence
from . import _facts


@claim_matcher(
    claim_id="callee_pointer.rotate",
    sentence="changes a code pointer that another entry point of this contract invokes at runtime",
    legacy_projection="hook_update",
    consumer_family="control_plane",
)
def callee_pointer_rotate(ctx: ClaimContext, function: str) -> MatchedEvidence | None:
    tree = ctx.predicate_tree(function)
    if tree is not None and _facts.tree_is_one_shot(tree):
        # An initializer setting a pointer for the first time is setup, not a
        # runtime rotation.
        return None
    pointers = _facts.pointer_write_targets(ctx, function)
    if not pointers:
        return None
    if _facts.writes_first_time_set_pointer(ctx, function, pointers):
        # A manual set-once latch (require(pointer == address(0))) that OZ's
        # initializer-family modifiers don't cover — still first-time setup.
        return None
    links: list[dict[str, str]] = []
    for pointer in pointers:
        sibling = _facts.sibling_invokes_pointer(ctx, function, pointer)
        if sibling is not None:
            links.append({"pointer": getattr(pointer, "name", ""), "invoked_by": sibling})
    if not links:
        return None
    return MatchedEvidence(
        tier="idiom_structural",
        witness={"kind": "use_link", "links": sorted(links, key=lambda link: link["pointer"])},
    )
