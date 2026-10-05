"""``callee_pointer.rotate``: the function writes a callable scalar pointer that a sibling entry point calls while
moving value or writing a mapping.

Linked on IR destination identity, not names. Plain mapping setters and namespaced pseudo-slots don't link. First-time
installs (initializers, ``require(pointer == address(0))`` latches) are setup, not rotation.
"""

from __future__ import annotations

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import ClaimEvidence
from . import _facts


@claim_matcher(
    claim_id="callee_pointer.rotate",
    sentence="changes a code pointer that another entry point of this contract invokes at runtime",
    legacy_projection="hook_update",
    consumer_family="control_plane",
    grant_class="control.gate",
)
def callee_pointer_rotate(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    tree = ctx.predicate_tree(function)
    if tree is not None and _facts.tree_is_one_shot(tree):
        return None
    pointers = _facts.pointer_write_targets(ctx, function)
    if not pointers:
        return None
    if _facts.writes_first_time_set_pointer(ctx, function, pointers):
        return None
    links: list[dict[str, str]] = []
    for pointer in pointers:
        sibling = _facts.sibling_invokes_pointer(ctx, function, pointer)
        if sibling is not None:
            links.append({"pointer": getattr(pointer, "name", ""), "invoked_by": sibling})
    if not links:
        return None
    return ClaimEvidence(
        tier="idiom_structural",
        witness={"kind": "use_link", "links": sorted(links, key=lambda link: link["pointer"])},
    )
