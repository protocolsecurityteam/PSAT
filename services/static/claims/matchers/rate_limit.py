"""``rate_limit.consume``: a throughput limiter the function passes through.

Published at zero severity weight and kept out of the ``amount_kind`` lattice: a refilling
bucket bounds throughput per window, not total loss, so crediting it as a ceiling would invent
a discount. But the meaning depends on two chain-state numbers:

===================  ==========================  ===========================
observed             what the limiter is         severity meaning
===================  ==========================  ===========================
``refill_rate > 0``  a throughput cap            bounds a window, not a total
``refill_rate == 0`` a one-shot total cap        DOES bound total extraction
``capacity == 0``    a freeze                    a pause in disguise
===================  ==========================  ===========================

No static pass can read them, so the witness carries them as ``not_determined`` along with the
getter that would. Detected by the limiter's published selectors, never an identifier.
"""

from __future__ import annotations

from typing import Any

from ..context import ClaimContext, abi_selector
from ..decorator import claim_matcher
from ..types import ClaimEvidence
from . import _facts

# ``consume`` reverts on exhaustion; ``consumeToken`` has the same shape.
CONSUME = abi_selector("consume(bytes32,uint64)")
CONSUME_TOKEN = abi_selector("consumeToken(bytes32,uint64)")
CONSUME_SELECTORS = {CONSUME: "consume", CONSUME_TOKEN: "consume_token"}

# The getter a resolution stage would read the discriminators with.
GET_LIMIT = abi_selector("getLimit(bytes32)")
SET_CAPACITY = abi_selector("setCapacity(bytes32,uint64)")
SET_REFILL_RATE = abi_selector("setRefillRate(bytes32,uint64)")

_UNREAD = {"state": "not_determined", "source": "chain_state"}


def _mandatory_callee_names(ctx: ClaimContext, function: str) -> set[str]:
    """Callee names named by a mandatory revert-gate leaf; a tree that doesn't mention the callee doesn't prove it
    skippable.
    """
    tree = ctx.predicate_tree(function)
    if tree is None:
        return set()
    names: set[str] = set()
    for leaf, _path in _facts._mandatory_leaves_with_paths(tree):
        name = _facts._leaf_callee_name(leaf)
        if name:
            names.add(name)
    return names


@claim_matcher(
    claim_id="rate_limit.consume",
    sentence="passes an amount through a bucket rate limiter",
    legacy_projection=None,
    consumer_family="fact",
    grant_class="fact",
)
def rate_limit_consume(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    sinks = [
        sink
        for sink in _facts.body_sinks(ctx, function)
        if sink.get("kind") == "external_call" and sink.get("selector") in CONSUME_SELECTORS
    ]
    if not sinks:
        return None
    mandatory_names = _mandatory_callee_names(ctx, function)
    kinds = sorted({CONSUME_SELECTORS[str(sink["selector"])] for sink in sinks})
    witness: dict[str, Any] = {
        "kind": "limiter_consume",
        "sink_ids": sorted(str(sink["id"]) for sink in sinks if sink.get("id")),
        "callee_selectors": sorted({str(sink["selector"]) for sink in sinks}),
        "consume_kinds": kinds,
        "mandatory": (
            {"state": "proven"}
            if any(str(sink.get("target") or "").rsplit(".", 1)[-1] in mandatory_names for sink in sinks)
            else {"state": "not_determined"}
        ),
        # Present-and-unread, never absent: an absent field read as 0 would turn a throughput cap into a freeze.
        "capacity": dict(_UNREAD),
        "refill_rate": dict(_UNREAD),
        # Inherits their state; a zero-refill bucket really does bound total extraction.
        "bounds_total_extraction": dict(_UNREAD),
        "config_reader": {
            "get_limit_selector": GET_LIMIT,
            "set_capacity_selector": SET_CAPACITY,
            "set_refill_rate_selector": SET_REFILL_RATE,
        },
        "severity_weight": 0,
        "interpretation": (
            "refill_rate > 0: throughput cap only (does NOT bound total extraction). "
            "refill_rate == 0: one-shot total cap. "
            "capacity == 0: a freeze — a pause in disguise. "
            "not_determined on either: no severity conclusion may be drawn."
        ),
    }
    return ClaimEvidence(tier="idiom_structural", witness=witness)
