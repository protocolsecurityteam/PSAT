"""``rate_limit.consume`` — a throughput limiter the function passes through.

**A FACT AT ZERO SEVERITY WEIGHT, and deliberately not part of the ``amount_kind``
lattice.** Every member of that lattice describes the MAGNITUDE that can leave
(``whole_balance``, ``capped_by_balance``, ``fixed_constant``), and a refilling
bucket is not a magnitude: it bounds throughput per window, not total loss. Over
N windows the extractable total under a refilling limiter is unbounded, so
crediting it as a ceiling would invent the kind of discount
``SCORING_INVARIANTS.md`` §7 forbids. The honest move is to publish the fact and
let it contribute nothing to severity — which is what ``consumer_family="fact"``
means structurally, not merely by convention.

**But the argument inverts on configuration, and that is why the configuration is
part of the fact rather than a footnote.** ``setRefillRate(id, 0)`` is one
governance call away, and a bucket created with a zero refill rate is a ONE-SHOT
total cap, not a throughput cap; the limiter source further documents
``capacity == 0`` on an existing bucket as *reverting*, which makes a zero
capacity a **pause in disguise**. So the same call site means three different
things depending on two numbers:

===================  ==========================  ===========================
observed             what the limiter is         severity meaning
===================  ==========================  ===========================
``refill_rate > 0``  a throughput cap            bounds a window, not a total
``refill_rate == 0`` a one-shot total cap        DOES bound total extraction
``capacity == 0``    a freeze                    a pause in disguise
===================  ==========================  ===========================

Both numbers are CHAIN state — no static pass can read them — so the witness
carries them as explicit three-state fields that read ``not_determined`` here,
alongside the selectors a later resolution stage would read them WITH. A future
scorer can then tell the three cases apart; it can never mistake "we did not read
it" for "zero", which under the table above is the difference between a rate
limit and a freeze.

Detection is by the limiter's PUBLISHED selectors on the call sink, never by an
identifier: ``consume(bytes32,uint64)`` / ``consumeToken(bytes32,uint64)``. A
contract that merely names a variable ``rateLimiter`` earns nothing.
"""

from __future__ import annotations

from typing import Any

from ..context import ClaimContext, abi_selector
from ..decorator import claim_matcher
from ..types import ClaimEvidence
from . import _facts

# The bucket-limiter ABI, by published signature. ``consume`` reverts on
# exhaustion; ``consumeToken`` is the token-side entry with the same shape.
CONSUME = abi_selector("consume(bytes32,uint64)")
CONSUME_TOKEN = abi_selector("consumeToken(bytes32,uint64)")
CONSUME_SELECTORS = {CONSUME: "consume", CONSUME_TOKEN: "consume_token"}

# How a resolution stage reads the two discriminators off-chain. Published so the
# witness names its own follow-up read rather than leaving a consumer to guess
# which getter holds the numbers.
GET_LIMIT = abi_selector("getLimit(bytes32)")
SET_CAPACITY = abi_selector("setCapacity(bytes32,uint64)")
SET_REFILL_RATE = abi_selector("setRefillRate(bytes32,uint64)")

_UNREAD = {"state": "not_determined", "source": "chain_state"}


def _mandatory_callee_names(ctx: ClaimContext, function: str) -> set[str]:
    """Bare callee names named by a MANDATORY revert-gate leaf of ``function``.

    A limiter call the path can route around bounds nothing, so "is this consume
    on every path to the sink" is a real question — and one whose negative answer
    is not provable from a tree that simply does not mention the callee."""
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
        # Three states, not a bool: a tree that does not name the callee is not
        # proof that the call is skippable.
        "mandatory": (
            {"state": "proven"}
            if any(str(sink.get("target") or "").rsplit(".", 1)[-1] in mandatory_names for sink in sinks)
            else {"state": "not_determined"}
        ),
        # THE DISCRIMINATORS. Present-and-unread, never absent: a consumer that
        # read an absent field as 0 would read a throughput cap as a freeze.
        "capacity": dict(_UNREAD),
        "refill_rate": dict(_UNREAD),
        # Derivable from the two above, so it inherits their state. It is NOT
        # flatly ``false``: a zero-refill bucket really does bound total
        # extraction, and asserting otherwise would be the mirror of the
        # over-claim this whole family exists to remove.
        "bounds_total_extraction": dict(_UNREAD),
        "config_reader": {
            "get_limit_selector": GET_LIMIT,
            "set_capacity_selector": SET_CAPACITY,
            "set_refill_rate_selector": SET_REFILL_RATE,
        },
        # Stated in the payload so a consumer cannot reach the wrong conclusion
        # from the numbers once they are read.
        "severity_weight": 0,
        "interpretation": (
            "refill_rate > 0: throughput cap only (does NOT bound total extraction). "
            "refill_rate == 0: one-shot total cap. "
            "capacity == 0: a freeze — a pause in disguise. "
            "not_determined on either: no severity conclusion may be drawn."
        ),
    }
    return ClaimEvidence(tier="idiom_structural", witness=witness)
