"""``@claim_matcher`` — the ADD-only extension point for matcher agents.

A matcher module declares one claim by decorating its per-function trigger. The
decorator registers the claim (sentence, contract-level gate, consumer family)
and the trigger together, so a new matcher is a new module and
nothing else. The ``matchers`` package auto-discovery imports the module, which
runs the decorator.
"""

from __future__ import annotations

from collections.abc import Callable

from .context import ClaimContext
from .registry import Gate, RegistryEntry, Trigger, register
from .types import ConsumerFamily


def _always(_ctx: ClaimContext) -> bool:
    return True


def claim_matcher(
    *,
    claim_id: str,
    sentence: str,
    consumer_family: ConsumerFamily,
    gate: Gate | None = None,
) -> Callable[[Trigger], Trigger]:
    """Register the decorated function as the ``trigger`` for ``claim_id``.

    ``gate`` defaults to always-on (single-contract claims whose evidence is
    entirely in the per-function trigger). The trigger is returned unchanged so
    it stays independently testable.
    """

    def decorate(trigger: Trigger) -> Trigger:
        register(
            RegistryEntry(
                claim_id=claim_id,
                sentence=sentence,
                gate=gate or _always,
                trigger=trigger,
                consumer_family=consumer_family,
            )
        )
        return trigger

    return decorate
