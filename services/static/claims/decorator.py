"""``@claim_matcher``: a matcher module declares its claim by decorating its trigger; auto-discovery imports the
module.
"""

from __future__ import annotations

from collections.abc import Callable

from .context import ClaimContext
from .registry import Gate, RegistryEntry, Trigger, register
from .types import ConsumerFamily, GrantClass


def _always(_ctx: ClaimContext) -> bool:
    return True


def claim_matcher(
    *,
    claim_id: str,
    sentence: str,
    legacy_projection: str | None,
    consumer_family: ConsumerFamily,
    grant_class: GrantClass,
    gate: Gate | None = None,
) -> Callable[[Trigger], Trigger]:
    """Register the decorated function as ``claim_id``'s trigger and return it unchanged.

    ``gate`` defaults to always-on.
    """

    def decorate(trigger: Trigger) -> Trigger:
        register(
            RegistryEntry(
                claim_id=claim_id,
                sentence=sentence,
                gate=gate or _always,
                trigger=trigger,
                legacy_projection=legacy_projection,
                consumer_family=consumer_family,
                grant_class=grant_class,
            )
        )
        return trigger

    return decorate
