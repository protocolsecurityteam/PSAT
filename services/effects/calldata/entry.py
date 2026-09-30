"""The synthesize entry point."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # typing-only: the effects plane stays off static's runtime import graph
    pass

from sqlalchemy.orm import Session

from services.effects.config import (
    EFFECT_CLASS_AUTHORITY_CHANGE,
    EFFECT_CLASS_FREEZE_PAUSE,
    EFFECT_CLASS_SUPPLY,
    EFFECT_CLASS_VALUE_OUT,
)
from services.effects.selection import Candidate

from .authority import synthesize_authority
from .facts import load_contract_facts, resolve_function
from .plans import CandidatePlanInputs
from .seeding import synthesize_pause
from .synthesize_value import synthesize_supply, synthesize_timelock, synthesize_value_out

logger = logging.getLogger("services.effects.calldata")


def synthesize(session: Session, candidate: Candidate) -> CandidatePlanInputs:
    """Build every derivable plan input for ``candidate``; missing facts give an all-``None`` bundle.

    Facts are read from the code-bearing address (artifacts live on the implementation's job); probes target
    ``candidate.probe_target`` (the deployment).
    """
    facts = load_contract_facts(session, candidate.contract_address)
    if facts is None:
        return CandidatePlanInputs()
    fn = resolve_function(facts, candidate.selector)
    if fn is None:
        return CandidatePlanInputs()
    # Blank candidates get every class; claim-enrolled ones only their re-enrolled families.
    allow = candidate.restrict_families

    def _allowed(family: str) -> bool:
        return allow is None or family in allow

    return CandidatePlanInputs(
        value_out=synthesize_value_out(candidate, fn) if _allowed(EFFECT_CLASS_VALUE_OUT) else None,
        supply=synthesize_supply(candidate, fn) if _allowed(EFFECT_CLASS_SUPPLY) else None,
        authority=synthesize_authority(candidate, facts, fn) if _allowed(EFFECT_CLASS_AUTHORITY_CHANGE) else None,
        pause=synthesize_pause(session, candidate, facts, fn) if _allowed(EFFECT_CLASS_FREEZE_PAUSE) else None,
        # A delayed executor is a value_out question Tier 1 can't ask.
        timelock=synthesize_timelock(session, candidate, facts, fn) if _allowed(EFFECT_CLASS_VALUE_OUT) else None,
    )
