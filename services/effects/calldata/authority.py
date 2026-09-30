"""Authority-change plan synthesis."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # typing-only: the effects plane stays off static's runtime import graph
    pass


from services.effects.selection import Candidate

from .encoding import encode_calldata
from .facts import ContractFacts, FunctionFacts
from .flows import _selector_of
from .plans import _AUTHORITY_ROLES, AuthorityPlanInputs
from .trees import _authority_roles, _gate_ref, _mandatory_state_vars

logger = logging.getLogger("services.effects.calldata")


def _normal_state_pairs(fn: FunctionFacts) -> set[tuple[str, str | None]]:
    """``(var, member)`` pairs F writes, limited to the hygiene class role-fact consumers trust and to body-origin
    writes. Guard-origin entries are the modifier's own bookkeeping, not an effect F causes (see
    :func:`_latch_pairs`).
    """
    pairs: set[tuple[str, str | None]] = set()
    for write in fn.effect_info.get("state_writes") or []:
        if not isinstance(write, dict) or write.get("hygiene_class") != "normal":
            continue
        if write.get("origin") != "body":
            continue
        var = write.get("var")
        if not var:
            continue
        member_path = write.get("member_path") or []
        pairs.add((str(var), str(member_path[0]) if member_path else None))
    return pairs


def _authority_gate_target(facts: ContractFacts, fn: FunctionFacts) -> str | None:
    """A function G whose mandatory caller-authority gate reads state F writes (the gate F can move).

    Sorted pick; ``None`` if none.
    """
    written = _normal_state_pairs(fn)
    if not written:
        return None
    for name in sorted(facts.trees):
        if name == fn.full_name:
            continue
        tree = facts.trees[name]
        if not _authority_roles(tree) & set(_AUTHORITY_ROLES):
            continue
        # Var-level, as in ``guarded_functions``.
        if _mandatory_state_vars(tree) & {var for var, _member in written}:
            return name
    return None


def synthesize_authority(candidate: Candidate, facts: ContractFacts, fn: FunctionFacts) -> AuthorityPlanInputs | None:
    """Applicable when F writes state another function reads as a mandatory caller-authority gate.

    The mutation keeps encoder defaults: the recipe only opens on a gate that opens to all random identities, so
    guessing a grantee couldn't help.
    """
    target = _authority_gate_target(facts, fn)
    if target is None:
        return None
    principal = candidate.principal_addresses[0] if candidate.principal_addresses else None
    if not principal:
        return None
    probe_sig = facts.canonical_signature(target)
    probe_selector = _selector_of(probe_sig)
    if not probe_selector:
        return None
    mutate = encode_calldata(fn.selector, fn.canonical_signature)
    probe = encode_calldata(probe_selector, probe_sig)
    if mutate is None or probe is None:
        return None
    return AuthorityPlanInputs(
        contract_address=candidate.probe_target,
        principal=principal,
        mutate_calldata=mutate,
        probe_calldata=probe,
        probe_function=target,
        gate_ref=_gate_ref(fn.tree),
    )
