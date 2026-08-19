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

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# authority-change
# ---------------------------------------------------------------------------


def _normal_state_pairs(fn: FunctionFacts) -> set[tuple[str, str | None]]:
    """``(var, member)`` pairs F writes, restricted to the hygiene class the
    role-fact consumers trust (a reentrancy latch or a constant is not an effect)
    and to body-origin writes.

    Same reason as :func:`_latch_pairs`: a guard-origin entry is the modifier's
    own bookkeeping read on F's gate, not an effect F causes, so it must not be
    taken as "the state F mutates" when picking a gate target. Narrower surface
    than the pause case — ``hygiene_class`` already excludes ``reentrancy_guard``
    — and measured impact on the etherfi candidate set was zero (10 candidates
    carry a guard-origin ``normal`` write; none of them selected a different gate
    target). Kept anyway: an unsound input path that today's data happens not to
    trip is how a wrong verdict reaches a protocol nobody sampled."""
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
    """A function G whose MANDATORY, caller-authority gate reads state that F
    writes — i.e. the gate F can move. Deterministic (sorted) pick; ``None`` when
    no such G exists."""
    written = _normal_state_pairs(fn)
    if not written:
        return None
    for name in sorted(facts.trees):
        if name == fn.full_name:
            continue
        tree = facts.trees[name]
        if not _authority_roles(tree) & set(_AUTHORITY_ROLES):
            continue
        # Var-level, for the same member-path reason as ``guarded_functions``.
        if _mandatory_state_vars(tree) & {var for var, _member in written}:
            return name
    return None


def synthesize_authority(candidate: Candidate, facts: ContractFacts, fn: FunctionFacts) -> AuthorityPlanInputs | None:
    """Applicable when F writes state that some other function reads as a
    mandatory caller-authority gate. The mutation keeps encoder defaults — we do
    not guess a grantee; the recipe only opens on a gate that opens to ALL the
    random identities, so a guessed one could never help."""
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
