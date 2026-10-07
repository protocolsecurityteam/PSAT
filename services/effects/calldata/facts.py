"""Contract/function fact loading and the per-session facts cache."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from weakref import WeakKeyDictionary

if TYPE_CHECKING:  # typing-only: the effects plane stays off static's runtime import graph
    pass

from sqlalchemy.orm import Session

from db.queue import get_artifact
from services.policy.effective_permissions import _abi_signature
from utils.logging import record_degraded

from .flows import _selector_of

logger = logging.getLogger("services.effects.calldata")


@dataclass(frozen=True)
class ContractFacts:
    address: str
    job_id: Any
    # Effects artifact ``functions``: full_name -> EffectInfo.
    effects: Mapping[str, Any] = field(default_factory=dict)
    # predicate_trees ``trees``: full_name -> guard tree.
    trees: Mapping[str, Any] = field(default_factory=dict)
    canonical_signatures: Mapping[str, str] = field(default_factory=dict)
    # contract_analysis value_flows (the shape with ``is_parameter``).
    legacy_value_flows: Mapping[str, list[dict[str, Any]]] = field(default_factory=dict)
    by_selector: Mapping[str, str] = field(default_factory=dict)
    # Effects artifact ``token_slots.entries``: mapping base slots the pause recipe seeds so token preconditions can't
    # hide entry points. Absent on older artifacts (seeding skipped).
    token_slots: tuple[Mapping[str, Any], ...] = ()

    def canonical_signature(self, full_name: str) -> str:
        return self.canonical_signatures.get(full_name) or _abi_signature(full_name)


@dataclass(frozen=True)
class FunctionFacts:
    full_name: str
    selector: str
    canonical_signature: str
    effect_info: Mapping[str, Any]
    tree: Any
    legacy_value_flows: tuple[dict[str, Any], ...]


# Per-session memo, weak on the Session so it dies with the unit of work.
_FACTS_CACHE: "WeakKeyDictionary[Session, dict[str, ContractFacts | None]]" = WeakKeyDictionary()


def load_contract_facts(session: Session, address: str) -> ContractFacts | None:
    """Load and index the static artifacts behind ``address`` (via ``find_analysis_job_for_address``, since proxies'
    artifacts live on the implementation job). ``None`` when there's no effects artifact.
    """
    cache = _FACTS_CACHE.setdefault(session, {})
    key = (address or "").lower()
    if key in cache:
        return cache[key]
    facts = _load_contract_facts_uncached(session, key)
    cache[key] = facts
    return facts


def _load_contract_facts_uncached(session: Session, address: str) -> ContractFacts | None:
    from services.resolution.capability_resolver import find_analysis_job_for_address

    try:
        lookup = find_analysis_job_for_address(session, address, required_artifact="effects", completed_only=False)
    except Exception as exc:
        # The lookup didn't answer (not "no facts"), so record degradation. ``contract_address`` because the formatter
        # drops extras colliding with the ambient ``address`` contextvar.
        context = {"contract_address": address, "exc_type": type(exc).__name__}
        record_degraded(phase="effects_calldata_facts", exc=exc, context=context)
        logger.warning(
            "effects calldata: analysis-job lookup failed; no contract facts for this address",
            extra=context,
        )
        return None
    if lookup is None:
        return None
    job_id = lookup.analysis_job.id

    effects_art = get_artifact(session, job_id, "effects")
    functions = effects_art.get("functions") if isinstance(effects_art, dict) else None
    if not isinstance(functions, dict) or not functions:
        return None

    trees_art = get_artifact(session, job_id, "predicate_trees")
    trees_art = trees_art if isinstance(trees_art, dict) else {}
    raw_trees = trees_art.get("trees")
    trees: dict[str, Any] = raw_trees if isinstance(raw_trees, dict) else {}
    canonical = {
        str(name): str(sig)
        for name, sig in (trees_art.get("canonical_signatures") or {}).items()
        if isinstance(sig, str) and "(" in sig and sig.endswith(")")
    }

    analysis = get_artifact(session, job_id, "contract_analysis")
    legacy_flows = _legacy_value_flow_map(analysis)

    raw_slots = effects_art.get("token_slots") if isinstance(effects_art, dict) else None
    slot_entries = raw_slots.get("entries") if isinstance(raw_slots, dict) else None
    token_slots = tuple(e for e in slot_entries if isinstance(e, dict)) if isinstance(slot_entries, list) else ()

    by_selector: dict[str, str] = {}
    for full_name, info in functions.items():
        if not isinstance(info, dict):
            continue
        artifact_selector = info.get("selector")
        if isinstance(artifact_selector, str) and artifact_selector.startswith("0x"):
            by_selector.setdefault(artifact_selector.lower(), str(full_name))
        # The canonical selector wins; an artifact stored before canonical lowering hashed the Slither spelling.
        sig = canonical.get(str(full_name)) or _abi_signature(str(full_name))
        computed = _selector_of(sig)
        if computed:
            by_selector[computed] = str(full_name)

    return ContractFacts(
        address=address,
        job_id=job_id,
        effects=functions,
        trees=trees,
        canonical_signatures=canonical,
        legacy_value_flows=legacy_flows,
        by_selector=by_selector,
        token_slots=token_slots,
    )


def _legacy_value_flow_map(analysis: Any) -> dict[str, list[dict[str, Any]]]:
    """``full_name -> value_flows`` from ``contract_analysis``, the only shape carrying ``is_parameter``."""
    out: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(analysis, dict):
        return out
    semantic = analysis.get("semantic_control")
    entries = semantic.get("semantic_functions") if isinstance(semantic, dict) else None
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        name = entry.get("function")
        flows = entry.get("value_flows")
        if isinstance(name, str) and isinstance(flows, list):
            out[name] = [f for f in flows if isinstance(f, dict)]
    return out


def facts_for_name(facts: ContractFacts, full_name: str) -> FunctionFacts | None:
    """One function's facts by artifact ``full_name``, or ``None``."""
    info = facts.effects.get(full_name)
    if not isinstance(info, dict):
        return None
    sig = facts.canonical_signature(full_name)
    selector = _selector_of(sig)
    return FunctionFacts(
        full_name=full_name,
        selector=selector or "",
        canonical_signature=sig,
        effect_info=info,
        tree=facts.trees.get(full_name),
        legacy_value_flows=tuple(facts.legacy_value_flows.get(full_name, ())),
    )


def resolve_function(facts: ContractFacts, selector: str | None) -> FunctionFacts | None:
    """A candidate's selector to its facts, or ``None``."""
    if not isinstance(selector, str) or not selector.startswith("0x") or len(selector) != 10:
        return None
    full_name = facts.by_selector.get(selector.lower())
    if not full_name:
        return None
    info = facts.effects.get(full_name)
    if not isinstance(info, dict):
        return None
    return FunctionFacts(
        full_name=full_name,
        selector=selector.lower(),
        canonical_signature=facts.canonical_signature(full_name),
        effect_info=info,
        tree=facts.trees.get(full_name),
        legacy_value_flows=tuple(facts.legacy_value_flows.get(full_name, ())),
    )
