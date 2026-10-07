"""Fail-soft read-only view over the facts a matcher reasons about (effects, predicate trees, the Slither contract)."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from eth_utils.crypto import keccak

logger = logging.getLogger(__name__)


# Selectors and topic0s are only meaningful for EVM-canonical signatures (contracts/interfaces lowered to ``address``,
# enums to ``uint8``, structs to tuples). Every matcher constant is hashed from published signature text here.


def abi_selector(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


def selectors_of(*signatures: str) -> frozenset[str]:
    return frozenset(abi_selector(signature) for signature in signatures)


def abi_topic0(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()


def selector_of(signature: str | None) -> str | None:
    """Like :func:`abi_selector`, but ``None`` for a malformed signature."""
    if not signature or "(" not in signature or not signature.endswith(")"):
        return None
    return abi_selector(signature)


def _is_canonical_signature(signature: str) -> bool:
    """True when every parameter is an EVM elementary type, i.e. the hash is a real dispatch selector."""
    from ..contract_analysis_pipeline.predicate_artifacts import is_canonical_abi_signature

    return is_canonical_abi_signature(signature)


def _lowered_types(elements: Any) -> list[str] | None:
    """Canonical ABI types for Slither typed elements, or ``None`` if one can't be lowered."""
    from ..contract_analysis_pipeline.predicate_artifacts import _is_elementary_token, _lower_type_to_abi

    lowered: list[str] = []
    for element in elements:
        try:
            text = _lower_type_to_abi(element.type, ())
        except (AttributeError, KeyError, TypeError, ValueError):
            return None
        if not _is_elementary_token(text):
            return None
        lowered.append(text)
    return lowered


def _functions_map(effects: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(effects, dict):
        return {}
    functions = effects.get("functions")
    if not isinstance(functions, dict):
        return {}
    return {sig: rec for sig, rec in functions.items() if isinstance(rec, dict)}


def _trees_map(predicate_trees: Any) -> dict[str, Any]:
    if not isinstance(predicate_trees, dict):
        return {}
    trees = predicate_trees.get("trees")
    return trees if isinstance(trees, dict) else {}


def _canonical_map(predicate_trees: Any) -> dict[str, str]:
    if not isinstance(predicate_trees, dict):
        return {}
    canonical = predicate_trees.get("canonical_signatures")
    return canonical if isinstance(canonical, dict) else {}


class ClaimContext:
    """Facts a matcher may consult, keyed by function full-name. Construct once per contract."""

    def __init__(self, contract: Any, effects: Any, predicate_trees: Any) -> None:
        self.contract = contract
        self._functions = _functions_map(effects)
        self._trees = _trees_map(predicate_trees)
        self._canonical = _canonical_map(predicate_trees)
        name = None
        if isinstance(effects, dict):
            name = effects.get("contract_name")
        if not name:
            name = getattr(contract, "name", None)
        self.contract_name: str | None = name
        self._abi_selectors: frozenset[str] | None = None
        self._events: dict[tuple[str, int], str] | None = None
        # Every matcher asks for the same selectors, so lower once.
        self._abi_signatures: dict[str, str | None] = {}

    def function_signatures(self) -> list[str]:
        """Externally observable function full-names, sorted for deterministic ordering."""
        return sorted(self._functions)

    def effect_record(self, function: str) -> Mapping[str, Any]:
        return self._functions.get(function) or {}

    def function_names(self) -> set[str]:
        return {sig.split("(", 1)[0] for sig in self._functions}

    def abi_selectors(self) -> frozenset[str]:
        """Every selector this contract publishes: its functions' canonical selectors plus the auto-generated getters
        for public state variables (``bool public paused`` publishes ``paused()``), which Slither keeps out of
        ``contract.functions``.
        """
        if self._abi_selectors is None:
            selectors = {
                selector
                for signature in self._functions
                if (selector := self.canonical_selector(signature)) is not None
            }
            selectors |= self._state_variable_getter_selectors()
            self._abi_selectors = frozenset(selectors)
        return self._abi_selectors

    def _state_variable_getter_selectors(self) -> set[str]:
        out: set[str] = set()
        for variable in getattr(self.contract, "state_variables", None) or []:
            if getattr(variable, "visibility", None) != "public":
                continue
            signature = getattr(variable, "solidity_signature", None)
            if isinstance(signature, str) and _is_canonical_signature(signature):
                out.add(abi_selector(signature))
        return out

    def has_selectors(self, *selectors: str | None) -> bool:
        """True when the contract publishes all of ``selectors``; an unresolvable one reads as absent."""
        published = self.abi_selectors()
        return all(selector is not None and selector in published for selector in selectors)

    def _declared_events(self) -> dict[tuple[str, int], str]:
        """``(event name, arity) -> topic0`` for declared and inherited events, hashed from the declaration (so
        user-defined member types hash to the logged topic). Keyed by name and arity because that is how an
        ``emit`` resolves.
        """
        if self._events is None:
            events: dict[tuple[str, int], str] = {}
            for event in getattr(self.contract, "events", None) or []:
                name = getattr(event, "name", None)
                elems = getattr(event, "elems", None) or []
                lowered = _lowered_types(elems)
                if isinstance(name, str) and lowered is not None:
                    events[(name, len(lowered))] = abi_topic0(f"{name}({','.join(lowered)})")
            self._events = events
        return self._events

    def event_topics(self) -> frozenset[str]:
        return frozenset(self._declared_events().values())

    def has_event_topic(self, topic0: str) -> bool:
        return topic0 in self.event_topics()

    def declared_event_topic(self, name: str, arity: int) -> str | None:
        """``topic0`` of the declared event an ``emit <name>(<arity> args)`` resolves to, or ``None``."""
        return self._declared_events().get((name, arity))

    def sinks(self, function: str) -> list[dict[str, Any]]:
        record = self._functions.get(function) or {}
        sinks = record.get("sinks")
        if not isinstance(sinks, list):
            return []
        return [s for s in sinks if isinstance(s, dict)]

    def sink_ids(self, function: str, kind: str) -> list[str]:
        return [str(s.get("id")) for s in self.sinks(function) if s.get("kind") == kind and s.get("id")]

    def effect_labels(self, function: str) -> list[str]:
        record = self._functions.get(function) or {}
        labels = record.get("effect_labels")
        return list(labels) if isinstance(labels, list) else []

    def predicate_tree(self, function: str) -> Any | None:
        return self._trees.get(function)

    def selector(self, function: str) -> str | None:
        """Selector the facts recorded for ``function``: ``""`` for fallback/receive, ``None`` when not determined."""
        record = self._functions.get(function) or {}
        selector = record.get("selector")
        return selector if isinstance(selector, str) else None

    def canonical_signature(self, function: str) -> str | None:
        """Canonical signature from the predicate pipeline, else ``None``."""
        canonical = self._canonical.get(function)
        return canonical if isinstance(canonical, str) else None

    def abi_signature(self, function: str) -> str | None:
        """The signature whose keccak is this function's on-chain selector.

        The predicate artifact only records a canonical form when it differs and is absent on degraded runs, so fall
        back to the full name if already elementary, else lower the Slither parameter types (recovers e.g. Safe
        ``execTransaction``'s enum param).
        """
        if function in self._abi_signatures:
            return self._abi_signatures[function]
        resolved = self.canonical_signature(function)
        if resolved is None:
            resolved = function if _is_canonical_signature(function) else self._lower_signature_from_slither(function)
        self._abi_signatures[function] = resolved
        return resolved

    def _lower_signature_from_slither(self, function: str) -> str | None:
        from ..contract_analysis_pipeline.predicate_artifacts import _canonical_signature

        for fn in getattr(self.contract, "functions", None) or []:
            if (getattr(fn, "full_name", None) or getattr(fn, "name", None)) != function:
                continue
            try:
                return _canonical_signature(fn)
            except Exception:  # pragma: no cover - defensive: a degraded IR
                logger.debug("canonical signature lowering failed for %s", function, exc_info=True)
                return None
        return None

    def canonical_selector(self, function: str) -> str | None:
        """Selector of the canonical signature (the on-chain ``msg.sig``), or ``None`` if it couldn't be lowered."""
        return selector_of(self.abi_signature(function))
