"""Tolerant read-only view over the Plane-0 facts a matcher reasons about.

Wraps the sibling-owned ``effects`` facts artifact, the ``predicate_trees``
artifact, and the Slither subject contract behind stable accessors, so matcher
modules never reach into ``effects.py`` internals. Every accessor fails soft: a
degraded (errored) or absent artifact reads as empty rather than raising, which
keeps the claims pass a no-op when its inputs are missing.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from eth_utils.crypto import keccak

logger = logging.getLogger(__name__)


# --- ABI primitives ---------------------------------------------------------
# A selector/topic0 is only meaningful for an EVM-canonical ``name(types)``
# signature (contract/interface params lowered to ``address``, enums to
# ``uint<N>``, structs to their tuple form). The three helpers below are the one
# place the claims package hashes a signature, so every matcher constant is
# built from the published signature text rather than a transcribed hex literal.


def abi_selector(signature: str) -> str:
    """keccak256[:4] of a canonical ``name(types)`` signature."""
    return "0x" + keccak(text=signature).hex()[:8]


def selectors_of(*signatures: str) -> frozenset[str]:
    return frozenset(abi_selector(signature) for signature in signatures)


def abi_topic0(signature: str) -> str:
    """keccak256 of a canonical ``Event(types)`` signature — the log's topic0."""
    return "0x" + keccak(text=signature).hex()


def selector_of(signature: str | None) -> str | None:
    """Tolerant :func:`abi_selector`: ``None`` for anything that is not a
    well-formed ``name(types)`` signature."""
    if not signature or "(" not in signature or not signature.endswith(")"):
        return None
    return abi_selector(signature)


def _is_canonical_signature(signature: str) -> bool:
    """True when every parameter token of ``signature`` is an EVM elementary
    type — i.e. hashing it yields the selector the chain would dispatch on. A
    residual user-defined name (``setAuthority(Authority)``) means the signature
    was never lowered, so its hash is not a real selector."""
    from ..contract_analysis_pipeline.predicate_artifacts import is_canonical_abi_signature

    return is_canonical_abi_signature(signature)


def _lowered_types(elements: Any) -> list[str] | None:
    """EVM-canonical ABI type strings for a sequence of Slither typed elements
    (event members / getter keys), or ``None`` when one cannot be lowered."""
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
    """Facts a matcher may consult. Construct once per contract; accessors are
    keyed by function full-name (the ``effects`` artifact's key)."""

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
        # Every registered matcher asks for the same function's selector, so the
        # lowering (which may scan the Slither function list) is resolved once.
        self._abi_signatures: dict[str, str | None] = {}

    # -- function enumeration -------------------------------------------------

    def function_signatures(self) -> list[str]:
        """Full-name signatures of every externally-observable function, sorted
        for deterministic claim ordering."""
        return sorted(self._functions)

    def effect_record(self, function: str) -> Mapping[str, Any]:
        return self._functions.get(function) or {}

    def function_names(self) -> set[str]:
        """Bare function names (before ``(``) — the coarse set standard gates
        check for sibling selectors."""
        return {sig.split("(", 1)[0] for sig in self._functions}

    # -- ABI surface (selectors + event topics) -------------------------------

    def abi_selectors(self) -> frozenset[str]:
        """Every 4-byte selector this contract publishes.

        Two sources, both on-chain facts rather than identifier text: the
        canonical selector of each externally-observable function, and the getter
        Solidity auto-generates for each public state variable — ``bool public
        paused`` publishes ``paused()`` exactly as a hand-written getter would,
        and Slither keeps that getter out of ``contract.functions``. A signature
        that never lowered to elementary types contributes nothing (its hash is
        not a selector the chain would dispatch on)."""
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
        """True when the contract publishes every one of ``selectors`` (a
        standard's mandated entry set). ``None`` — an unresolvable signature —
        always reads as absent."""
        published = self.abi_selectors()
        return all(selector is not None and selector in published for selector in selectors)

    def _declared_events(self) -> dict[tuple[str, int], str]:
        """``(event name, arity) -> topic0`` for every event the contract declares
        or inherits, computed from the *declaration's* canonical signature so a
        user-defined member type (``AuthorityUpdated(address,Authority)``) hashes
        to the topic the chain actually logs. Keyed by name and arity because
        that is how Solidity resolves an ``emit`` back to its declaration — the
        emitted argument types are subject to implicit conversion and are not the
        signature."""
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
        """``topic0`` of every event the contract declares or inherits."""
        return frozenset(self._declared_events().values())

    def has_event_topic(self, topic0: str) -> bool:
        return topic0 in self.event_topics()

    def declared_event_topic(self, name: str, arity: int) -> str | None:
        """``topic0`` of the declared event an ``emit <name>(<arity> args)``
        resolves to, or ``None`` when the contract declares no such event."""
        return self._declared_events().get((name, arity))

    # -- sinks ----------------------------------------------------------------

    def sinks(self, function: str) -> list[dict[str, Any]]:
        record = self._functions.get(function) or {}
        sinks = record.get("sinks")
        if not isinstance(sinks, list):
            return []
        return [s for s in sinks if isinstance(s, dict)]

    def sink_ids(self, function: str, kind: str) -> list[str]:
        """Ids of every ``kind`` sink on ``function`` (stable cross-references
        for a witness)."""
        return [str(s.get("id")) for s in self.sinks(function) if s.get("kind") == kind and s.get("id")]

    # -- labels / predicate trees --------------------------------------------

    def effect_labels(self, function: str) -> list[str]:
        record = self._functions.get(function) or {}
        labels = record.get("effect_labels")
        return list(labels) if isinstance(labels, list) else []

    def predicate_tree(self, function: str) -> Any | None:
        return self._trees.get(function)

    def selector(self, function: str) -> str:
        """4-byte selector the facts artifact recorded for ``function`` (empty
        for fallback/receive, which have none)."""
        record = self._functions.get(function) or {}
        selector = record.get("selector")
        return selector if isinstance(selector, str) else ""

    def canonical_signature(self, function: str) -> str | None:
        """Production canonical ``name(types)`` signature when the predicate
        pipeline resolved one (enum/struct params normalized), else ``None``."""
        canonical = self._canonical.get(function)
        return canonical if isinstance(canonical, str) else None

    def abi_signature(self, function: str) -> str | None:
        """The signature whose keccak IS this function's on-chain selector.

        The predicate artifact only records a canonical form when it DIFFERS from
        the full name, and it is absent entirely on a degraded run — so fall back
        to the full name when that is already elementary, and otherwise lower the
        Slither parameter types directly, which is what recovers a standard entry
        carrying an enum or interface param (Safe's ``execTransaction``)."""
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
        """The 4-byte selector computed from the function's canonical signature
        — the value that appears as ``msg.sig`` on chain. ``None`` when the
        signature could not be lowered (fail toward no match)."""
        return selector_of(self.abi_signature(function))
