"""Adapter framework for semantic predicate resolution.

Adapters consume structural ``SetDescriptor`` payloads emitted by the
static stage. The durable backend is intentionally generic: event
enumeration is driven by ``enumeration_hint`` records instead of named
protocol standards.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from ..capabilities import CapabilityExpr, Confidence

# Convenience re-export for adapters that need to construct caps.
__all__ = [
    "AdapterRegistry",
    "CallFrame",
    "EnumerationResult",
    "EventLogRepo",
    "EvaluationContext",
    "SetAdapter",
    "Trit",
]


# ---------------------------------------------------------------------------
# Trit
# ---------------------------------------------------------------------------


class Trit(Enum):
    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# EnumerationResult
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnumerationResult:
    """Adapter output for enumerate()."""

    members: list[str] = field(default_factory=list)
    confidence: Confidence = "enumerable"
    partial_reason: str | None = None
    last_indexed_block: int | None = None


@dataclass(frozen=True)
class CallFrame:
    """Execution frame for recursive predicate evaluation.

    ``protected_contract_address`` is the root contract whose
    function we are resolving. ``executing_contract_address`` is the
    contract whose predicate tree is currently being evaluated.
    Those differ when a guarded function delegates authorization to
    an external checker.
    """

    protected_contract_address: str | None = None
    executing_contract_address: str | None = None
    current_function_signature: str | None = None
    current_function_selector: str | None = None
    current_msg_sender: str | None = None
    current_address_this: str | None = None
    current_msg_sig: str | None = None
    bound_parameters: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    @classmethod
    def root(
        cls,
        *,
        contract_address: str | None,
        function_signature: str | None,
        function_selector: str | None,
    ) -> "CallFrame":
        normalized = contract_address.lower() if isinstance(contract_address, str) else None
        return cls(
            protected_contract_address=normalized,
            executing_contract_address=normalized,
            current_function_signature=function_signature,
            current_function_selector=function_selector,
            current_msg_sender=None,
            current_address_this=normalized,
            current_msg_sig=function_selector,
        )


# ---------------------------------------------------------------------------
# Repo Protocols (backends)
# ---------------------------------------------------------------------------


class EventLogRepo(Protocol):
    """Reads generic indexed logs and folds them into a member set."""

    def fold_event_writes(
        self,
        *,
        chain_id: int,
        event_address: str,
        topic0: str,
        topics_to_keys: dict[int, int],
        data_to_keys: dict[int, int],
        key_sources: list[dict[str, Any]],
        direction: str,
        block: int | None = None,
    ) -> EnumerationResult: ...


class BytecodeRepo(Protocol):
    """Reads contract code metadata an adapter uses to score
    matches() — selectors present in the bytecode, declared events,
    inherited interfaces. Adapters can also inspect descriptor
    fields directly."""

    def has_selector(self, *, chain_id: int, contract_address: str, selector: str) -> bool: ...

    def declares_event(self, *, chain_id: int, contract_address: str, topic0: str) -> bool: ...


# ---------------------------------------------------------------------------
# EvaluationContext
# ---------------------------------------------------------------------------


@dataclass
class EvaluationContext:
    # Required (inv. 6): the chain the evaluator binds its event/bytecode/RPC
    # reads to. No mainnet default — a contextless walk can no longer run as
    # chain 1. Callers thread the job's chain_id.
    chain_id: int
    rpc_url: str | None = None
    block: int | None = None
    finality_depth: int = 12
    contract_address: str | None = None
    event_log_repo: EventLogRepo | None = None
    bytecode: BytecodeRepo | None = None
    recursive_resolver: Any = None
    # Persisted state-variable values keyed by storage-var name (e.g.
    # ``"_owner" → "0xabc..."``). Populated by the resolver from the
    # ``controller_values`` table so the predicate evaluator can
    # enumerate ``state_variable`` operands into concrete addresses
    # without hitting the chain. ``None`` falls back to the
    # lower_bound/partial placeholder behavior.
    state_var_values: dict[str, str] | None = None
    # SQLAlchemy Session — needed for cross-contract evaluator inlining
    # (loading the registry contract's predicate_trees artifact when an
    # external_bool leaf carries a callee signature/selector). Optional
    # so call sites that build the context inline can keep working
    # without a DB.
    session: Any = None
    # Recursion guard for cross-contract inlining. Keys are
    # ``(chain_id, address.lower(), function_signature)``. The evaluator
    # adds an entry before recursing into B's tree and removes it after;
    # encountering an already-visited entry short-circuits to
    # external_check_only so a malformed dep graph can't loop.
    evaluation_stack: set[tuple[int, str, str]] = field(default_factory=set)
    call_frame: CallFrame | None = None
    # Free-form metadata bag for adapter-specific state; avoid using
    # for general-purpose data.
    meta: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# SetAdapter Protocol
# ---------------------------------------------------------------------------


SetDescriptor = dict  # forward-import-light alias; full type lives in predicate_types


class SetAdapter(Protocol):
    """Standard-ABI adapter for resolving a set descriptor's members."""

    @classmethod
    def matches(cls, descriptor: SetDescriptor, ctx: EvaluationContext) -> int:
        """Return 0-100. 0 means definitely not this adapter; 100
        means definitely yes. Ties at the registry level are broken
        by registration order. Score 0 from all → unsupported."""
        ...

    @classmethod
    def supports_external_check_only(cls) -> bool:
        """True iff the adapter can answer membership() against a
        live backend (used by the predicate evaluator to decide
        whether to emit external_check_only vs lower_bound finite_set
        when enumerate returns partial)."""
        ...

    def enumerate(self, descriptor: SetDescriptor, ctx: EvaluationContext) -> CapabilityExpr:
        """Populate the capability — finite_set for enumerable, or
        partial / external_check_only when the adapter can't fully
        list members."""
        ...


# ---------------------------------------------------------------------------
# AdapterRegistry
# ---------------------------------------------------------------------------


@dataclass
class AdapterRegistry:
    """Ordered list of adapters. ``pick()`` returns the highest-
    scoring adapter for a descriptor; on a tie, registration order
    wins. Score 0 from all → returns None and the caller emits
    unsupported(no_adapter)."""

    adapters: list[type[SetAdapter]] = field(default_factory=list)

    def register(self, adapter_cls: type[SetAdapter]) -> None:
        if adapter_cls in self.adapters:
            return
        self.adapters.append(adapter_cls)

    def pick(self, descriptor: SetDescriptor, ctx: EvaluationContext) -> type[SetAdapter] | None:
        best: tuple[int, type[SetAdapter]] | None = None
        for cls in self.adapters:
            score = cls.matches(descriptor, ctx)
            if score <= 0:
                continue
            if best is None or score > best[0]:
                best = (score, cls)
        return best[1] if best is not None else None

    def enumerate(self, descriptor: SetDescriptor, ctx: EvaluationContext) -> CapabilityExpr:
        adapter_cls = self.pick(descriptor, ctx)
        # Tally which adapter claimed each descriptor onto the resolve-level
        # counter (when the capability resolver wired one onto ``ctx.meta``), so
        # a per-job ``adapter_match`` breakdown surfaces — Solmate vs generic
        # event-indexed vs ``no_adapter``. A standard adapter that silently
        # stops matching (e.g. the Veda RolesAuthority cold-index race) shows up
        # as a shift in this distribution run-over-run.
        counters = ctx.meta.get("resolve_counters") if isinstance(ctx.meta, dict) else None
        if isinstance(counters, dict):
            name = adapter_cls.__name__ if adapter_cls is not None else "no_adapter"
            bucket = counters.setdefault("adapter_match", {})
            bucket[name] = bucket.get(name, 0) + 1
        if adapter_cls is None:
            return CapabilityExpr.unsupported("no_adapter")
        adapter = adapter_cls()
        return adapter.enumerate(descriptor, ctx)
