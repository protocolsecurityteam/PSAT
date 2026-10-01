"""Adapter framework for semantic predicate resolution.

Adapters consume the static stage's ``SetDescriptor``; event enumeration is driven by ``enumeration_hint`` records
rather than named standards.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from ..capabilities import CapabilityConfidence, CapabilityExpr

__all__ = [
    "AdapterRegistry",
    "CallFrame",
    "EnumerationResult",
    "EventLogRepo",
    "EvaluationContext",
    "SetAdapter",
    "Trit",
]


class Trit(Enum):
    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class EnumerationResult:
    members: list[str] = field(default_factory=list)
    confidence: CapabilityConfidence = "enumerable"
    partial_reason: str | None = None
    last_indexed_block: int | None = None


@dataclass(frozen=True)
class CallFrame:
    """Execution frame for recursive predicate evaluation.

    ``protected_contract_address`` is the root contract; ``executing_contract_address`` is whose tree is being evaluated
    (they differ when authorization is delegated).
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


class EventLogRepo(Protocol):
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
    """Contract code metadata (selectors, events, interfaces) adapters use to score matches()."""

    def has_selector(self, *, chain_id: int, contract_address: str, selector: str) -> bool: ...

    def declares_event(self, *, chain_id: int, contract_address: str, topic0: str) -> bool: ...


@dataclass
class EvaluationContext:
    # Required; no mainnet default.
    chain_id: int
    rpc_url: str | None = None
    block: int | None = None
    finality_depth: int = 12
    contract_address: str | None = None
    event_log_repo: EventLogRepo | None = None
    bytecode: BytecodeRepo | None = None
    recursive_resolver: Any = None
    # Persisted ``controller_values`` by var name, so ``state_variable`` operands resolve without the chain. ``None``
    # gives the lower_bound placeholder.
    state_var_values: dict[str, str] | None = None
    # For cross-contract inlining (loading the registry's predicate_trees). Optional for DB-less call sites.
    session: Any = None
    # Recursion guard for inlining, keyed ``(chain_id, address, function_signature)``; a revisit short-circuits to
    # external_check_only.
    evaluation_stack: set[tuple[int, str, str]] = field(default_factory=set)
    call_frame: CallFrame | None = None
    # Adapter-specific state only.
    meta: dict[str, Any] = field(default_factory=dict)


SetDescriptor = dict  # forward-import-light alias; full type lives in predicate_types


class SetAdapter(Protocol):
    @classmethod
    def matches(cls, descriptor: SetDescriptor, ctx: EvaluationContext) -> int:
        """0-100: 0 means definitely not, 100 definitely yes.

        Ties go to registration order; all zero means unsupported.
        """
        ...

    @classmethod
    def supports_external_check_only(cls) -> bool:
        """Whether the adapter can answer membership() live, deciding between external_check_only and a lower_bound
        finite_set on partial enumeration.
        """
        ...

    def enumerate(self, descriptor: SetDescriptor, ctx: EvaluationContext) -> CapabilityExpr:
        """A finite_set when enumerable, else partial or external_check_only."""
        ...


@dataclass
class AdapterRegistry:
    """Ordered adapters.

    ``pick()`` returns the highest scorer (ties by registration order), or None so the caller emits
    unsupported(no_adapter).
    """

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
        # Tally which adapter claimed each descriptor, so an adapter that silently stops matching shows as a
        # distribution shift.
        counters = ctx.meta.get("resolve_counters") if isinstance(ctx.meta, dict) else None
        if isinstance(counters, dict):
            name = adapter_cls.__name__ if adapter_cls is not None else "no_adapter"
            bucket = counters.setdefault("adapter_match", {})
            bucket[name] = bucket.get(name, 0) + 1
        if adapter_cls is None:
            return CapabilityExpr.unsupported("no_adapter")
        adapter = adapter_cls()
        return adapter.enumerate(descriptor, ctx)
