"""Analysis data. A formula is authoritative; a list is an optional projection of it."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .terms import Term, stable


class ReadError(RuntimeError):
    """A required input was not obtained. Retry the job; do not publish an analysis."""


class BudgetExceeded(RuntimeError):
    """Input acquisition stopped deliberately, rather than receiving an empty answer."""


class Reads(Protocol):
    block: int

    def storage(self, address: int, slot: int) -> int: ...
    def code(self, address: int) -> bytes: ...
    def balance(self, address: int) -> int: ...
    def block_field(self, name: str) -> int: ...
    def storage_dump(self, address: int) -> dict[int, int]: ...
    def key_words(self, address: int) -> set[int]: ...
    def preimages(self, address: int, slots: set[int]) -> dict[int, bytes]: ...


@dataclass(frozen=True)
class Issue:
    kind: str
    detail: str


@dataclass(frozen=True)
class Update:
    location: tuple
    value: Term


@dataclass(frozen=True)
class Transition:
    guard: Term
    updates: tuple[Update, ...]


@dataclass(frozen=True)
class Effect:
    kind: str
    target: tuple
    value: Term
    guard: Term


@dataclass(frozen=True)
class Formula:
    address: int
    block: int
    signature: str
    selector: int
    parameters: tuple[Term, ...]
    success: Term
    effects: tuple[Effect, ...]
    transitions: tuple[Transition, ...]


@dataclass(frozen=True)
class SolutionSet:
    """Existential projection onto one identity, retaining the complete predicate.

    finite/cofinite sets are certified by UNSAT after blocking the listed members/exclusions.
    A symbolic result carries any proved members but never claims its enumeration is complete.
    No finite sample establishes universal access.
    """

    predicate: Term
    identity: Term
    representation: str  # finite | cofinite | symbolic
    members: tuple[int, ...] = ()
    excluded: tuple[int, ...] = ()
    issues: tuple[Issue, ...] = ()
    assumptions: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return self.representation in ("finite", "cofinite")


@dataclass(frozen=True)
class Analysis:
    formula: Formula
    callers: SolutionSet
    effects: tuple[SolutionSet, ...]


@dataclass(frozen=True)
class Limits:
    members: int = 256
    storage_steps: int = 100_000
    callee_depth: int = 8
    solver_ms: int = 1000


def encode(value: Any) -> Any:
    """Lossless DAG encoding, so large shared formulas do not expand exponentially."""
    from dataclasses import fields, is_dataclass

    nodes: list[Any] = []
    seen: dict[Term, int] = {}

    def visit(v: Any) -> Any:
        if isinstance(v, Term):
            if v not in seen:
                index = len(nodes)
                seen[v] = index
                nodes.append(None)
                nodes[index] = [visit(x) for x in v]
            return {"term": seen[v]}
        if is_dataclass(v):
            return {f.name: visit(getattr(v, f.name)) for f in fields(v)}
        if isinstance(v, frozenset):
            return {"set": [visit(x) for x in sorted(v, key=stable)]}
        if isinstance(v, tuple):
            return {"tuple": [visit(x) for x in v]}
        if isinstance(v, bytes):
            return {"bytes": v.hex()}
        if isinstance(v, dict):
            return {k: visit(x) for k, x in v.items()}
        return v

    return {"schema": 2, "value": visit(value), "terms": nodes}
