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
    callers: SolutionSet | None
    effects: tuple[SolutionSet, ...]
    effect_indices: tuple[int, ...] = ()


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


def decode_formula(payload: dict) -> Formula:
    """Restore a saved formula in another process, without re-running the lowerer."""
    if payload.get("schema") != 2 or not isinstance(payload.get("terms"), list):
        raise ValueError("unsupported formula encoding")
    nodes = payload["terms"]
    memo: dict[int, Term] = {}
    active: set[int] = set()

    def visit(value: Any) -> Any:
        if isinstance(value, dict):
            if set(value) == {"term"}:
                index = value["term"]
                if type(index) is not int or not 0 <= index < len(nodes) or index in active:
                    raise ValueError("invalid or cyclic term reference")
                if index not in memo:
                    node = nodes[index]
                    if not isinstance(node, list) or not node or not isinstance(node[0], str):
                        raise ValueError("invalid term")
                    active.add(index)
                    from .terms import mk

                    memo[index] = mk(*(visit(v) for v in node))
                    active.remove(index)
                return memo[index]
            if set(value) == {"tuple"}:
                return tuple(visit(v) for v in value["tuple"])
            if set(value) == {"set"}:
                return frozenset(visit(v) for v in value["set"])
            if set(value) == {"bytes"}:
                return bytes.fromhex(value["bytes"])
            return {k: visit(v) for k, v in value.items()}
        if value is None or isinstance(value, (int, str, bool)):
            return value
        raise ValueError("invalid formula value")

    try:
        data = visit(payload["value"])
        data["effects"] = tuple(Effect(**effect) for effect in data["effects"])
        data["transitions"] = tuple(
            Transition(t["guard"], tuple(Update(**u) for u in t["updates"])) for t in data["transitions"]
        )
        formula = Formula(**data)
        if (
            type(formula.address) is not int
            or not 0 <= formula.address < 2**160
            or type(formula.block) is not int
            or formula.block < 0
            or type(formula.selector) is not int
            or not 0 <= formula.selector < 2**32
            or not isinstance(formula.signature, str)
            or not isinstance(formula.success, Term)
            or not isinstance(formula.parameters, tuple)
            or not all(isinstance(p, Term) for p in formula.parameters)
            or any(
                not isinstance(e.guard, Term) or not isinstance(e.value, Term) or not isinstance(e.target, tuple)
                for e in formula.effects
            )
            or any(
                not isinstance(t.guard, Term)
                or any(not isinstance(u.value, Term) or not isinstance(u.location, tuple) for u in t.updates)
                for t in formula.transitions
            )
        ):
            raise ValueError("invalid formula fields")
        return formula
    except (KeyError, TypeError, AttributeError, RecursionError) as exc:
        raise ValueError("invalid formula payload") from exc
