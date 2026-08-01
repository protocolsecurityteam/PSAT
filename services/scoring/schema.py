"""The typed signal-row and score-document contract.

This is the surface Layer 1 (per-function distillation, end of the effects
stage) hands to Layer 2 (the whole-protocol grade fold). It is deliberately the
only shape either side agrees on: distillation produces
:class:`FunctionSignal`, the fold consumes nothing else, and the persisted
``function_score_signals`` plane is a faithful round-trip of it.

Signals REFERENCE, they do not RESOLVE
--------------------------------------
A signal carries ``function_principal_id`` + ``(chain, address)`` for principals
and ``<chain>::<address>`` entity keys for value — never a resolved principal
type, a weakness, or a dollar amount. Cross-contract resolution (principal
units, MAX per (entity, asset), subsumption) is the fold's job because only the
fold sees every finding that touches an entity: two functions reaching the same
vault must charge it once, and a signal that had already resolved its own value
would make that undecidable.

The three-state encoding: PAIRED DISCRIMINATOR
----------------------------------------------
Every fact that can be undetermined is one of **proven-present**,
**proven-absent**, or **not_determined**, and all three are distinct here and
all the way to the consumer. There is exactly ONE encoding, used everywhere:

    a NOT NULL ``*_state`` discriminator drawn from a closed vocabulary in
    ``utils.scoring_status`` that always contains ``not_determined``, paired
    with a payload that is populated only in a proven state.

In this module that pair is :class:`Tri`; in the DB it is the ``*_state`` column
plus its nullable payload column, tied by a named CHECK. The two are the same
shape on purpose, so persistence is a field-for-field move with nothing to
reinterpret.

Why this convention and not the alternatives:

* **Not "``None`` means not_determined".** That collapses proven-absent into
  not_determined — the exact conflation this tool exists to prevent. Proven zero
  value and unreadable value are different facts, and ``None`` cannot hold both.
* **Not "the key is absent".** Absence is not a witness. A reader that infers
  state from a missing key gets the same answer for "we proved nothing is here"
  and "nobody looked", and every ``dict.get`` in the codebase becomes a place
  where a default silently becomes a fact.
* **Not a bare enum without a payload.** The fold needs the value, and splitting
  the two across unrelated fields is how they drift apart.

**A not_determined is never a default.** No :class:`Tri`-typed field on any
dataclass here declares a default value, and no ``*_state`` column carries a
server default. Constructing a signal therefore requires *naming* every state,
and an INSERT that omits one raises instead of recording ``not_determined``
silently. This is the load-bearing half of the convention: a defaultable
not_determined is indistinguishable from an unread witness that got published.
:meth:`Tri.not_determined` exists so that naming it is explicit and greppable,
never implicit.

Determinism
-----------
:class:`ScoreDocument` is what a fold emits and what ``protocol_scores``
persists. The same DB state must produce a byte-identical document modulo
``computed_at``, so every sequence field here is expected to arrive in a stable
sorted order from the fold; this module fixes the shape, not the ordering.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Generic, TypeVar

from utils.scoring_status import (
    DESTINATION_STATE_NOT_APPLICABLE,
    DESTINATION_STATE_NOT_DETERMINED,
    DESTINATION_STATES,
    GRADE_STATE_COMPUTED,
    GRADE_STATE_NOT_DETERMINED,
    GRADE_STATES,
    NO_SELECTOR,
    OPENNESS_NOT_DETERMINED,
    OPENNESS_STATES,
    PERIMETER_NOT_DETERMINED,
    PERIMETER_STATES,
    PRINCIPAL_STATE_ENUMERATED,
    PRINCIPAL_STATE_NOT_DETERMINED,
    PRINCIPAL_STATES,
    REACH_GATE_NOT_DETERMINED,
    REACH_GATE_STATES,
    SCORE_TRIGGERS,
    SEVERITY_STATE_NOT_DETERMINED,
    SEVERITY_STATE_PROVEN,
    SEVERITY_STATES,
    VALUE_BOUND_NOT_DETERMINED,
    VALUE_BOUNDS,
    VALUE_STATE_NOT_DETERMINED,
    VALUE_STATE_PROVEN_REACH,
    VALUE_STATES,
    WITNESS_TIER_NOT_DETERMINED,
    WITNESS_TIERS,
)

T = TypeVar("T")

NOT_DETERMINED = "not_determined"


def entity_key(chain: str, address: str) -> str:
    """The chain-scoped value/principal entity token, ``<chain>::<address>``.

    Chain-scoped because the same address on two chains is two entities: an
    unscoped key re-introduces the cross-chain twin aliasing that #158 closed,
    and would let one chain's value pool inflate another chain's finding.
    """
    return f"{chain}::{address.lower()}"


@dataclass(frozen=True, slots=True)
class Tri(Generic[T]):
    """A three-state fact: a state name plus the payload proven in that state.

    ``state`` is always one of the vocabulary's members and always includes
    ``not_determined`` as a real option. ``value`` is populated only in a proven
    state — the pairing is enforced in ``__post_init__`` so an undetermined fact
    cannot carry a number that a caller might read anyway.
    """

    state: str
    value: T | None

    def __post_init__(self) -> None:
        if self.state == NOT_DETERMINED and self.value is not None:
            raise ValueError(f"not_determined carries no value, got {self.value!r}")

    @classmethod
    def not_determined(cls) -> Tri[T]:
        """Spelled out at every call site so an unread witness is greppable."""
        return cls(state=NOT_DETERMINED, value=None)

    @classmethod
    def proven(cls, state: str, value: T) -> Tri[T]:
        if state == NOT_DETERMINED:
            raise ValueError("proven() cannot take the not_determined state")
        return cls(state=state, value=value)

    @property
    def is_determined(self) -> bool:
        return self.state != NOT_DETERMINED

    def require(self, expected_state: str) -> T:
        """The payload, or a raise. The only sanctioned way to read ``value``.

        Every consumer must branch on ``state`` first. This exists so that
        reading a payload without having decided which state licensed it is an
        error rather than a silent ``None`` flowing into arithmetic.
        """
        if self.state != expected_state:
            raise ValueError(f"expected state {expected_state!r}, have {self.state!r}")
        if self.value is None:
            raise ValueError(f"state {self.state!r} carries no value")
        return self.value


def _check_member(name: str, value: str, vocabulary: tuple[str, ...]) -> None:
    if value not in vocabulary:
        raise ValueError(f"{name}={value!r} not in {vocabulary}")


@dataclass(frozen=True, slots=True)
class PrincipalRef:
    """A reference to one ``function_principals`` row. Never a resolved copy.

    ``function_principal_id`` is the pinned reference; ``(chain, address)`` is
    the natural key that still identifies the principal after
    ``effective_functions`` is delete+reinserted and the id is gone. Neither
    ``resolved_type``, nor an owner set, nor a threshold travels here — those are
    resolutions, and resolving them per-signal is what makes the same Safe two
    different units in two different contracts' findings.
    """

    function_principal_id: int
    chain: str
    address: str

    @property
    def key(self) -> str:
        return entity_key(self.chain, self.address)

    def to_json(self) -> dict[str, Any]:
        return {
            "function_principal_id": self.function_principal_id,
            "chain": self.chain,
            "address": self.address,
        }

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> PrincipalRef:
        return cls(
            function_principal_id=int(raw["function_principal_id"]),
            chain=str(raw["chain"]),
            address=str(raw["address"]),
        )


@dataclass(frozen=True, slots=True)
class FunctionSignal:
    """One (function, capability) signal row.

    Every three-state field is a required :class:`Tri` or a required state
    string — no defaults, so a distiller that has not decided a state cannot
    construct the row at all. The optional-looking fields below
    (``function_id``, ``contract_id``, ``effect_verdict_id``) are plain
    identifiers, not facts about the protocol; their ``None`` means "no such row
    to point at", which is why they are the only ones allowed a default.
    """

    job_id: Any
    protocol_id: int
    chain: str
    deployment_address: str
    function_name: str
    claim_id: str

    witness_tier: str

    # Severity has no proven-absent arm: a proven zero (the ``pause.set``
    # build-up starts at 0.0) is SEVERITY_STATE_PROVEN carrying 0.0, which is a
    # different fact from an unread severity and must stay one.
    severity: Tri[float]
    severity_basis: tuple[str, ...]

    authority_openness: str
    principal_state: str
    principal_refs: tuple[PrincipalRef, ...]

    value_state: str
    value_bound: str
    value_entity_keys: tuple[str, ...]
    value_basis: str

    destination: Tri[str]
    reach_gate_state: str

    gate_inputs: dict[str, Any]
    citations: tuple[dict[str, Any], ...]
    witness_notes: tuple[str, ...]

    selector: str = NO_SELECTOR
    function_id: int | None = None
    contract_id: int | None = None
    effect_verdict_id: int | None = None

    def __post_init__(self) -> None:
        _check_member("witness_tier", self.witness_tier, WITNESS_TIERS)
        _check_member("severity.state", self.severity.state, SEVERITY_STATES)
        _check_member("authority_openness", self.authority_openness, OPENNESS_STATES)
        _check_member("principal_state", self.principal_state, PRINCIPAL_STATES)
        _check_member("value_state", self.value_state, VALUE_STATES)
        _check_member("value_bound", self.value_bound, VALUE_BOUNDS)
        _check_member("destination.state", self.destination.state, DESTINATION_STATES)
        _check_member("reach_gate_state", self.reach_gate_state, REACH_GATE_STATES)

        # The same pairings the DB CHECKs enforce, checked here so a bad row
        # fails at the distiller rather than as an IntegrityError three layers
        # away with no context about which witness was missing.
        if self.severity.state == SEVERITY_STATE_PROVEN and not self.severity_basis:
            raise ValueError("a proven severity must name what proved it")
        if (self.principal_state == PRINCIPAL_STATE_ENUMERATED) != bool(self.principal_refs):
            raise ValueError("principal refs exist exactly on the enumerated state")
        if (self.value_state == VALUE_STATE_PROVEN_REACH) != bool(self.value_entity_keys):
            raise ValueError("value entity keys exist exactly on the proven_reach state")
        if self.value_state != VALUE_STATE_PROVEN_REACH and self.value_bound != VALUE_BOUND_NOT_DETERMINED:
            raise ValueError("only a proven reach can be bounded")

    @property
    def enters_grade(self) -> bool:
        """Whether the fold may score this row at all.

        An undetermined severity fails closed to not-scored. This is the single
        gate that keeps the banned defect class out: severity is never escalated
        by the ABSENCE of a constraint witness, so a row that could not prove its
        severity contributes nothing rather than contributing a default.
        """
        return self.severity.state == SEVERITY_STATE_PROVEN


def not_determined_signal_defaults() -> dict[str, Any]:
    """The undetermined value for each three-state field, for explicit use only.

    Deliberately a function a distiller must call and splat, never a set of
    dataclass defaults: the point is that choosing ``not_determined`` is a
    visible act at the call site. Wave 2 uses this to build a fail-closed row
    when a witness is missing, then overrides the fields it actually proved.
    """
    return {
        "witness_tier": WITNESS_TIER_NOT_DETERMINED,
        "severity": Tri[float].not_determined(),
        "severity_basis": (),
        "authority_openness": OPENNESS_NOT_DETERMINED,
        "principal_state": PRINCIPAL_STATE_NOT_DETERMINED,
        "principal_refs": (),
        "value_state": VALUE_STATE_NOT_DETERMINED,
        "value_bound": VALUE_BOUND_NOT_DETERMINED,
        "value_entity_keys": (),
        "value_basis": NOT_DETERMINED,
        "destination": Tri[str].not_determined(),
        "reach_gate_state": REACH_GATE_NOT_DETERMINED,
        "gate_inputs": {},
        "citations": (),
        "witness_notes": (),
    }


@dataclass(frozen=True, slots=True)
class ScoreDocument:
    """What a fold emits and ``protocol_scores`` persists.

    ``grade`` and ``exposure`` are undetermined together with ``confidence_pct``
    — a grade with no confidence is not a grade — which is why one
    ``grade_state`` covers all three, matching ``ck_protocol_scores_grade_pairing``.

    ``model_parameters`` travels with every document rather than being read from
    code at display time: two scores are only comparable against the constants
    each was actually computed under, and it carries the uncalibrated-arm flags
    so a consumer can see which rules have never fired their positive branch.
    """

    protocol_id: int
    model_version: str
    computed_at: datetime
    trigger: str
    perimeter_state: str

    grade_state: str
    grade_lambda: float | None
    grade_exposure: float | None
    confidence_pct: float | None

    findings: list[dict[str, Any]]
    earned_negatives: list[dict[str, Any]]
    warnings: list[dict[str, Any]]
    model_parameters: dict[str, Any]
    provenance: dict[str, Any]

    trigger_job_id: Any | None = None
    uncalibrated_arms: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _check_member("trigger", self.trigger, SCORE_TRIGGERS)
        _check_member("perimeter_state", self.perimeter_state, PERIMETER_STATES)
        _check_member("grade_state", self.grade_state, GRADE_STATES)
        determined = (self.grade_lambda, self.grade_exposure, self.confidence_pct)
        if (self.grade_state == GRADE_STATE_COMPUTED) != all(v is not None for v in determined):
            raise ValueError("grade, exposure and confidence are determined together or not at all")

    def document(self) -> dict[str, Any]:
        """The JSONB payload persisted to ``protocol_scores.findings``.

        Served verbatim by the API — no projection into any other shape, because
        every projection so far has been where a three-state collapsed back into
        two.
        """
        return {
            "model_version": self.model_version,
            "grade_state": self.grade_state,
            "grade_lambda": self.grade_lambda,
            "grade_exposure": self.grade_exposure,
            "confidence_pct": self.confidence_pct,
            "perimeter_state": self.perimeter_state,
            "findings": self.findings,
            "earned_negatives": self.earned_negatives,
            "warnings": self.warnings,
            "model_parameters": self.model_parameters,
            "uncalibrated_arms": list(self.uncalibrated_arms),
        }


__all__ = [
    "DESTINATION_STATE_NOT_APPLICABLE",
    "DESTINATION_STATE_NOT_DETERMINED",
    "GRADE_STATE_COMPUTED",
    "GRADE_STATE_NOT_DETERMINED",
    "NOT_DETERMINED",
    "PERIMETER_NOT_DETERMINED",
    "SEVERITY_STATE_NOT_DETERMINED",
    "SEVERITY_STATE_PROVEN",
    "FunctionSignal",
    "PrincipalRef",
    "ScoreDocument",
    "Tri",
    "entity_key",
    "not_determined_signal_defaults",
]
