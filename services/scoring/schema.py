"""The typed signal-row and score-document contract between Layer 1 (distillation) and Layer 2 (the fold).

The fold consumes only :class:`FunctionSignal`; persistence round-trips it via :func:`signal_to_row_kwargs` /
:func:`signal_from_row`, pinned by a test covering all three states of every field.

Signals reference, they don't resolve: principals are ``function_principal_id`` + ``(chain, address)`` and value is
``<chain>::<address>`` keys. Cross-contract resolution (units, max per entity, subsumption) needs every finding and
belongs to the fold.

Three-state encoding: every undeterminable fact is proven-present, proven-absent, or not_determined, encoded as a NOT
NULL ``*_state`` discriminator (closed vocabulary in ``utils.scoring_status``) paired with a payload populated only when
proven. Here that is :class:`Tri`; in the DB, a state column plus nullable payload tied by a CHECK. Not
``None``-means-undetermined (merges proven-absent), not key absence (absence isn't a witness), not a bare enum (the fold
needs the value).

not_determined is never a default: no ``Tri`` field has a default and no ``*_state`` column has a server default, so
every state must be named; :meth:`Tri.not_determined` keeps that greppable.

Signals are a current-state plane replaced per contract (:func:`services.scoring.population.replace_contract_signals`);
``job_id`` is provenance, not identity. :class:`ScoreDocument` must be byte-identical for the same DB state modulo
``computed_at``; the fold supplies sorted sequences.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Generic, TypeVar

from utils.scoring_status import (
    DESTINATION_BEARING_CLAIMS,
    DESTINATION_STATE_NOT_APPLICABLE,
    DESTINATION_STATE_NOT_DETERMINED,
    DESTINATION_STATES,
    GRADE_STATE_COMPUTED,
    GRADE_STATE_NOT_DETERMINED,
    GRADE_STATES,
    NO_SELECTOR,
    NOT_DETERMINED,
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


def coalesce_chain(chain: str | None) -> str:
    """Chain token, byte-identical to ``company_overview._coalesce_chain``.

    NULL/empty/``"mainnet"`` become ``"ethereum"``; everything else is lowercased. Not
    :func:`utils.chains.canonical_chain`, which folds extra aliases. Without this, one vault could get three keys and be
    charged three times; ``tests/test_scoring_schema.py`` pins it.
    """
    token = str(chain or "").strip().lower()
    if not token or token == "mainnet":
        return "ethereum"
    return token


def entity_key(chain: str | None, address: str | None) -> str:
    """The chain-scoped entity token ``<chain>::<address>``; unscoped keys would reintroduce the cross-chain aliasing
    #158 closed.
    """
    return f"{coalesce_chain(chain)}::{str(address or '').lower()}"


def is_entity_key(token: str) -> bool:
    """Whether ``token`` is a well-formed chain-scoped key. Bare addresses are rejected, not coerced."""
    if not isinstance(token, str) or token.count("::") != 1:
        return False
    chain, _, address = token.partition("::")
    return bool(chain) and bool(address) and token == entity_key(chain, address)


@dataclass(frozen=True, slots=True)
class Tri(Generic[T]):
    """A three-state fact: a state plus the payload proven in that state.

    ``value`` is set only in a proven state, enforced in ``__post_init__``.
    """

    state: str
    value: T | None

    def __post_init__(self) -> None:
        # Both directions: an undetermined fact with a value could be misread; a proven fact without one claims a
        # witness it lacks.
        if self.state == NOT_DETERMINED:
            if self.value is not None:
                raise ValueError(f"not_determined carries no value, got {self.value!r}")
        elif self.value is None:
            raise ValueError(f"state {self.state!r} is proven and must carry its witness value")

    @classmethod
    def not_determined(cls) -> Tri[T]:
        return cls(state=NOT_DETERMINED, value=None)

    def to_json(self) -> dict[str, Any]:
        """The wire shape inside ``gate_inputs``. Always both keys, so state is never implied by absence."""
        return {"state": self.state, "value": self.value}

    @classmethod
    def from_json(cls, raw: object) -> Tri[Any]:
        if not isinstance(raw, dict) or "state" not in raw or "value" not in raw:
            raise ValueError(f"not a tri-state envelope: {raw!r}")
        return Tri(state=str(raw["state"]), value=raw["value"])

    @classmethod
    def proven(cls, state: str, value: T) -> Tri[T]:
        if state == NOT_DETERMINED:
            raise ValueError("proven() cannot take the not_determined state")
        return cls(state=state, value=value)

    @property
    def is_determined(self) -> bool:
        return self.state != NOT_DETERMINED

    def require(self, expected_state: str) -> T:
        """The payload, or a raise.

        The only sanctioned way to read ``value``, so reading without branching on state is an error.
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
    """A reference to one ``function_principals`` row, never a resolved copy.

    ``(chain, address)`` survives the id being lost to delete+reinsert. Resolutions (type, owner set, threshold) stay
    out, since resolving per signal would split one Safe into different units.
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

    Three-state fields have no defaults, so an undecided distiller can't construct a row. ``contract_id`` is required
    too: it's identity (split-proxy implementations share a deployment address), and the in-memory CLI path has no NOT
    NULL column to catch a ``None``. ``function_id`` and ``effect_verdict_id`` are optional back-references.
    """

    job_id: Any
    protocol_id: int
    contract_id: int
    chain: str
    deployment_address: str
    function_name: str
    claim_id: str

    witness_tier: str

    # No proven-absent arm: a proven zero (``pause.set``) is PROVEN carrying 0.0.
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

        # Mirrors the DB CHECKs so failures surface at the distiller with context.
        if self.severity.state == SEVERITY_STATE_PROVEN and not self.severity_basis:
            raise ValueError("a proven severity must name what proved it")
        if (self.principal_state == PRINCIPAL_STATE_ENUMERATED) != bool(self.principal_refs):
            raise ValueError("principal refs exist exactly on the enumerated state")
        if (self.value_state == VALUE_STATE_PROVEN_REACH) != bool(self.value_entity_keys):
            raise ValueError("value entity keys exist exactly on the proven_reach state")
        if self.value_state != VALUE_STATE_PROVEN_REACH and self.value_bound != VALUE_BOUND_NOT_DETERMINED:
            raise ValueError("only a proven reach can be bounded")
        # Unscoped or malformed keys break max-per-entity dedup.
        bad_keys = [k for k in self.value_entity_keys if not is_entity_key(k)]
        if bad_keys:
            raise ValueError(f"value_entity_keys must be canonical <chain>::<address> tokens, got {bad_keys!r}")
        if self.destination.state == DESTINATION_STATE_NOT_APPLICABLE and self.claim_id in DESTINATION_BEARING_CLAIMS:
            raise ValueError(f"{self.claim_id} has a destination; not_applicable would launder an unread one")
        for name, raw in self.gate_inputs.items():
            try:
                Tri.from_json(raw)
            except ValueError as exc:
                raise ValueError(f"gate input {name!r} is not a tri-state envelope") from exc

    def gate_input(self, name: str) -> Tri[Any]:
        """One ``gate_inputs`` entry, as a :class:`Tri`.

        Raises if absent, making a missing gate a distiller bug rather than a silent undetermined. Genuinely
        undetermined gates are written as ``Tri.not_determined().to_json()``.
        """
        if name not in self.gate_inputs:
            raise KeyError(f"gate input {name!r} was never distilled for {self.claim_id} on {self.function_name}")
        return Tri.from_json(self.gate_inputs[name])

    @property
    def enters_grade(self) -> bool:
        """Whether the fold may score this row.

        Undetermined severity fails closed, so absent constraint witnesses never escalate.
        """
        return self.severity.state == SEVERITY_STATE_PROVEN


def not_determined_signal_defaults() -> dict[str, Any]:
    """The undetermined value for each three-state field, to splat explicitly so choosing ``not_determined`` is
    visible at the call site.
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


def signal_to_row_kwargs(signal: FunctionSignal, *, job_id: Any = None) -> dict[str, Any]:
    """:class:`FunctionSignal` to ``FunctionScoreSignal`` column values.

    Owned here so the shapes can't drift (a state in the wrong column passes every CHECK). ``job_id`` is supplied by the
    writer. Returns kwargs to avoid importing ``db.models``, which loads the engine.
    """
    return {
        "job_id": job_id if job_id is not None else signal.job_id,
        "protocol_id": signal.protocol_id,
        "chain": signal.chain,
        "deployment_address": signal.deployment_address,
        "contract_id": signal.contract_id,
        "function_id": signal.function_id,
        "selector": signal.selector,
        "function_name": signal.function_name,
        "claim_id": signal.claim_id,
        "witness_tier": signal.witness_tier,
        "severity_state": signal.severity.state,
        "severity_proven": signal.severity.value,
        "severity_basis": list(signal.severity_basis),
        "authority_openness": signal.authority_openness,
        "principal_state": signal.principal_state,
        "principal_refs": [ref.to_json() for ref in signal.principal_refs],
        "value_state": signal.value_state,
        "value_bound": signal.value_bound,
        "value_entity_keys": list(signal.value_entity_keys),
        "value_basis": signal.value_basis,
        "destination_state": signal.destination.state,
        "destination_shape": signal.destination.value,
        "reach_gate_state": signal.reach_gate_state,
        "gate_inputs": dict(signal.gate_inputs),
        "citations": list(signal.citations),
        "witness_notes": list(signal.witness_notes),
        "effect_verdict_id": signal.effect_verdict_id,
    }


def signal_from_row(row: Any) -> FunctionSignal:
    """``FunctionScoreSignal`` to :class:`FunctionSignal`, the inverse seam.

    ``severity_proven`` is narrowed from ``Decimal`` to ``float`` here.
    """
    severity = (
        Tri.not_determined()
        if row.severity_state == SEVERITY_STATE_NOT_DETERMINED
        else Tri.proven(row.severity_state, float(row.severity_proven))
    )
    destination = (
        Tri.not_determined()
        if row.destination_state == NOT_DETERMINED
        else Tri.proven(row.destination_state, str(row.destination_shape))
    )
    return FunctionSignal(
        job_id=row.job_id,
        protocol_id=row.protocol_id,
        chain=row.chain,
        deployment_address=row.deployment_address,
        contract_id=row.contract_id,
        function_id=row.function_id,
        selector=row.selector,
        function_name=row.function_name,
        claim_id=row.claim_id,
        witness_tier=row.witness_tier,
        severity=severity,
        severity_basis=tuple(row.severity_basis or ()),
        authority_openness=row.authority_openness,
        principal_state=row.principal_state,
        principal_refs=tuple(PrincipalRef.from_json(r) for r in (row.principal_refs or ())),
        value_state=row.value_state,
        value_bound=row.value_bound,
        value_entity_keys=tuple(row.value_entity_keys or ()),
        value_basis=row.value_basis,
        destination=destination,
        reach_gate_state=row.reach_gate_state,
        gate_inputs=dict(row.gate_inputs or {}),
        citations=tuple(row.citations or ()),
        witness_notes=tuple(row.witness_notes or ()),
        effect_verdict_id=row.effect_verdict_id,
    )


@dataclass(frozen=True, slots=True)
class ScoreDocument:
    """What a fold emits and ``protocol_scores`` persists.

    ``grade``, ``exposure`` and ``confidence_pct`` share one ``grade_state`` (``ck_protocol_scores_grade_pairing``).
    ``model_parameters`` travels with each document so scores are compared under their own constants.

    ``provenance`` must distinguish "no population" from "population scored to nothing"; both surface as ``grade_state =
    not_determined``, so the per-plane counts are the only place the difference survives.
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

    # Faults census, or ``None`` (key omitted) when every published magnitude was read. The field arrived mid-1.1.0 (PR
    # #172): absence is ambiguous on 1.1.0-provisional or earlier and an earned zero from 1.2.0-provisional on.
    execution_evidence_faults: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        _check_member("trigger", self.trigger, SCORE_TRIGGERS)
        _check_member("perimeter_state", self.perimeter_state, PERIMETER_STATES)
        _check_member("grade_state", self.grade_state, GRADE_STATES)
        determined = (self.grade_lambda, self.grade_exposure, self.confidence_pct)
        if (self.grade_state == GRADE_STATE_COMPUTED) != all(v is not None for v in determined):
            raise ValueError("grade, exposure and confidence are determined together or not at all")

    def document(self) -> dict[str, Any]:
        """The JSONB persisted to ``protocol_scores.findings``, served verbatim: projections are where three states
        collapsed to two.
        """
        payload: dict[str, Any] = {
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
        if self.execution_evidence_faults is not None:
            payload["execution_evidence_faults"] = self.execution_evidence_faults
        return payload


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
