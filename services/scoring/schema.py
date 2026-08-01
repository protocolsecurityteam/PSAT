"""The typed signal-row and score-document contract.

This is the surface Layer 1 (per-function distillation, end of the effects
stage) hands to Layer 2 (the whole-protocol grade fold). It is deliberately the
only shape either side agrees on: distillation produces :class:`FunctionSignal`,
the fold consumes nothing else, and the persisted ``function_score_signals``
plane round-trips it through :func:`signal_to_row_kwargs` /
:func:`signal_from_row` — the seam is owned here, and pinned by a test that
sends all three states of every field through the database and back.

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

Lifecycle
---------
Signals are a CURRENT-STATE plane, replaced wholesale per contract by
:func:`services.scoring.population.replace_contract_signals`. ``job_id`` on a
signal is provenance, never identity: re-analysis mints a new job, so keying on
it would accumulate one stale signal set per re-analysis and the fold would
double-count them. The fold reads
:func:`services.scoring.population.current_signals_for_protocol` and needs no
currency filtering of its own.

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
    DESTINATION_BEARING_CLAIMS,
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


def coalesce_chain(chain: str | None) -> str:
    """Chain token, byte-identical to ``company_overview._coalesce_chain``.

    NULL/empty/``"mainnet"`` fold to ``"ethereum"`` (the NULL≡ethereum legacy
    read convention); everything else lowercases as-is. Deliberately NOT
    :func:`utils.chains.canonical_chain`, which folds extra aliases the entity
    key does not.

    Load-bearing for MAX-per-entity: without the fold, ``"mainnet"``,
    ``"Ethereum"`` and ``None`` mint three keys for one entity and the
    deduplication silently stops deduplicating — the value axis would then
    charge the same vault up to three times. ``tests/test_scoring_schema.py``
    pins this against the canon so the two cannot drift.
    """
    token = str(chain or "").strip().lower()
    if not token or token == "mainnet":
        return "ethereum"
    return token


def entity_key(chain: str | None, address: str | None) -> str:
    """The chain-scoped value/principal entity token, ``<chain>::<address>``.

    Chain-scoped because the same address on two chains is two entities: an
    unscoped key re-introduces the cross-chain twin aliasing that #158 closed,
    and would let one chain's value pool inflate another chain's finding.
    """
    return f"{coalesce_chain(chain)}::{str(address or '').lower()}"


def is_entity_key(token: str) -> bool:
    """Whether ``token`` is a well-formed chain-scoped key.

    A bare address passes no chain scope and would alias every chain's copy of
    that address into one entity, so it is rejected rather than coerced.
    """
    if not isinstance(token, str) or token.count("::") != 1:
        return False
    chain, _, address = token.partition("::")
    return bool(chain) and bool(address) and token == entity_key(chain, address)


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
        # Biconditional, both arms load-bearing. An undetermined fact carrying a
        # value is one a careless reader can still pick up; a proven fact with no
        # value is a state claiming a witness it cannot produce. Neither is
        # representable.
        if self.state == NOT_DETERMINED:
            if self.value is not None:
                raise ValueError(f"not_determined carries no value, got {self.value!r}")
        elif self.value is None:
            raise ValueError(f"state {self.state!r} is proven and must carry its witness value")

    @classmethod
    def not_determined(cls) -> Tri[T]:
        """Spelled out at every call site so an unread witness is greppable."""
        return cls(state=NOT_DETERMINED, value=None)

    def to_json(self) -> dict[str, Any]:
        """The wire shape used inside ``gate_inputs``. Always both keys.

        The state is never left implicit in a key's absence: a reader must find
        a state to branch on, or find nothing at all and raise.
        """
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
    construct the row at all.

    ``contract_id`` is required for the same reason, though it is an identifier
    rather than a state: it is part of the signal's IDENTITY (split-proxy
    secondary implementations share one ``deployment_address``, so it is the
    only thing distinguishing two legitimately different contracts' signals).
    Defaulting it to ``None`` was only survivable on the persisted path, where
    the NOT NULL column eventually rejects it — three layers from the distiller
    that made the mistake. On the §7.5 in-memory CLI path there is no database
    at all, so a ``None`` would never be caught and split-proxy siblings would
    collapse into one another in the differential oracle, diverging the two
    feeding modes that §7.5 guarantees are identical.

    ``function_id`` and ``effect_verdict_id`` do keep their defaults: they are
    optional back-references, not identity, and their ``None`` honestly means
    "no such row to point at".
    """

    job_id: Any
    protocol_id: int
    contract_id: int
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
        # Every entity key must be chain-scoped and canonically formed, or
        # MAX-per-entity silently stops deduplicating the entity it names.
        bad_keys = [k for k in self.value_entity_keys if not is_entity_key(k)]
        if bad_keys:
            raise ValueError(f"value_entity_keys must be canonical <chain>::<address> tokens, got {bad_keys!r}")
        # A destination-bearing capability can never claim it has no destination.
        if self.destination.state == DESTINATION_STATE_NOT_APPLICABLE and self.claim_id in DESTINATION_BEARING_CLAIMS:
            raise ValueError(f"{self.claim_id} has a destination; not_applicable would launder an unread one")
        for name, raw in self.gate_inputs.items():
            try:
                Tri.from_json(raw)
            except ValueError as exc:
                raise ValueError(f"gate input {name!r} is not a tri-state envelope") from exc

    def gate_input(self, name: str) -> Tri[Any]:
        """One ``gate_inputs`` entry, as a :class:`Tri`. RAISES if absent.

        The only sanctioned way to read that blob. A ``dict.get`` would return
        ``None`` for a gate the distiller never wrote, and every caller would
        then have to remember that ``None`` means "unread" rather than "absent
        constraint" — which is the absence-reads-as-a-fact defect, re-entering
        through a JSONB key instead of a column. Raising makes a missing gate a
        bug in the distiller rather than a silent not_determined at the fold.

        A gate that was genuinely not determined is written explicitly, as
        ``Tri.not_determined().to_json()``, and comes back as such.
        """
        if name not in self.gate_inputs:
            raise KeyError(f"gate input {name!r} was never distilled for {self.claim_id} on {self.function_name}")
        return Tri.from_json(self.gate_inputs[name])

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


def signal_to_row_kwargs(signal: FunctionSignal, *, job_id: Any = None) -> dict[str, Any]:
    """:class:`FunctionSignal` → ``FunctionScoreSignal`` column values.

    The seam is owned here rather than left to each caller so the two shapes
    cannot drift: a state written to the wrong column is a three-state collapse
    that no CHECK downstream would catch, because every individual value is
    still legal. ``job_id`` is provenance and is passed in by the writer, not
    carried on the signal — the same signal is re-derivable from a later job.

    Returns kwargs rather than the ORM object so this module keeps no import on
    ``db.models`` (which loads the engine at import time).
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
    """``FunctionScoreSignal`` → :class:`FunctionSignal`. The inverse seam.

    Reconstructs the ``Tri`` pairs from their column pairs, so the fold reads
    the same three states the distiller wrote and never sees a bare NULL it
    would have to interpret. ``severity_proven`` comes back as a ``Decimal``
    from Postgres and is narrowed to ``float`` here, at the one place that knows
    it is a model quantity rather than a currency amount.
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

    ``grade`` and ``exposure`` are undetermined together with ``confidence_pct``
    — a grade with no confidence is not a grade — which is why one
    ``grade_state`` covers all three, matching ``ck_protocol_scores_grade_pairing``.

    ``model_parameters`` travels with every document rather than being read from
    code at display time: two scores are only comparable against the constants
    each was actually computed under, and it carries the uncalibrated-arm flags
    so a consumer can see which rules have never fired their positive branch.

    **Required of the fold (inherited from the ``protocol_scores_latest``
    divergence):** ``provenance`` MUST distinguish "no population" — no current
    signals for this protocol, nothing was scorable — from "population scored to
    nothing", where signals existed and every one of them failed closed. Both
    reach the read surface as ``grade_state = not_determined`` and the view
    cannot tell them apart, so the per-plane signal counts in ``provenance`` are
    the only place the difference survives. Collapsing them would make an
    un-analysed protocol and a fully-undetermined one indistinguishable, which
    is precisely the absence-reads-as-a-fact defect at protocol scope.
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
