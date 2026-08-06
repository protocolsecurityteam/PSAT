"""Layer 2 — the whole-protocol grade fold. Pure, read-only, deterministic.

The fold is a recompute, never an accumulator. Three facts make a running total
wrong: value is MAX per (entity, asset) so two contracts reaching one vault must
charge it once; principal units are cross-contract and get RE-KEYED when a later
contract reveals an owner overlap; and which finding subsumes which is only
decidable with the whole finding set present.

Its population is the signal plane and nothing else — read through the one
pinned, totally ordered query — plus the resolution planes in
:mod:`services.scoring.planes`, which is where a reference becomes a unit, a
dollar or a breadth floor.

THE ROOT RULE
-------------
**Never substitute an available field for an unread one.** Every ``x or y`` on a
nullable or three-state expression is that substitution written as an idiom: an
owner set that did not resolve is not the threshold, an unread delay is not zero,
an unpriced entity is not ``$0.00``, and a principal address is not its own owner
set unless the principal IS a key. Where a witness is missing the answer is the
uncredited rung, an explicit ``None``, or a withheld row — chosen so the mistake
costs a credit rather than fabricating one. Every remaining fallback in this
module is guarded by a proof that the substituted value IS the fact.

Every arithmetic branch fails closed. A signal whose severity was not proven is
not scored; a value that could not be priced falls to the unpriced branch rather
than to zero; a malformed gate envelope withholds its own row rather than
raising out of the whole fold.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from services.scoring import constants as K
from services.scoring import planes as P
from services.scoring.population import current_signals_with_faults
from services.scoring.schema import (
    NOT_DETERMINED,
    FunctionSignal,
    ScoreDocument,
    Tri,
    entity_key,
)
from utils.scoring_status import (
    GRADE_STATE_COMPUTED,
    GRADE_STATE_NOT_DETERMINED,
    MODEL_VERSION,
    OPENNESS_NOT_DETERMINED,
    OPENNESS_OPEN,
    PRINCIPAL_STATE_ENUMERATED,
    PRINCIPAL_STATE_NONE_REQUIRED,
    PRINCIPAL_STATE_NOT_DETERMINED,
    SCORE_TRIGGER_MANUAL,
    SEVERITY_STATE_PROVEN,
    VALUE_STATE_PROVEN_NO_REACH,
    VALUE_STATE_PROVEN_REACH,
)

ANYONE = "anyone"

# The closed vocabulary of every gate the fold reads: gate name → the proven
# state tokens that license its positive branch. ``gate_inputs`` is free-form
# JSONB with no CHECK behind it, so a reader that branches on "is not
# not_determined" treats a WITHHELD envelope (say ``not_earned``) as the earned
# one. Branching on the exact token is what makes the two different facts again.
GATE_PROVEN_TOKENS: dict[str, tuple[str, ...]] = {
    "exact_empty_credit": ("earned",),
    "latch_witness": ("witnessed",),
    "reach_magnitude_usd": ("proven_exact", "proven_floor"),
    "token_identity": ("proven",),
    "asset_class": ("proven",),
    "input_seeded": ("proven",),
    "contract_balance_seeded": ("proven",),
    "amount_capped_by_balance": ("proven",),
    "asset_identity": ("resolved",),
    "pause_effective": ("proven",),
    "freeze_recovery_principals": ("enumerated",),
    "freeze_coverage_fraction": ("observed_blast_radius",),
    "destination_basis": ("basis",),
}

# Gates whose payload enters arithmetic. Validated as a real, finite number at
# READ as well as at construction: a string "1e12" compares and multiplies just
# fine in Python and would charge $1T off an untyped payload.
NUMERIC_GATES = frozenset({"reach_magnitude_usd"})

# Every gate's payload SHAPE, checked before any consumer walks it. ``gate_inputs``
# is free-form JSONB, so a list the fold iterates as dicts can arrive as a list of
# ints; without this the walk raises out of ``compute_protocol_score`` and one bad
# payload on one function silently costs the whole protocol its score.
GATE_PAYLOAD_SHAPES: dict[str, str] = {
    "exact_empty_credit": "object",
    "latch_witness": "object",
    "asset_identity": "object",
    "reach_magnitude_usd": "number",
    "token_identity": "bool",
    "input_seeded": "bool",
    "contract_balance_seeded": "bool",
    "amount_capped_by_balance": "bool",
    "asset_class": "string",
    "destination_basis": "string",
    "pause_effective": "bool",
    "freeze_coverage_fraction": "string_list",
    "freeze_recovery_principals": "principal_ref_list",
}

# The gates the fold WILL read for a given claim. A signal missing one of them is
# a distiller bug, and it withholds its own row: reading a gate that was never
# written would put a default where a witness belongs, and raising would let one
# malformed row take the whole protocol's grade down with it.
REQUIRED_GATES = ("exact_empty_credit", "latch_witness", "reach_magnitude_usd")
REQUIRED_GATES_BY_CLAIM: dict[str, tuple[str, ...]] = {
    "flow.out": ("token_identity", "asset_class", "asset_identity"),
    "pause.set": ("freeze_recovery_principals",),
}

SINGLE_ASSET_CLASSES = frozenset({"erc20_only", "mixed"})


@dataclass
class _Instance:
    """One signal's contribution to one (unit, capability, weakness) row."""

    signal: FunctionSignal
    severity: float
    severity_basis: tuple[str, ...]
    entity_keys: tuple[str, ...]
    magnitude: Tri[float]
    value_bound: str
    pricing_blocked: str | None
    native_only: bool
    asset_identity_undecidable: bool
    # The principal this instance was witnessed under. A merged unit's row folds
    # instances from several members, and without this the row cannot say WHICH
    # member is proven to reach a given entity (inv.5 is the weakest path to that
    # entity, not the weakest member of the unit).
    principal_address: str = ""


@dataclass
class _Row:
    unit: str
    capability: str
    path: str
    weakness: float = 0.0
    weakest_label: str = ""
    principal_kind: str = ""
    weakest_address: str = ""
    principal_addresses: set[str] = field(default_factory=set)
    # Per contributing member address, the ``(weakness, label, kind)`` IT earned.
    # The row-level ``weakness`` is the max over these, which is only the right
    # price for an entity every member reaches; ``_aggregate`` re-attributes the
    # rest from this map.
    member_gate: dict[str, tuple[float, str, str]] = field(default_factory=dict)
    # The burn-sentinel admission rule's own count, and the instances it emptied
    # outright — an admission rule publishes what it refused (§3.1 pt 5).
    zero_reach_keys_refused: int = 0
    zero_reach_stripped: list[dict[str, Any]] = field(default_factory=list)
    instances: list[_Instance] = field(default_factory=list)
    seeds: set[str] = field(default_factory=set)
    tiers: set[str] = field(default_factory=set)
    notes: set[str] = field(default_factory=set)
    citations: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class _RowValue:
    """What one row's instances proved about value, and what they did not."""

    per_entity: dict[str, float]
    total_usd: float | None
    basis: str
    undetermined: list[dict[str, Any]]
    proven_no_reach: list[dict[str, Any]]
    # Witnessed membership, NOT the keys of ``per_entity``: an entity whose
    # dollars are not_determined is still an entity the row provably reaches.
    reach: set[str]
    magnitude_caps: list[dict[str, Any]]


def compute_protocol_score(
    session: Session,
    protocol_id: int,
    *,
    signals: list[FunctionSignal] | None = None,
    trigger: str = SCORE_TRIGGER_MANUAL,
    trigger_job_id: Any | None = None,
    computed_at: datetime | None = None,
) -> ScoreDocument:
    """The protocol's score document, folded over its current signal rows.

    ``signals`` is the §7.5 in-memory feeding mode and nothing else: the offline
    CLI distils every contract without persisting, and passes the result in the
    population order :func:`order_signals` pins. Left unset — every persisted
    path — the population comes from the one pinned query and from nowhere else,
    so no caller can hand the fold a filtered or re-ordered population.
    """
    row_faults: list[dict[str, Any]] = []
    if signals is None:
        # A row whose persisted JSONB does not hold its declared shape withholds
        # ITSELF: the schema's canonical-key checks are the right checks, but
        # raising them through the population read costs the whole protocol its
        # score over one bad column.
        signals, row_faults = current_signals_with_faults(session, protocol_id)

    value_plane = P.load_value_plane(session, protocol_id)
    closure = P.load_control_closure(session, protocol_id)
    role_floors = P.load_role_holder_floors(session, protocol_id)
    refs = [ref for signal in signals for ref in signal.principal_refs]
    refs.extend(_recovery_refs(signals))
    principal_facts = P.load_principal_plane(session, refs)

    warnings: list[dict[str, Any]] = [
        {
            "kind": "signal_row_malformed",
            "entity": fault["entity"],
            "function": fault["function_name"],
            "capability": fault["claim_id"],
            "note": f"signal row withheld: {fault['column']} does not hold its declared shape",
            "column": fault["column"],
            "detail": fault["detail"],
        }
        for fault in row_faults
    ]
    earned_negatives: list[dict[str, Any]] = []
    seen_negatives: set[tuple[str, str]] = set()

    units = _UnitResolver(signals, principal_facts, role_floors)
    rows_by_key: dict[tuple[str, str, str], _Row] = {}

    for signal in signals:
        malformed = _malformed_gates(signal)
        if malformed:
            # One unreadable envelope withholds its own row. Raising here would
            # take the whole protocol's grade down with one bad payload, and
            # scoring around it would read a payload nobody validated.
            warnings.append(_warning("gate_input_malformed", signal, f"unreadable gate envelopes: {malformed}"))
            continue

        _collect_disclosures(signal, earned_negatives, seen_negatives, warnings)
        if not signal.enters_grade:
            continue

        if signal.authority_openness == OPENNESS_OPEN:
            severity, severity_basis, extra_notes = _fold_severity(signal, None, principal_facts, warnings)
            instance = _instance(signal, severity, severity_basis, ANYONE)
            unit = entity_key(signal.chain, ANYONE)
            row = _row_for(rows_by_key, unit, signal.claim_id, "direct", K.WEAKNESS_ANYONE, "ANYONE", ANYONE, ANYONE)
            _attach(row, signal, instance, extra_notes)
            continue

        if signal.authority_openness == OPENNESS_NOT_DETERMINED:
            warnings.append(_warning("unresolved_reachability", signal, "authority_openness is not_determined"))
            continue

        if signal.principal_state != PRINCIPAL_STATE_ENUMERATED:
            warnings.append(
                _warning("restricted_privileged_no_principal", signal, "no resolved principal and no earned empty")
            )
            continue

        for ref in signal.principal_refs:
            facts = principal_facts.get(int(ref.function_principal_id))
            if facts is None:
                warnings.append(_warning("principal_row_missing", signal, f"principal {ref.address} not readable"))
                continue
            severity, severity_basis, extra_notes = _fold_severity(signal, facts, principal_facts, warnings)
            instance = _instance(signal, severity, severity_basis, facts.address)
            weakness, label, kind, notes = units.weakness_for(
                facts,
                recovery_proven_independent=any(n.startswith("keyset_independent") for n in extra_notes),
            )
            if weakness is None:
                warnings.append(
                    _warning(
                        "contract_gated_unknown_path" if kind == "contract" else "unresolved_principal",
                        signal,
                        f"gated by a {label} principal whose own authority is not reduced to a key",
                        principal=facts.address,
                    )
                )
                continue
            unit = units.unit_for(facts)
            row = _row_for(
                rows_by_key,
                unit,
                signal.claim_id,
                units.path_for(facts),
                weakness,
                label,
                kind,
                facts.address,
            )
            _attach(row, signal, instance, extra_notes | set(notes))

    findings, subsumed, value_warnings = _aggregate(rows_by_key, value_plane, closure, units)
    warnings.extend(value_warnings)

    grade_lambda, grade_exposure, exposure_usd, exposure_gaps = _grade(findings, value_plane)
    confidence = _confidence(
        signals,
        value_plane,
        closure,
        P.load_proven_eoa_entities(session, protocol_id),
        P.discovery_relation_entities(session, protocol_id),
    )

    perimeter, perimeter_detail = P.perimeter_state(session, protocol_id)
    provenance: dict[str, Any] = {
        "plane_row_counts": P.plane_row_counts(session, protocol_id),
        "population": {
            "signals": len(signals),
            "signals_entering_grade": sum(1 for s in signals if s.enters_grade),
            "findings": len(findings),
            "subsumed_rows": len(subsumed),
            # The distinction the read surface cannot make on its own: an
            # un-analysed protocol and a fully-undetermined one both reach a
            # consumer as grade_state=not_determined.
            "disposition": _population_disposition(signals, findings),
            "rows_withheld_malformed": len(row_faults),
        },
        "value": value_plane.provenance,
        "value_annotations": value_plane.annotations,
        # Each closure admission rule, counted where it fired AND where it did
        # not. A refusal and an earned negative are different facts about the
        # same row: the first says what this scorer declined to walk, the second
        # says the protocol has proven an authority slot empty, and only the
        # second is evidence about the protocol.
        "closure_admission": {
            "refusals": closure.refusal_counts(),
            "renounced": closure.renounced_counts(),
            "reading": (
                "refusals are EDGES this closure declined to admit, by rule: the zero address "
                "is a burn sentinel and not an assessable entity, so it is refused as principal "
                "and as anchor rather than becoming the largest control hub in the graph. "
                "renounced counts controller_value edges pointing AT the zero address, which is "
                "an authority slot proven EMPTY — renunciation for an ownership slot, an unset "
                "reference for a configuration pointer, proven-absent authority either way. "
                "edges is the citable row population; authority_slots is the distinct "
                "(anchor, label) it resolves to, which is the number of facts — the edge table "
                "carries one row per witnessed read, so the two differ by how often the "
                "resolver looked and never by how much authority was renounced"
            ),
        },
        "unpriced_positions": value_plane.unpriced_positions,
        "exposure_gaps": exposure_gaps,
        "principal_units": units.published_units(),
        "safe_keyset_overlaps": units.overlaps,
        "unit_evidence_scope": (
            "principal_units and safe_keyset_overlaps cover only the Safes reachable "
            "from claim-bearing signals: a Safe that gates nothing this scorer scored "
            "is absent from the union-find, so an overlap it would have merged is "
            "not_determined rather than proven absent"
        ),
        "upgrade_history": P.load_upgrade_provenance(session, protocol_id),
        "unconsumed_reach_relations": P.unconsumed_reach_relations(session, protocol_id),
        "ledgers": P.load_ledgers(session, protocol_id),
        "audit_posture": P.load_audit_posture(session, protocol_id, value_plane),
        "perimeter": perimeter_detail,
        "signal_scope": (
            "a signal is keyed on a CAPABILITY, so a function carrying no claim produces "
            "none: its earned empty caller set and its one_shot latch witness are outside "
            "this document. That is a distillation gap, never a proven absence"
        ),
        "determinism": (
            "every query carries a total ORDER BY and every sort a total tiebreak; "
            "the same DB state yields an identical document modulo computed_at"
        ),
    }

    # The three grade figures stand or fall together, and so does everything
    # derived from them. An exposure ratio with no priced denominator is not a
    # 100 — it is a quantity that was never measured — so a protocol with
    # findings but no priced value publishes the findings and parks every
    # derived number under provenance instead of serving it beside a withheld
    # grade.
    scored = bool(findings) and grade_exposure is not None
    if not scored:
        withheld_rows = [
            {
                "principal_unit": finding["principal_unit"],
                "capability": finding["capability"],
                "net_points_lambda": finding.pop("net_points_lambda", None),
                "exposure_usd": finding.pop("exposure_usd", None),
            }
            for finding in findings
        ]
        if findings:
            provenance["grade_withheld"] = {
                "grade_lambda_computed": grade_lambda,
                "confidence_pct_computed": confidence.pop("pct", None),
                "exposure_usd_computed": exposure_usd,
                "per_finding": withheld_rows,
                "reason": "no priced value in the perimeter, so the exposure denominator is not_determined",
            }
        else:
            confidence.pop("pct", None)

    return ScoreDocument(
        protocol_id=protocol_id,
        model_version=MODEL_VERSION,
        computed_at=computed_at or datetime.now(timezone.utc),
        trigger=trigger,
        trigger_job_id=trigger_job_id,
        perimeter_state=perimeter,
        grade_state=GRADE_STATE_COMPUTED if scored else GRADE_STATE_NOT_DETERMINED,
        grade_lambda=grade_lambda if scored else None,
        grade_exposure=grade_exposure if scored else None,
        confidence_pct=confidence.get("pct") if scored else None,
        findings=findings,
        earned_negatives=sorted(earned_negatives, key=lambda e: (e["entity"], e["function"], e["capability"])),
        warnings=_summarise_warnings(warnings),
        model_parameters={**K.model_parameters(), "confidence_detail": confidence},
        provenance={**provenance, "subsumed_rows": subsumed, "exposure_usd": exposure_usd if scored else None},
        uncalibrated_arms=K.UNCALIBRATED_ARMS,
    )


def _row_for(
    rows: dict[tuple[str, str, str], _Row],
    unit: str,
    capability: str,
    path: str,
    weakness: float,
    label: str,
    kind: str,
    address: str,
) -> _Row:
    """The row for one (unit, capability, ACCESS PATH), at its weakest gate.

    The path is part of the key because a unit can hold the same capability
    through paths that cost different things: a Safe that also proposes-and-
    executes on a timelock reaches the timelock's contracts only by paying the
    delay, and one max-weakness row would charge that delayed value at the
    Safe's undelayed rung. Within one path the weakest gate still wins (inv.5),
    which is what keeps two merged Safes one power rather than two.
    """
    key = (unit, capability, path)
    row = rows.get(key)
    if row is None:
        row = _Row(unit=unit, capability=capability, path=path)
        rows[key] = row
    if weakness > row.weakness or not row.weakest_label:
        row.weakness = weakness
        row.weakest_label = label
        row.principal_kind = kind
        row.weakest_address = address
    row.principal_addresses.add(address)
    # The member's OWN rung, kept beside the unit's weakest: a merged Safe unit
    # publishes one reach union, and pricing an entity only the 4/8 member
    # reaches at the 3/7 member's rung charges a coalition nobody proved.
    previous = row.member_gate.get(address)
    if previous is None or weakness > previous[0]:
        row.member_gate[address] = (weakness, label, kind)
    return row


# ---------------------------------------------------------------- gate reads


def _malformed_gates(signal: FunctionSignal) -> list[str]:
    """Gate envelopes this fold refuses to read, by name.

    A state outside the gate's closed vocabulary, or a numeric payload that is
    not a finite number, is a row this fold cannot score honestly.
    """
    bad: list[str] = []
    for name in REQUIRED_GATES + REQUIRED_GATES_BY_CLAIM.get(signal.claim_id, ()):
        if name not in signal.gate_inputs:
            bad.append(f"{name}(absent)")
    for name, raw in sorted(signal.gate_inputs.items()):
        expected = GATE_PROVEN_TOKENS.get(name)
        if expected is None:
            continue
        try:
            tri = Tri.from_json(raw)
        except ValueError:
            bad.append(name)
            continue
        if tri.state == NOT_DETERMINED:
            continue
        if tri.state not in expected:
            bad.append(name)
            continue
        if not _payload_has_shape(name, tri.value):
            bad.append(name)
    return bad


def _payload_has_shape(name: str, value: Any) -> bool:
    """Whether a proven gate payload is the shape its consumers walk."""
    shape = GATE_PAYLOAD_SHAPES.get(name)
    if shape is None:
        return True
    if shape == "number":
        return _is_number(value)
    if shape == "bool":
        return isinstance(value, bool)
    if shape == "string":
        return isinstance(value, str)
    if shape == "object":
        return isinstance(value, dict)
    if shape == "string_list":
        return isinstance(value, list) and all(isinstance(item, str) for item in value)
    if shape == "principal_ref_list":
        return isinstance(value, list) and all(_is_principal_ref(item) for item in value)
    return False


def _is_principal_ref(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    raw_id = entry.get("function_principal_id")
    if isinstance(raw_id, bool) or not isinstance(raw_id, int):
        return False
    for key in ("chain", "address"):
        if key in entry and entry[key] is not None and not isinstance(entry[key], str):
            return False
    return True


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value))


def _gate(signal: FunctionSignal, name: str) -> Tri[Any]:
    """One gate, read on its EXACT proven token. Never "is not not_determined".

    A state the gate's vocabulary does not name is returned as
    ``not_determined``: an unrecognised token is a witness this fold cannot
    vouch for, and reading it as the positive branch is how a withheld arm
    publishes an earned one.
    """
    try:
        tri = signal.gate_input(name)
    except KeyError:
        # ``_malformed_gates`` has already withheld any row whose required gates
        # are missing; this arm keeps an incidental read from raising out of the
        # fold rather than inventing a value.
        return Tri.not_determined()
    expected = GATE_PROVEN_TOKENS.get(name, ())
    if tri.state == NOT_DETERMINED or tri.state in expected:
        if name in NUMERIC_GATES and tri.is_determined and not _is_number(tri.value):
            return Tri.not_determined()
        return tri
    return Tri.not_determined()


# ---------------------------------------------------------------- principals


class _UnitResolver:
    """Principal units: per (chain, address), with the two licensed collapses.

    Safes that can ACT AS each other are one unit — independence is a property of
    owner KEY SETS, and two Safes sharing enough owners are one power. A timelock
    whose proposer-executor is a Safe collapses into that Safe: upgrade-by-
    timelock is a subset of exec-by-proposer, so two rows would charge the same
    value twice. The collapse needs BOTH halves proven — proposing without
    executing is not acting as the timelock — and neither collapse ever crosses a
    chain, because same-address is not proof of same owner set.
    """

    def __init__(
        self,
        signals: list[FunctionSignal],
        principal_facts: dict[int, P.PrincipalFacts],
        role_floors: dict[tuple[str, str, str], dict[str, Any]],
    ) -> None:
        self._facts = principal_facts
        self._role_floors = role_floors
        by_key: dict[str, list[P.PrincipalFacts]] = defaultdict(list)
        for facts in sorted(principal_facts.values(), key=lambda f: f.key):
            if facts.resolved_type == "safe" and facts.owners:
                by_key[facts.key].append(facts)
        # Last row wins, exactly as before: which contradictory owner set to adopt
        # is an open ruling (R17), and this fold does not arbitrate it. What it
        # will not do is arbitrate SILENTLY — a Safe whose witnesses disagree
        # publishes the disagreement beside the set the merge decision used.
        self._safe_by_key = {key: rows[-1] for key, rows in by_key.items()}
        self.owner_set_contradictions = [
            {
                "safe": key,
                "adopted_owner_set": sorted(rows[-1].owners),
                "adopted_k_of_n": (
                    f"{rows[-1].threshold}/{len(rows[-1].owners)}"
                    if rows[-1].threshold is not None
                    else f"k not_determined/{len(rows[-1].owners)}"
                ),
                "witnesses": [
                    {
                        "function_principal_id": row.function_principal_id,
                        "owners": sorted(row.owners),
                        "threshold": row.threshold,
                    }
                    for row in sorted(rows, key=lambda r: r.function_principal_id)
                ],
                "basis": (
                    "function_principals rows disagree on this Safe's owner set; the adopted "
                    "row is the one this fold read, NOT an adjudication that the others are wrong"
                ),
            }
            for key, rows in sorted(by_key.items())
            if len({frozenset(row.owners) for row in rows}) > 1
        ]
        self._parent = {key: key for key in self._safe_by_key}
        self.overlaps: list[dict[str, Any]] = []
        self._union_overlapping_safes()
        self._proposers = self._timelock_proposer_executors(signals)
        self._members: dict[str, set[str]] = defaultdict(set)

    def _find(self, key: str) -> str:
        while self._parent[key] != key:
            self._parent[key] = self._parent[self._parent[key]]
            key = self._parent[key]
        return key

    def _union_overlapping_safes(self) -> None:
        keys = sorted(self._safe_by_key)
        for i, a in enumerate(keys):
            for b in keys[i + 1 :]:
                left, right = self._safe_by_key[a], self._safe_by_key[b]
                if left.chain != right.chain:
                    continue
                shared = left.owners & right.owners
                if not shared:
                    continue
                # An unread threshold cannot license a merge: "these two Safes are
                # one power" needs both thresholds proven, and a sentinel standing
                # in for one would publish a coalition size nobody measured.
                if left.threshold is None or right.threshold is None:
                    self.overlaps.append(
                        {
                            "a": a,
                            "b": b,
                            "shared_owners": len(shared),
                            "merged": False,
                            "basis": "threshold_not_determined_on_at_least_one_side",
                        }
                    )
                    continue
                k_left, k_right = left.threshold, right.threshold
                can_act = len(shared) >= max(k_left, k_right)
                block_left = len(left.owners) - k_left + 1
                block_right = len(right.owners) - k_right + 1
                self.overlaps.append(
                    {
                        "a": a,
                        "b": b,
                        "a_k_of_n": f"{k_left}/{len(left.owners)}",
                        "b_k_of_n": f"{k_right}/{len(right.owners)}",
                        "shared_owners": len(shared),
                        "shared_can_act_as_both": can_act,
                        "shared_can_block_both": len(shared) >= max(block_left, block_right),
                        "min_coalition_to_act_as_both": max(k_left, k_right) if can_act else None,
                        "merged": can_act,
                        "basis": "owner_key_set_intersection",
                    }
                )
                if can_act:
                    root_a, root_b = self._find(a), self._find(b)
                    if root_a != root_b:
                        self._parent[root_b] = root_a
        self.overlaps.sort(key=lambda o: (o["a"], o["b"]))

    def _timelock_proposer_executors(self, signals: list[FunctionSignal]) -> dict[str, dict[str, Any]]:
        """The weakest Safe proven able to BOTH propose and execute on a timelock.

        Both halves are required because the collapse asserts the Safe can act as
        the timelock. A propose-only witness proves the right to start a delayed
        action, not the right to complete one, and treating it as the collapse
        would re-price every timelock-gated dollar at the proposer's undelayed
        weakness on the strength of a witness that never mentioned execution.
        """
        by_role: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"schedule": set(), "execute": set()})
        facts_by_key: dict[str, P.PrincipalFacts] = {}
        for signal in sorted(signals, key=lambda s: (s.chain, s.deployment_address, s.selector, s.claim_id)):
            role = {"timelock.schedule": "schedule", "timelock.execute": "execute"}.get(signal.claim_id)
            if role is None:
                continue
            timelock_key = entity_key(signal.chain, signal.deployment_address)
            for ref in signal.principal_refs:
                facts = self._facts.get(int(ref.function_principal_id))
                if facts is None or facts.resolved_type != "safe" or not facts.owners:
                    continue
                by_role[timelock_key][role].add(facts.key)
                facts_by_key[facts.key] = facts

        out: dict[str, dict[str, Any]] = {}
        for timelock_key in sorted(by_role):
            both = sorted(by_role[timelock_key]["schedule"] & by_role[timelock_key]["execute"])
            best: dict[str, Any] | None = None
            for safe_key in both:
                facts = facts_by_key[safe_key]
                # inv.5 is the WEAKEST path. An unread threshold cannot lose that
                # comparison: it sorts first, and is then priced at the uncredited
                # rung rather than at a ratio nobody measured.
                rank = (0, 0.0) if facts.threshold is None else (1, facts.threshold / len(facts.owners))
                candidate = {
                    "key": safe_key,
                    "k": facts.threshold,
                    "n": len(facts.owners),
                    "rank": rank,
                }
                if best is None or candidate["rank"] < best["rank"]:
                    best = candidate
            if best is not None:
                out[timelock_key] = best
        return out

    def unit_for(self, facts: P.PrincipalFacts) -> str:
        key = facts.key
        if facts.resolved_type == "timelock":
            proposer = self._proposers.get(key)
            if proposer:
                key = str(proposer["key"])
        if key in self._parent:
            # The unit is named by its LOWEST member key, not by whichever root
            # the union order happened to leave: a union-find root is an
            # implementation artefact, and naming a unit with one would make the
            # same set of Safes carry different identities across runs.
            root = self._find(key)
            members = {member for member in self._parent if self._find(member) == root}
            unit = min(members)
            self._members[unit] |= members
            return unit
        self._members[key].add(key)
        return key

    def published_units(self) -> dict[str, Any]:
        """The unit memberships this fold folded, as the document's own evidence.

        A unit id is only meaningful beside the members it collapsed: without
        them a consumer cannot tell a re-labelled unit from a re-keyed one, and
        cannot check the inv.13 collapse that removed a double charge.
        """
        return {
            "members": {unit: sorted(members) for unit, members in sorted(self._members.items())},
            "timelock_collapses": {
                timelock: {
                    "into": entry["key"],
                    "proposer_k_of_n": (f"{entry['k']}/{entry['n']}" if entry["k"] is not None else "not_determined"),
                    "basis": "proven proposer AND executor",
                }
                for timelock, entry in sorted(self._proposers.items())
            },
            "owner_set_contradictions": self.owner_set_contradictions,
        }

    def proposer_for(self, facts: P.PrincipalFacts) -> dict[str, Any] | None:
        return self._proposers.get(facts.key)

    def path_for(self, facts: P.PrincipalFacts) -> str:
        """How this principal reaches the unit's capability: directly, or via a delay."""
        if facts.resolved_type == "timelock" and facts.key in self._proposers:
            return f"via_timelock:{facts.key}"
        return "direct"

    def weakness_for(
        self, facts: P.PrincipalFacts, *, recovery_proven_independent: bool = False
    ) -> tuple[float | None, str, str, list[str]]:
        notes: list[str] = []
        if facts.resolver_bases:
            weak = [b for b in facts.resolver_bases if K.resolver_basis_tier(b) == K.WEAKEST_RESOLVER_BASIS_TIER]
            if weak:
                notes.append("resolver_basis_convention:" + ",".join(sorted(weak)))

        if facts.resolved_type == "eoa":
            weakness, label, kind = K.WEAKNESS_EOA, "EOA", "eoa"
        elif facts.resolved_type == "safe":
            weakness, label, notes = _safe_weakness(facts, notes, recovery_proven_independent)
            kind = "safe"
        elif facts.resolved_type == "timelock":
            weakness, label, notes = self._timelock_weakness(facts, notes)
            kind = "timelock"
        elif facts.resolved_type == "contract":
            # "An EOA controls the gating CONTRACT" is not "an EOA can call this
            # function": the gating contract may impose its own conditions. The
            # hop is a confidence fact, never this row's weakness.
            return None, "contract", "contract", notes
        else:
            return None, facts.resolved_type or "unresolved", "unknown", notes

        raised = self._role_breadth(facts)
        if raised is not None and raised > weakness:
            notes.append(f"role_holder_floor_raises_breadth:{raised}")
            weakness = raised
        return weakness, label, kind, notes

    def _timelock_weakness(self, facts: P.PrincipalFacts, notes: list[str]) -> tuple[float, str, list[str]]:
        discount = K.delay_discount(facts.delay_seconds)
        proposer = self.proposer_for(facts)
        if discount is None:
            notes.append("timelock_delay_not_determined")
            return K.WEAKNESS_TIMELOCK_UNDETERMINED, "timelock(delay not_determined)", notes
        # Reached only where the discount resolved, which requires a read delay.
        delay_seconds = float(facts.delay_seconds) if facts.delay_seconds is not None else 0.0
        days = int(delay_seconds // 86400)
        if delay_seconds == 0:
            # A proven ZERO delay is proven-absent protection, not an unread one.
            # It earns no discount and does not land on the undetermined rung.
            notes.append("timelock_delay_proven_zero:no_protection")
            if proposer is None:
                return K.WEAKNESS_SAFE_UNCREDITED, "timelock(0d, proposer not_determined)", notes
            base = K.quorum_weakness(proposer["k"], proposer["n"], credit_withheld=False)
            notes.append(f"proposer={_kn(proposer)}")
            return base, f"timelock 0d via {_kn(proposer)}", notes
        if proposer is None:
            # A proven delay whose proposer-executor set is undetermined is not
            # proven protection, so the delay earns no discount.
            notes.append("timelock_proposer_not_determined:no_delay_credit")
            return K.WEAKNESS_TIMELOCK_UNDETERMINED, f"timelock {days}d(proposer not_determined)", notes
        base = K.quorum_weakness(proposer["k"], proposer["n"], credit_withheld=False)
        notes.append(f"delay_discount={discount};proposer={_kn(proposer)}")
        return round(base * discount, 4), f"timelock {days}d via {_kn(proposer)}", notes

    def _role_breadth(self, facts: P.PrincipalFacts) -> float | None:
        """A proven holder floor above one is proven BREADTH. It may only raise."""
        for registry, role_hash in facts.role_bindings:
            entry = self._role_floors.get((facts.chain, registry, role_hash))
            if entry and entry["holders_floor"] > 1:
                return K.ROLE_BREADTH_MULTI_HOLDER_WEAKNESS
        return None


def _kn(proposer: dict[str, Any]) -> str:
    """A proposer's k/n, or the honest refusal. Never a fabricated ratio."""
    return f"{proposer['k']}/{proposer['n']}" if proposer["k"] is not None else "k not_determined"


def _safe_weakness(
    facts: P.PrincipalFacts, notes: list[str], recovery_proven_independent: bool
) -> tuple[float, str, list[str]]:
    """A Safe's weakness from its PROVEN k and n, or the uncredited rung.

    An unread owner set is not an n. Backfilling n from k publishes a k-of-k Safe
    — the strongest rung on the ladder — out of a witness that never existed, and
    prints the fabricated ratio as the finding's own principal.
    """
    if not facts.owners:
        notes.append("safe_owner_set_not_determined:kn_uncomputable")
        label = "Safe (owners not_determined)" if facts.threshold is None else f"Safe k={facts.threshold}/n?"
        return K.WEAKNESS_SAFE_UNCREDITED, label, notes
    n = len(facts.owners)
    weakness = K.quorum_weakness(
        facts.threshold,
        n,
        credit_withheld=facts.protection_credit_withheld,
        waive_single_signer_cliff=recovery_proven_independent,
    )
    if facts.protection_credit_withheld:
        notes.append(f"safe_kn_credit_withheld:{facts.protection_basis}")
    label = f"Safe {facts.threshold}/{n}" if facts.threshold is not None else f"Safe k?/{n}"
    return weakness, label, notes


def _recovery_refs(signals: list[FunctionSignal]) -> list[Any]:
    """Principal references named by pause recovery gates, so the fold can read them."""

    @dataclass(frozen=True)
    class _Ref:
        function_principal_id: int
        chain: str
        address: str

    out: list[Any] = []
    for signal in signals:
        # Runs before the per-signal gate check in the main loop, so it repeats
        # it: a malformed payload must not be walked HERE either.
        if signal.claim_id != "pause.set" or _malformed_gates(signal):
            continue
        gate = _gate(signal, "freeze_recovery_principals")
        if not gate.is_determined or not isinstance(gate.value, list):
            continue
        for entry in gate.value:
            if _is_principal_ref(entry):
                out.append(
                    _Ref(
                        function_principal_id=int(entry["function_principal_id"]),
                        # The gate's entries are minted beside the pause signal on
                        # the same contract, so the chain is the same fact, not a
                        # substitute for an unread one. A JSONB null falls back to
                        # that same fact rather than stringifying to "None".
                        chain=str(entry.get("chain") or signal.chain),
                        address=str(entry.get("address") or ""),
                    )
                )
    return out


# ---------------------------------------------------------------- severity


def _fold_severity(
    signal: FunctionSignal,
    principal: P.PrincipalFacts | None,
    principal_facts: dict[int, P.PrincipalFacts],
    warnings: list[dict[str, Any]],
) -> tuple[float, tuple[str, ...], set[str]]:
    """The distilled severity, plus the components only the fold can prove.

    Per PRINCIPAL, not per function: whether a freeze is recoverable is a
    property of the freezing key set against the recovery key set, so evaluating
    it once over the union of a function's principals would charge a key set for
    an overlap another principal contributed.
    """
    severity = signal.severity.require(SEVERITY_STATE_PROVEN)
    basis = tuple(signal.severity_basis)
    notes: set[str] = set()
    if signal.claim_id != "pause.set" or principal is None:
        return severity, basis, notes

    verdict, coalition, note = _keyset_independence(signal, principal, principal_facts)
    if verdict is False:
        # PROVEN: this key set can freeze and also deny the recovery quorum.
        severity = max(severity, K.FREEZE_SUSTAINABLE)
        basis = basis + ("freeze_keyset_not_independent",)
        warnings.append(
            _warning(
                "freeze_keyset_not_independent",
                signal,
                "this key set can freeze AND deny the recovery quorum",
                min_coalition_to_sustain=coalition,
            )
        )
    elif verdict is None:
        # Every undetermined arm — no recovery claim, an unresolved recovery
        # principal, an unread freezing key set — leaves the rung where the
        # capability's proven existence put it. Raising here would move severity
        # on an absent witness; lowering would credit one. The question itself is
        # published instead.
        notes.add(note)
        basis = basis + ("freeze_recovery_independence_not_determined",)
        warnings.append(_warning("freeze_recovery_independence_not_determined", signal, note))
    else:
        # PROVEN independence: the credited rung, which equals the existence rung
        # today, so what changes is the basis rather than the number.
        severity = min(severity, K.FREEZE_KEYSET_RECOVERABLE)
        notes.add(note)
        basis = basis + ("freeze_keyset_independent",)
    return severity, basis, notes


def _keyset_independence(
    signal: FunctionSignal, principal: P.PrincipalFacts, principal_facts: dict[int, P.PrincipalFacts]
) -> tuple[bool | None, int | None, str]:
    """Is the recovery quorum independent of the freezing one, in KEYS?

    Independence is a property of owner key sets: P and U are independent iff
    ``|owners(U) \\ owners(P)| >= threshold(U)``. Comparing principal ADDRESSES
    publishes a protective credit for a configuration where a handful of keys
    freeze the protocol and hold it — and an address stands in for a key set only
    where the principal IS a single key, i.e. an EOA. For every other type an
    unread owner set makes the test uncomputable, not favourable.
    """
    if principal.owners:
        pauser_owners = principal.owners
    elif principal.resolved_type == "eoa":
        pauser_owners = frozenset({principal.address})
    else:
        return None, None, "pauser_key_set_not_determined"

    gate = _gate(signal, "freeze_recovery_principals")
    if not gate.is_determined or not isinstance(gate.value, list):
        return None, None, "recovery_path_not_determined_no_unset_claim"
    saw_safe = False
    best: int | None = None
    for entry in sorted((e for e in gate.value if _is_principal_ref(e)), key=lambda e: str(e.get("address"))):
        facts = principal_facts.get(int(entry["function_principal_id"]))
        if facts is None or facts.resolved_type != "safe" or not facts.owners or facts.threshold is None:
            continue
        saw_safe = True
        residual = len(facts.owners - pauser_owners)
        if residual >= facts.threshold:
            return True, None, f"keyset_independent:{residual}>={facts.threshold}"
        block = max(1, len(facts.owners) - facts.threshold + 1)
        best = block if best is None else min(best, block)
    if saw_safe:
        return False, best, "keyset_dependent"
    return None, None, "recovery_principal_unresolved"


# ---------------------------------------------------------------- value fold


def _instance(
    signal: FunctionSignal, severity: float, basis: tuple[str, ...], principal_address: str = ""
) -> _Instance:
    magnitude = _gate(signal, "reach_magnitude_usd")
    pricing_blocked = None
    native_only = False
    asset_identity_undecidable = False
    if signal.claim_id == "flow.out":
        if _gate(signal, "token_identity").is_determined:
            # Exactly one NON-FUNGIBLE token moves: pricing the row off a
            # fungible balance sheet is forbidden, not merely imprecise.
            pricing_blocked = "token_identity(non-fungible; pricing forbidden)"
        asset_class = _gate(signal, "asset_class")
        native_only = asset_class.is_determined and asset_class.value == "native_only"
        # The W2 pricing precondition: single-asset pricing is licensed only by a
        # decidable token identity. Undecidable ⇒ the unpriced branch, never the
        # entity's whole fungible sheet read as this call's magnitude.
        asset_identity_undecidable = (
            asset_class.is_determined
            and asset_class.value in SINGLE_ASSET_CLASSES
            and not _gate(signal, "asset_identity").is_determined
        )
    return _Instance(
        signal=signal,
        severity=severity,
        severity_basis=basis,
        entity_keys=signal.value_entity_keys,
        magnitude=magnitude,
        value_bound=signal.value_bound,
        pricing_blocked=pricing_blocked,
        native_only=native_only,
        asset_identity_undecidable=asset_identity_undecidable,
        principal_address=principal_address,
    )


def _attach(row: _Row, signal: FunctionSignal, instance: _Instance, notes: set[str]) -> None:
    # The burn sentinel is refused as a REACH key here, one admission short of the
    # walk: ``msg.sender != 0x0``, so nothing routes value through it and a
    # repoint witness that names it has proved no reach. The confidence perimeter
    # refuses it on the same rule; this is the value side of that discipline.
    kept = tuple(key for key in instance.entity_keys if not P.is_zero_key(key))
    if len(kept) != len(instance.entity_keys):
        row.zero_reach_keys_refused += len(instance.entity_keys) - len(kept)
        row.notes.add("zero_address_reach_key_refused")
        if not kept:
            # Every reach key this instance carried was the sentinel, so it now
            # witnesses nothing. Dropping it silently would read as "this call
            # reaches no priced entity" — an earned negative it never earned.
            row.zero_reach_stripped.append(
                {
                    "function": signal.function_name,
                    "entity": entity_key(signal.chain, signal.deployment_address),
                    "why": "every_reach_key_was_the_zero_address(refused; reach not_determined)",
                }
            )
        instance.entity_keys = kept
    row.instances.append(instance)
    row.seeds.add(entity_key(signal.chain, signal.deployment_address))
    row.tiers.add(signal.witness_tier)
    row.notes.update(signal.witness_notes)
    row.notes.update(notes)
    row.citations.extend(signal.citations)


def _member_weakness(
    row: _Row, per_entity: dict[str, float], value_plane: P.ValuePlane, closure: P.ControlClosure
) -> tuple[dict[str, float], float, tuple[str, str, str]]:
    """A merged unit's weakness, per REACHED ENTITY (inv. 5).

    ``_row_for`` keeps the max weakness over a merged Safe unit's members while
    the row folds the UNION of their reach, with no tie between a member's rung
    and the entities that member reaches — so value only the 4/8 member can move
    is published at the 3/7 member's rung, a coalition nobody proved.

    inv. 5's weakest path is the weakest path TO THAT ENTITY: entity ``e`` is
    priced at the max over ONLY the members proven to reach ``e``. The row still
    publishes a single weakness against a union no single member reaches, so that
    union is priced at **the hardest rung among the contributing members** — the
    ``min`` over the per-entity rungs. That is NOT the overlap record's
    ``min_coalition_to_act_as_both``: that field is ``max(k)``, and weakness is
    keyed on ``k/n``, so a 3/4 member (0.20) and a 5/20 member (0.55) put the
    coalition size on the 5/20 Safe while this rung is the 3/4's 0.20. The
    hardest rung is the deliberate under-claim — inv. 5 forbids pricing a union
    at a rung no contributing member has to clear. Naming a member's reach needs
    the member's own witness, so a row whose instances cannot be attributed to a
    member keeps the unit-level rung rather than inventing an attribution.
    """
    unchanged = ({}, row.weakness, (row.weakest_label, row.principal_kind, row.weakest_address))
    if len(row.member_gate) < 2 or not per_entity:
        return unchanged
    by_member: dict[str, list[_Instance]] = defaultdict(list)
    for instance in row.instances:
        if instance.principal_address not in row.member_gate:
            return unchanged
        by_member[instance.principal_address].append(instance)

    reach_by_member: dict[str, set[str]] = {}
    for address, instances in by_member.items():
        probe = _Row(unit=row.unit, capability=row.capability, path=row.path)
        probe.instances = instances
        # Reach is MEMBERSHIP, so it is read off ``.reach`` and never off the
        # value map: W2b's per-call magnitude cap scales what a member is charged
        # and can empty ``per_entity`` outright, but it moves no entity out of
        # what the member provably reaches.
        reached = _row_value(probe, value_plane, closure).reach
        reach_by_member[address] = reached

    weakness_by_entity: dict[str, float] = {}
    holders_by_entity: dict[str, list[str]] = {}
    for key in sorted(per_entity):
        holders = sorted(a for a, reached in reach_by_member.items() if key in reached)
        if not holders:
            # The union carries an entity no single member's fold reproduces.
            # That is an attribution this function cannot witness, so the row
            # keeps the unit rung rather than pricing it at a guess.
            return unchanged
        holders_by_entity[key] = holders
        weakness_by_entity[key] = max(row.member_gate[a][0] for a in holders)

    if len({*weakness_by_entity.values(), row.weakness}) == 1:
        return unchanged
    binding_key = min(weakness_by_entity, key=lambda k: (weakness_by_entity[k], k))
    published = weakness_by_entity[binding_key]
    binding = max(holders_by_entity[binding_key], key=lambda a: (row.member_gate[a][0], a))
    _, label, kind = row.member_gate[binding]
    return weakness_by_entity, published, (label, kind, binding)


def _aggregate(
    rows_by_key: dict[tuple[str, str, str], _Row],
    value_plane: P.ValuePlane,
    closure: P.ControlClosure,
    units: _UnitResolver,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    warnings: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for key in sorted(rows_by_key):
        row = rows_by_key[key]
        if not row.instances:
            continue
        valued = _row_value(row, value_plane, closure)
        per_entity, value_usd, undetermined = valued.per_entity, valued.total_usd, valued.undetermined
        value_basis = valued.basis
        if row.zero_reach_stripped:
            undetermined = undetermined + row.zero_reach_stripped
            value_basis += f"; {len(row.zero_reach_stripped)} instance(s) reached only the refused zero address"
        # A priced total over an entity that also holds assets the priced sheet
        # never covered is a FLOOR over that entity, not its value: an instance
        # that answered is not the same fact as an entity that was answered.
        partially_priced = _partially_priced_entities(value_plane, valued.reach)
        is_floor = bool(value_usd is not None and (undetermined or partially_priced))
        weakness_by_entity, weakness, weakest = _member_weakness(row, per_entity, value_plane, closure)
        severity = max(instance.severity for instance in row.instances)
        band = K.band(value_usd)
        if value_usd is None or value_usd < 100_000:
            warnings.append(
                {
                    "kind": "value_at_stake_at_band_floor",
                    "unit": row.unit,
                    "capability": row.capability,
                    "note": (
                        "the weight sits at the band floor because the value this "
                        "capability is proven to reach is undetermined or below it. "
                        "This is not a claim that the entities hold nothing: position "
                        "and unpriced value are absent from the priced sheet, and this "
                        "is the one direction in which the model under-scores"
                    ),
                    "missing_witness": "priced value for the reached entities",
                }
            )
        rows.append(
            {
                "principal_unit": row.unit,
                "unit_members": sorted(units.published_units()["members"].get(row.unit, [row.unit])),
                # The published principal IS the one that set the weakness, not
                # whichever row was folded last.
                "principal": f"{weakest[0]} {weakest[2]}",
                "access_path": row.path,
                "principal_addresses": sorted(row.principal_addresses),
                "principal_kind": weakest[1],
                "capability": row.capability,
                "chain": row.unit.split("::", 1)[0],
                "value_at_stake_usd": (round(value_usd, 2) if value_usd is not None else None),
                "value_state": (VALUE_STATE_PROVEN_REACH if value_usd is not None else NOT_DETERMINED),
                "value_by_entity": {k: round(v, 2) for k, v in sorted(per_entity.items())},
                "value_at_stake_basis": value_basis,
                "value_at_stake_is_floor": is_floor,
                # The entities behind the floor flag, named rather than left to
                # be inferred from the flag alone.
                "entities_holding_unpriced_assets": partially_priced,
                "value_band": (
                    ((">= " + K.band_label(value_usd)) if is_floor else K.band_label(value_usd))
                    if value_usd is not None
                    else NOT_DETERMINED
                ),
                "undetermined_instances": undetermined,
                "proven_no_reach_instances": valued.proven_no_reach,
                "witnessed_magnitude_caps": valued.magnitude_caps,
                "zero_address_reach_keys_refused": row.zero_reach_keys_refused,
                # Filled in after the sort, which is where a tie can be seen.
                # Present on every row: null is the proven "nothing tied".
                "exposure_order_tie": None,
                "severity_proven": round(severity, 4),
                "severity_basis": sorted({b for instance in row.instances for b in instance.severity_basis}),
                "weakness": round(weakness, 4),
                "weakest_gate": weakest[0],
                # inv.5 read as the weakest path TO AN ENTITY: present only where a
                # merged unit's members reach different entities at different rungs,
                # and then the union is priced at the hardest rung among the
                # contributing members. Absent means one rung priced the whole union.
                "weakness_by_entity": {k: round(v, 4) for k, v in sorted(weakness_by_entity.items())},
                "raw_points": round(K.SEV_SCALE * severity * weakness * band, 4),
                "n_functions": len({(i.signal.deployment_address, i.signal.selector) for i in row.instances}),
                "n_entities": len(row.seeds),
                # The deployment entities the row's instances were witnessed ON
                # — the direct targets — as distinct from reach_entities, the
                # closure the capability reaches through control edges. That
                # closure is MEMBERSHIP and is not filtered by pricing: the
                # entities in it whose dollars are undetermined are named in
                # the row's exposure gap, not dropped from the fact that this
                # capability reaches them.
                "host_entities": sorted(row.seeds),
                "reach_entities": sorted(valued.reach),
                "example_functions": sorted({i.signal.function_name for i in row.instances})[:6],
                "witness_tiers": sorted(row.tiers),
                "witness_notes": sorted(row.notes),
                "citations": row.citations[:8],
                "counterfactual": _counterfactual(weakest[1]),
            }
        )

    by_unit: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_unit[row["principal_unit"]].append(row)
    findings: list[dict[str, Any]] = []
    subsumed: list[dict[str, Any]] = []
    for unit in sorted(by_unit):
        ordered = sorted(
            by_unit[unit], key=lambda r: (-r["raw_points"], r["capability"], r["access_path"], r["weakness"])
        )
        top = dict(ordered[0])
        rest = ordered[1:]
        top["subsumed_capabilities"] = [
            {
                "capability": r["capability"],
                "access_path": r["access_path"],
                "weakness": r["weakness"],
                "raw_points": r["raw_points"],
                "value_at_stake_usd": r["value_at_stake_usd"],
                "n_entities": r["n_entities"],
            }
            for r in rest
        ]
        top["subsumed_raw_points"] = round(sum(r["raw_points"] for r in rest), 4)
        # Subsumption removes a row's POINTS, never the unit's reach. Value that
        # only a subsumed row names is still value this unit provably reaches, and
        # dropping it from the exposure accounting would publish a smaller
        # exposure for a unit that got no smaller.
        #
        # The contributing row's OWN fraction travels with the value. The top row
        # is a different access path — often an undelayed one — and charging the
        # delayed row's value at the undelayed fraction would re-merge in the
        # exposure term exactly what keying rows by access path separated.
        exclusive: dict[str, dict[str, float]] = {}
        for row in rest:
            per_entity_weakness = row["weakness_by_entity"]
            for key, held in row["value_by_entity"].items():
                if key in top["value_by_entity"]:
                    continue
                fraction = row["severity_proven"] * per_entity_weakness.get(key, row["weakness"])
                previous = exclusive.get(key)
                if previous is None or held * fraction > previous["usd"] * previous["fraction"]:
                    exclusive[key] = {"usd": held, "fraction": round(fraction, 6)}
        top["subsumed_exclusive_value_by_entity"] = dict(sorted(exclusive.items()))
        if rest:
            top["counterfactual"] += (
                "; this row subsumes " + ", ".join(r["capability"] for r in rest) + " — fixing the top "
                "capability alone does not release them"
            )
        findings.append(top)
        subsumed.extend(rest)
    findings.sort(key=lambda r: (-r["raw_points"], r["capability"], r["principal_unit"]))
    subsumed.sort(key=lambda r: (-r["raw_points"], r["capability"], r["principal_unit"]))
    _disclose_order_ties(findings)
    return findings, subsumed, warnings


def _disclose_order_ties(findings: list[dict[str, Any]]) -> None:
    """Where rows tie on the sort key, say so: the order decides, and it is a string.

    Two rows with equal points and capability are separated by the unit address
    alone, and that order is spent twice — on the λ position, which discounts by
    index, and on the exposure budget, which the earlier row consumes first and
    the later row gets the remainder of. Splitting the shared entity correctly
    needs evidence this fold does not have, so the order stays fixed (inv. 8) and
    what it decided is published instead of read as an attribution.

    Findings only. A subsumed row has no λ position and spends no exposure
    budget — the order decides nothing for it — so its ``exposure_order_tie``
    stays ``None``, which here is the proven "nothing was decided by order",
    not an unasked question.
    """
    groups: dict[tuple[Any, Any], list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        groups[(finding["raw_points"], finding["capability"])].append(finding)
    for group in groups.values():
        if len(group) < 2:
            continue
        units = [f["principal_unit"] for f in group]
        for position, finding in enumerate(group):
            others = {key for other in group if other is not finding for key in other["value_by_entity"]}
            finding["exposure_order_tie"] = {
                "tied_with": [unit for unit in units if unit != finding["principal_unit"]],
                "shared_entities": sorted(set(finding["value_by_entity"]) & others),
                "position_in_tie": position,
                "basis": "equal raw_points and capability; the remaining order is the principal_unit string",
                "reading": (
                    "this row's λ position and its share of any entity it holds in common with "
                    "the tied rows are decided by that string, not by evidence; the split among "
                    "them is order-determined and is not a measurement of who reaches what"
                ),
            }


# Every published dollar is rounded to the cent, so a share below half a cent
# reaches a consumer as $0.00 whatever it really was.
_PUBLISHED_CENT = 0.005

_UNPRICED_ASSET_STATES = frozenset({P.ASSET_UNPRICED, P.ASSET_BELOW_RESOLUTION})


def _partially_priced_entities(value_plane: P.ValuePlane, keys: set[str]) -> list[str]:
    """Reached entities whose priced sheet does not cover everything they hold.

    Whole-entity unpricedness already lands in ``undetermined_instances``; this
    is the case one level in, where the entity IS priced but only partly — ten
    priced rows beside a hundred unpriced ones answer ten questions, and a total
    over them is a floor, not the entity's value.

    Two sources, ORed, and the per-ASSET map is read rather than the sheet
    state: the sheet state collapses a mixed entity to whichever fact ranks
    highest, so an entity with one priced asset and a hundred unanswered ones
    reads as ``priced`` there and the shortfall disappears. ``below_resolution``
    counts as unpriced here — an asset whose price landed on the storage floor
    is a holding of at most half a cent that the total does not carry, which is
    the same shortfall as one nobody priced. The restaking plane is the second
    source: it has no USD column at all, so a position there is unpriced by
    construction.
    """
    partial: set[str] = set()
    for key in keys:
        canonical = value_plane.canonical(key)
        if value_plane.total(canonical) is None:
            # Nothing determined at all: an undetermined entity, not a floor.
            continue
        states = value_plane.per_asset_state.get(canonical) or {}
        if any(state in _UNPRICED_ASSET_STATES for state in states.values()):
            partial.add(canonical)
        elif value_plane.unpriced_positions.get(canonical):
            partial.add(canonical)
    return sorted(partial)


def _row_value(row: _Row, value_plane: P.ValuePlane, closure: P.ControlClosure) -> _RowValue:
    """Value at stake for one row: MAX per entity, never SUM.

    Two functions reaching the same vault charge it once, and a witnessed
    magnitude caps what the row may charge against an entity — the entity's whole
    balance sheet is not what a bounded call can move. The magnitude is also one
    number for the whole CALL, so it caps that call's sum across the keys it
    reached rather than being re-charged at each of them.
    """
    per_entity: dict[str, float] = {}
    reached: set[str] = set()
    undetermined: list[dict[str, Any]] = []
    proven_no_reach: list[dict[str, Any]] = []
    magnitude_caps: list[dict[str, Any]] = []
    transitive = row.capability in K.TRANSITIVE_CAPABILITIES

    for instance in sorted(row.instances, key=lambda i: (i.signal.deployment_address, i.signal.function_name)):
        entity = entity_key(instance.signal.chain, instance.signal.deployment_address)
        if instance.pricing_blocked:
            undetermined.append(
                {"function": instance.signal.function_name, "entity": entity, "why": instance.pricing_blocked}
            )
            continue
        if instance.asset_identity_undecidable and not instance.magnitude.is_determined:
            undetermined.append(
                {
                    "function": instance.signal.function_name,
                    "entity": entity,
                    "why": "token_identity_not_decidable(unpriced branch)",
                }
            )
            continue
        if instance.signal.value_state == VALUE_STATE_PROVEN_NO_REACH:
            # An EARNED negative, not a gap: reach was witnessed and reached
            # nothing. Counting it among the undetermined instances would make a
            # proven fact read as a missing one.
            proven_no_reach.append(
                {"function": instance.signal.function_name, "entity": entity, "basis": instance.signal.value_basis}
            )
            continue
        if instance.signal.value_state != VALUE_STATE_PROVEN_REACH:
            # The transitive closure is a REACH, not a licence: a signal whose own
            # reach was never witnessed contributes no seed, however much value
            # its deployment's neighbours hold.
            undetermined.append(
                {"function": instance.signal.function_name, "entity": entity, "why": instance.signal.value_basis}
            )
            continue

        keys = set(instance.entity_keys)
        if transitive:
            keys = _closure(keys, closure)
        # Reach is MEMBERSHIP, and it is witnessed here. It may not be read off
        # the value map: an entity drops out of that map whenever its dollars
        # are not_determined — an unpriced sheet today, a refused magnitude once
        # the magnitude discipline lands — and deleting a proven fact because an
        # unproven one is missing is the whole error this fold is being repaired
        # for. Priced or not, the row reaches these entities.
        reached.update(value_plane.canonical(key) for key in keys)
        contributions, gaps, cap = _instance_contributions(instance, keys, value_plane, transitive=transitive)
        undetermined.extend(gaps)
        if cap is not None:
            magnitude_caps.append(cap)
        for canonical, contribution in contributions.items():
            previous = per_entity.get(canonical)
            if previous is None or contribution > previous:
                per_entity[canonical] = contribution

    if not per_entity:
        basis = "proven_no_reach" if proven_no_reach and not undetermined else "not_determined"
        return _RowValue(per_entity, None, basis, undetermined, proven_no_reach, reached, magnitude_caps)
    basis = (
        "transitive control closure, MAX per entity over latest-observation sheets"
        if transitive
        else "per-instance witnessed value, MAX per entity over latest-observation sheets"
    )
    if undetermined:
        basis = f">= proven floor over {len(per_entity)} entity(ies); {len(undetermined)} instance(s) not_determined"
    if proven_no_reach:
        basis += f"; {len(proven_no_reach)} instance(s) proven_no_reach"
    total = round(sum(sorted(per_entity.values())), 6)
    return _RowValue(per_entity, total, basis, undetermined, proven_no_reach, reached, magnitude_caps)


def _instance_contributions(
    instance: _Instance, keys: set[str], value_plane: P.ValuePlane, *, transitive: bool
) -> tuple[dict[str, float], list[dict[str, Any]], dict[str, Any] | None]:
    """One call's per-entity contributions, bounded by the one magnitude it proved.

    A witnessed magnitude is a per-CALL quantity: ``withdraw`` proven to move
    $28.1M moves $28.1M whichever of the keys it reached holds it. Charging it
    once per key multiplies a single proven number by the size of the reach set,
    which is the balance-sheet-as-a-reach error one level up from the one
    :func:`_entity_contribution` already refuses.

    An ``exact`` witness bounds the whole call, so its keys consume it as a
    budget: the trim falls on whichever key the deterministic order reaches
    last, an arbitrary basis that is published rather than absorbed. A key left
    with no room is ``not_determined``, never a published ``$0.00`` — an
    exhausted budget is not a measurement that the entity holds nothing.

    A ``floor`` witness bounds nothing above: it proves the call moves *at
    least* that much and says nothing about how the amount divides between two
    holders, so over more than one key the call's magnitude is
    ``not_determined`` rather than the floor charged once per key. At one key
    both rules leave the witness exactly as proven.
    """
    per_key: dict[str, float] = {}
    gaps: list[dict[str, Any]] = []
    for key in sorted(keys):
        contribution, why = _entity_contribution(instance, key, value_plane, transitive=transitive)
        if contribution is None:
            # The RAW key the walk reached, not its canonical fold — pre-existing
            # and kept, because this row names where the walk landed and folding
            # it would report a proxy the closure never visited. The keys this
            # unit adds below are canonical, matching ``value_by_entity``.
            gaps.append({"function": instance.signal.function_name, "entity": key, "why": why})
            continue
        # An implementation and the proxy that deploys it are ONE priced entity:
        # the plane already folded the balance onto the proxy, so a row reaching
        # both keys would charge that one balance twice — once in this sum and
        # again in the exposure budget, which is keyed on these same entities.
        canonical = value_plane.canonical(key)
        previous = per_key.get(canonical)
        if previous is None or contribution > previous:
            per_key[canonical] = contribution

    magnitude = _witnessed_magnitude(instance)
    if magnitude is None or len(per_key) < 2:
        return per_key, gaps, None

    uncapped = round(sum(sorted(per_key.values())), 6)
    if instance.magnitude.state != "proven_exact":
        for key in sorted(per_key):
            gaps.append(
                {
                    "function": instance.signal.function_name,
                    "entity": key,
                    "why": "floor_magnitude_over_multiple_keys_without_apportionment_witness(not_determined)",
                }
            )
        return (
            {},
            gaps,
            {
                "function": instance.signal.function_name,
                "capability": instance.signal.claim_id,
                "witness_state": instance.magnitude.state,
                "witnessed_usd": magnitude,
                "entities": sorted(per_key),
                "uncapped_sum_usd": uncapped,
                "published_sum_usd": None,
                "reading": (
                    "a floor proves the call moves at least this much, never how it divides "
                    "between holders; with no apportionment witness the magnitude of this call "
                    "is not_determined rather than the floor charged once per entity"
                ),
            },
        )
    if uncapped <= magnitude:
        return per_key, gaps, None

    capped: dict[str, float] = {}
    exhausted: list[str] = []
    remaining = magnitude
    for key in sorted(per_key):
        take = round(min(per_key[key], remaining), 6)
        remaining = round(remaining - take, 6)
        # A residual under half a cent publishes as $0.00 at the row's rounding,
        # which is the phantom proven-zero this branch exists to refuse — the
        # threshold is the published resolution, not exact equality with zero.
        if take < _PUBLISHED_CENT:
            exhausted.append(key)
            gaps.append(
                {
                    "function": instance.signal.function_name,
                    "entity": key,
                    "why": "call_magnitude_consumed_by_earlier_keys(share_not_determined)",
                }
            )
            continue
        capped[key] = take
    return (
        capped,
        gaps,
        {
            "function": instance.signal.function_name,
            "capability": instance.signal.claim_id,
            "witness_state": instance.magnitude.state,
            "witnessed_usd": magnitude,
            "entities": sorted(per_key),
            "entities_left_not_determined": exhausted,
            "uncapped_sum_usd": uncapped,
            "published_sum_usd": round(sum(sorted(capped.values())), 6),
            "reading": (
                "the witness bounds one call, so its keys consume it as a budget; which key "
                "the trim falls on is decided by the deterministic key order, not by evidence, "
                "and no witness apportions this magnitude between the entities"
            ),
        },
    )


def _witnessed_magnitude(instance: _Instance) -> float | None:
    """The one dollar figure this call's witness proved, if it proved one."""
    raw = instance.magnitude.value
    if instance.magnitude.is_determined and _is_number(raw):
        return float(raw)  # type: ignore[arg-type]  # _is_number narrows it
    return None


def _entity_contribution(
    instance: _Instance, key: str, value_plane: P.ValuePlane, *, transitive: bool
) -> tuple[float | None, str]:
    if instance.native_only:
        # A provably native-only flow may only be valued against the native
        # holding, and an absent native row is not_determined, never $0.
        native = P.native_value_state(value_plane, key)
        if not native.is_determined:
            return None, "native_only_flow+absent_native_row(not_determined)"
        # Proven, and proven zero carries 0.0 — the pairing is enforced by Tri.
        held: float | None = float(native.value if native.value is not None else 0.0)
        basis = "native_only_flow x native_balance"
    else:
        held = value_plane.total(key)
        basis = "entity_holdings"

    magnitude = _witnessed_magnitude(instance)
    if magnitude is not None:
        if instance.magnitude.state == "proven_exact":
            # The witness bounds what this call moves; the entity's sheet bounds
            # what is there to move. Neither alone is the answer, and the sheet
            # alone is the balance-sheet-as-a-reach error.
            return (min(held, magnitude) if held is not None else magnitude), f"witnessed_reach(exact) x {basis}"
        return magnitude, "witnessed_reach(floor)"
    if held is None:
        return None, "entity_value_not_determined" if not transitive else "closure_entity_value_not_determined"
    return held, basis


def _closure(seeds: set[str], closure: P.ControlClosure) -> set[str]:
    """The reach the walk proves, with the burn sentinel refused at every hop.

    ``load_control_closure`` already refuses ``0x0`` at both ends of an edge, so
    on the production path this guard never fires. It is here because the fold's
    guarantee must not be a property of how the closure was BUILT: the sentinel
    is the single largest fan-out in the graph, and one edge into it — from a
    repoint witness, a hand-built closure, or a future loader — would otherwise
    hand a row everything behind ``msg.sender != 0x0``. Refusing reach is always
    monotone, so the second line of defence costs nothing.
    """
    seen: set[str] = set()
    stack = [key for key in sorted(seeds) if not P.is_zero_key(key)]
    while stack:
        key = stack.pop()
        if key in seen:
            continue
        seen.add(key)
        for edge in closure.edges_from(key):
            if edge.anchor not in seen and not P.is_zero_key(edge.anchor):
                stack.append(edge.anchor)
    return seen


def _gap_reading(exposure: float | None, unpriced: list[Any], exhausted: list[Any], partial: list[Any]) -> str:
    """How to read one gap entry, assembled from the reasons that actually fired.

    A null exposure and a published one are opposite cases and cannot share a
    sentence: the first measured nothing, the second measured a MARGINAL share
    and understates by an amount this accounting can name.
    """
    parts = [
        (
            "not counted and not read as zero; where the exposure is null nothing "
            "about this finding's dollar exposure was measured"
        )
        if exposure is None
        else (
            "the published figure is this row's MARGINAL share of what it reaches, so it is "
            "a floor on this finding's exposure and not a measurement of it"
        )
    ]
    if unpriced:
        parts.append(
            "the unpriced entities are absent from it rather than counted as zero, so nothing "
            "here says they hold nothing"
        )
    if exhausted:
        parts.append(
            "the entities under budget_exhausted_entities were charged in full by the findings "
            "listed against them, so this row's share of those entities is unmeasured, not zero"
        )
    if partial:
        parts.append(
            "the entities under budget_partially_exhausted_entities were charged at less than "
            "this row's own fraction, and the difference is missing from the figure"
        )
    return "; ".join(parts)


def _grade(
    findings: list[dict[str, Any]], value_plane: P.ValuePlane
) -> tuple[float | None, float | None, float | None, list[dict[str, Any]]]:
    if not findings:
        return None, None, None, []
    for index, finding in enumerate(findings):
        finding["net_points_lambda"] = round(finding["raw_points"] * (K.LAMBDA**index), 4)
    cumulative = round(sum(f["net_points_lambda"] for f in findings), 4)
    grade_lambda = round(100.0 - min(cumulative, 100.0), 4)

    claimed: dict[str, float] = defaultdict(float)
    # Which findings spent each entity's budget, so a later row that finds it
    # empty can name them instead of publishing the emptiness as a measurement.
    claimed_by: dict[str, list[dict[str, Any]]] = defaultdict(list)
    exposure = 0.0
    gaps: list[dict[str, Any]] = []
    any_priced = False
    for finding in findings:
        # W2c/R9 hook (this dict lookup is the whole change to this function):
        # inv.5 is the weakest path TO THAT ENTITY, so a merged unit charges each
        # entity at the rung of the members proven to reach it, not at the unit's
        # weakest member.
        per_entity_weakness = finding.get("weakness_by_entity") or {}
        mine = 0.0
        # Entities this row could actually measure a share of. An entity whose
        # budget earlier rows already spent is priced and still unmeasurable,
        # so counting it here is what published the exhaustion as a zero.
        measured_entities = 0
        exhausted: list[dict[str, Any]] = []
        partial: list[dict[str, Any]] = []
        unpriced: list[str] = []
        exclusive = finding.get("subsumed_exclusive_value_by_entity") or {}
        charged_entities = list(finding["reach_entities"]) + [
            k for k in exclusive if k not in finding["reach_entities"]
        ]
        for key in charged_entities:
            # The row's OWN per-entity contribution, not its total: charging the
            # row total against each entity would multiply one witnessed
            # magnitude by the number of entities it was spread across.
            held = finding["value_by_entity"].get(key)
            # An entity only a subsumed row reaches is charged at THAT row's
            # fraction, never at this one's.
            key_fraction = finding["severity_proven"] * per_entity_weakness.get(key, finding["weakness"])
            if held is None and key in exclusive:
                held = exclusive[key]["usd"]
                key_fraction = exclusive[key]["fraction"]
            if held is None:
                # An unpriced entity contributes nothing AND is disclosed. Reading
                # it as $0.00 publishes "this capability exposes nothing" out of a
                # price lookup that never answered.
                unpriced.append(key)
                continue
            room = max(0.0, 1.0 - claimed[key])
            if room <= 0.0:
                # Earlier findings spent this entity's whole budget. The
                # remainder is not a measured $0.00 — it is a share this
                # accounting cannot separate from theirs, so it is disclosed
                # with the rows that took it rather than summed as a zero.
                exhausted.append({"entity": key, "claimed_by": list(claimed_by[key])})
                continue
            measured_entities += 1
            take = min(key_fraction, room)
            if room < key_fraction:
                # A partial charge understates by exactly the difference, and it
                # does so silently: the published figure is this row's MARGINAL
                # share, not its exposure to the entity. Which row was marginal
                # is a function of the sort order, not of what anyone reaches.
                partial.append(
                    {
                        "entity": key,
                        "fraction_wanted": round(key_fraction, 6),
                        "fraction_taken": round(take, 6),
                        "claimed_by": list(claimed_by[key]),
                    }
                )
            if take > 0:
                claimed[key] += take
                claimed_by[key].append(
                    {
                        "principal_unit": finding["principal_unit"],
                        "capability": finding["capability"],
                        "fraction_taken": round(take, 6),
                    }
                )
                mine += take * held
        finding["exposure_entities_charged"] = sorted(
            key for key in charged_entities if finding["value_by_entity"].get(key) is not None or key in exclusive
        )
        if measured_entities:
            any_priced = True
            finding["exposure_usd"] = round(mine, 2)
        else:
            # Either no priced entity in reach, or every priced one's budget was
            # already spent: the exposure of this finding is a quantity nobody
            # measured, and null is the only honest answer.
            finding["exposure_usd"] = None
        if unpriced or exhausted or partial or finding["exposure_usd"] is None:
            # One gap per finding, never two: a row with an unpriced entity AND
            # a spent budget has one set of reasons, not one entry per reason.
            # Every key is present on every entry — an empty list is the proven
            # negative "this did not happen", which is not the same published
            # fact as a key that is missing.
            #
            # S5: repopulated from the row's own undetermined instances, which
            # is where an unpriced entity actually lands.
            unpriced_entities = sorted(set(unpriced) | {row["entity"] for row in finding["undetermined_instances"]})
            gaps.append(
                {
                    "principal_unit": finding["principal_unit"],
                    "capability": finding["capability"],
                    "unpriced_entities": unpriced_entities,
                    "undetermined_instances": finding["undetermined_instances"],
                    "budget_exhausted_entities": exhausted,
                    "budget_partially_exhausted_entities": partial,
                    "exposure_usd": finding["exposure_usd"],
                    "reading": _gap_reading(finding["exposure_usd"], unpriced_entities, exhausted, partial),
                }
            )
        # A finding whose exposure is not_determined contributes nothing to the
        # total and is disclosed in exposure_gaps; it is never summed as a zero.
        if finding["exposure_usd"] is not None:
            exposure += finding["exposure_usd"]

    tracked = value_plane.tracked_total
    if not tracked or not any_priced:
        return grade_lambda, None, round(exposure, 2), gaps
    return grade_lambda, round(100.0 * (1.0 - exposure / tracked), 3), round(exposure, 2), gaps


def _entities_outside_perimeter(
    signals: list[FunctionSignal],
    answered: dict[str, list[int]],
    perimeter: dict[str, float],
    value_plane: P.ValuePlane,
) -> list[str]:
    """Deployment AND reach keys the confidence denominator never asked about.

    A signal answers questions about the entity it was distilled on, and it
    charges value against the entities it REACHES. Checking only the first left
    a reach key that no denominator accounts for invisible to the disclosure
    that exists to name it — value carried into a finding by an entity whose
    unanswered weight is nowhere. The keys the closure walk ADDS to a reach are
    admitted to the perimeter by construction (every principal and everything it
    controls), so the witnessed keys are the ones that can fall outside. The zero
    address is refused by an admission rule with its own published count, so its
    absence is a decision rather than a gap and it is not reported here.
    """
    outside = {key for key in answered if key not in perimeter}
    for signal in signals:
        for raw in signal.value_entity_keys:
            key = value_plane.canonical(raw)
            if key not in perimeter and not P.is_zero_key(key):
                outside.add(key)
    return sorted(outside)


def _confidence(
    signals: list[FunctionSignal],
    value_plane: P.ValuePlane,
    closure: P.ControlClosure,
    proven_eoas: set[str],
    discovery_entities: dict[str, set[str]] | None = None,
) -> dict[str, Any]:
    """Monotone in resolution work: the denominator is the PERIMETER.

    The perimeter's base population is the protocol's ``contracts`` rows, unioned
    with the value plane and the control closure. Discovery fixes that base, so it
    does not move with what has been analysed — losing a contract's signals cannot
    drop its unanswered weight out of its own denominator — while an unpriced
    contract outside the closure still carries ``band(None)`` of unanswered
    weight rather than vanishing. Seeding it from the signal population instead
    is what let LESS analysis publish MORE confidence. Four figures, and the
    headline is the MINIMUM — knowing who can call something, knowing what it
    does, being able to price what it reaches, and knowing HOW MUCH the reach
    moves are different questions.

    The closure the scorer WALKS is a subset of the relations discovery proved
    exist, so seeding the perimeter from the walked closure alone let declining a
    relation FREE confidence: the entities that relation proved are principals of
    gated functions never entered the denominator. ``discovery_entities`` carries
    every endpoint of every relation in the DB's own authority vocabulary, walked
    or not, so declining one charges confidence and can never relieve it (inv. 6).

    The fourth term is the honest home for an unproven magnitude. A signal that
    proved reach but not how much value that reach moves is UNANSWERED here — the
    unknown that otherwise has nowhere to land but the grade. Its denominator is
    the whole perimeter, exactly as the reachability and capability terms', which
    is the only shape monotone under losing work: an entity whose signals vanish
    contributes zero either way, while a denominator scoped to entities that
    happen to carry a signal would RISE when a signal is lost.

    Every key is admitted through ``value_plane.canonical``: an implementation
    is the same entity as the proxy that deploys it, and admitting both hands
    the impl a second copy of the proxy's value band that no signal can ever
    answer (signals are distilled at the proxy address). The alias map comes
    from the same discovery-fixed ``contracts`` rows as the base population, so
    folding through it keeps the denominator independent of analysis. The zero
    address is excluded outright — it is a burn sentinel, not an assessable
    entity (``msg.sender != 0x0``). A perimeter entity proven codeless
    (``resolved_type == 'eoa'``, earned from an empty ``eth_getCode``) has no
    capability surface to leave unanswered: its reach and capability terms are
    vacuously answered, while its pricing term is untouched — holding value is
    a question code-lessness does not answer.
    """
    perimeter: dict[str, float] = {}
    folded: set[str] = set()
    zero_excluded: set[str] = set()

    def admit(raw: str) -> None:
        if P.is_zero_key(raw):
            zero_excluded.add(raw)
            return
        key = value_plane.canonical(raw)
        if key != raw:
            folded.add(raw)
        perimeter.setdefault(key, K.band(value_plane.total(key)))

    for key in sorted(value_plane.contract_entities):
        admit(key)
    for key in sorted(value_plane.per_asset):
        admit(key)
    for key in closure.principals():
        admit(key)
        for controlled in closure.controlled_by(key):
            admit(controlled)
    # Everything above is what the scorer WALKED. Everything below is what
    # discovery PROVED exists, per relation — counted against the walked base so
    # each relation's own contribution is visible rather than assigned to
    # whichever relation happened to be admitted first.
    walked = set(perimeter)
    discovery = discovery_entities or {}
    discovery_admitted: dict[str, int] = {}
    for relation in sorted(discovery):
        keys = sorted(discovery[relation])
        for key in keys:
            admit(key)
        discovery_admitted[relation] = len(
            {value_plane.canonical(key) for key in keys if not P.is_zero_key(key)} - walked
        )
    denominator = round(sum(sorted(perimeter.values())), 6)

    reach: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    scored: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    priced: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    magnitude: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    magnitude_census: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for signal in signals:
        key = value_plane.canonical(entity_key(signal.chain, signal.deployment_address))
        answered = (
            signal.authority_openness == OPENNESS_OPEN
            or signal.principal_state == PRINCIPAL_STATE_ENUMERATED
            or _gate(signal, "exact_empty_credit").is_determined
        )
        reach[key][1] += 1
        scored[key][1] += 1
        if answered:
            reach[key][0] += 1
        if answered and signal.enters_grade:
            scored[key][0] += 1
        if signal.claim_id == "flow.out":
            # The pricing term: an unpriceable reach is a real gap in what the
            # grade could measure, and leaving it out of confidence would make
            # unpriceable value free.
            priced[key][1] += 1
            asset_class = _gate(signal, "asset_class")
            decidable = not _gate(signal, "token_identity").is_determined and (
                not asset_class.is_determined
                or asset_class.value not in SINGLE_ASSET_CLASSES
                or _gate(signal, "asset_identity").is_determined
            )
            if decidable and value_plane.total(key) is not None:
                priced[key][0] += 1
        if signal.value_state == VALUE_STATE_PROVEN_REACH:
            # The reach-magnitude term. A proven reach whose magnitude has no
            # witness is the unknown that otherwise lands in the grade as the
            # entity's whole balance sheet; here it lands as UNANSWERED, which is
            # the only place it can sit without being published as a number.
            #
            # EVERY proven-reach signal is in the denominator. A per-capability
            # exclusion list was tried and removed: a capability that publishes
            # proven_reach is claiming it can move value, and its only live effect
            # was on entities carrying both an excluded and an admitted signal,
            # where dropping the excluded one RAISED the term by discarding a real
            # unanswered question — the shape this term exists to stop.
            witnessed = _gate(signal, "reach_magnitude_usd").is_determined
            magnitude[key][1] += 1
            magnitude_census[signal.claim_id][1] += 1
            if witnessed:
                magnitude[key][0] += 1
                magnitude_census[signal.claim_id][0] += 1

    def weighted(table: dict[str, list[int]]) -> float:
        total = 0.0
        for key in sorted(table):
            answered, seen = table[key]
            if seen and key in perimeter:
                total += perimeter[key] * (answered / seen)
        return round(total, 6)

    codeless_answered = sorted(key for key in perimeter if key in proven_eoas and not scored.get(key, [0, 0])[1])
    for key in codeless_answered:
        reach[key] = [1, 1]
        scored[key] = [1, 1]
        # No code is no capability, and no capability moves no value: there is no
        # reach magnitude here to leave unwitnessed. Same earned getCode witness,
        # same VACUOUS answer — counted in the term and disclosed separately as
        # ``reach_magnitude_vacuous_credit_pct``, because a vacuous answer is not
        # a witness. The pricing term still stands alone.
        magnitude[key] = [1, 1]

    outside = _entities_outside_perimeter(signals, reach, perimeter, value_plane)
    reach_pct = round(100.0 * weighted(reach) / denominator, 1) if denominator else 0.0
    capability_pct = round(100.0 * weighted(scored) / denominator, 1) if denominator else 0.0
    priced_weight = sum(perimeter[k] for k in sorted(perimeter) if value_plane.total(k) is not None)
    priced_pct = round(100.0 * priced_weight / denominator, 1) if denominator else 0.0
    magnitude_pct = round(100.0 * weighted(magnitude) / denominator, 1) if denominator else 0.0
    # The share of the denominator this term could reach at its best: every entity
    # already answered vacuously, plus every reach-carrying entity if all of its
    # proven reaches carried a magnitude witness. Without it a consumer cannot
    # tell how much of the gap is unwitnessed magnitude from how much is perimeter
    # the signal population never covered — two different pieces of work.
    magnitude_ceiling = sum(perimeter[k] for k in sorted(magnitude) if magnitude[k][1] and k in perimeter)
    magnitude_ceiling_pct = round(100.0 * magnitude_ceiling / denominator, 1) if denominator else 0.0
    # Most of this term can be VACUOUS: a proven-codeless entity answers it with
    # no magnitude witness at all. Publishing the headline alone would let a
    # perimeter full of EOAs read as answered magnitude, so the vacuous share is
    # published beside it (term minus this is the witness-backed share of the
    # denominator) together with the witnessed share of the weight that actually
    # carries a proven reach — the figure that only rises when W3/W4b do work.
    vacuous = {key for key in codeless_answered if key in perimeter}
    vacuous_weight = sum(perimeter[key] for key in sorted(vacuous))
    vacuous_pct = round(100.0 * vacuous_weight / denominator, 1) if denominator else 0.0
    reaching = [key for key in sorted(magnitude) if key not in vacuous and magnitude[key][1] and key in perimeter]
    reaching_weight = sum(perimeter[key] for key in reaching)
    reaching_answered = sum(perimeter[key] * (magnitude[key][0] / magnitude[key][1]) for key in reaching)
    witnessed_of_reaching_pct = round(100.0 * reaching_answered / reaching_weight, 1) if reaching_weight else 0.0
    # Counted off the census, not off the weighted table: the table also carries
    # the vacuous credit for proven-codeless entities, which are not signals.
    signals_seen = sum(v[1] for v in magnitude_census.values())
    signals_witnessed = sum(v[0] for v in magnitude_census.values())
    return {
        "pct": min(reach_pct, capability_pct, priced_pct, magnitude_pct),
        "reachability_answered_pct": reach_pct,
        "capability_scored_pct": capability_pct,
        "value_priced_pct": priced_pct,
        "reach_magnitude_witnessed_pct": magnitude_pct,
        "reach_magnitude_ceiling_pct": magnitude_ceiling_pct,
        # Both in the same units as the term (share of the perimeter denominator),
        # so ``witnessed_pct - vacuous_credit_pct`` is the witness-backed share.
        "reach_magnitude_vacuous_credit_pct": vacuous_pct,
        # Of the perimeter weight that actually carries a proven reach, the share
        # whose magnitude is witnessed. No vacuous credit is in this figure.
        "reach_magnitude_witnessed_of_reaching_pct": witnessed_of_reaching_pct,
        "reach_magnitude_signals": {
            "proven_reach_in_denominator": signals_seen,
            "magnitude_witnessed": signals_witnessed,
            "by_capability": {k: v for k, v in sorted(magnitude_census.items())},
            "denominator_rule": (
                "EVERY proven-reach signal, with no per-capability exclusions: a capability "
                "that publishes proven_reach is claiming it moves value, so 'how much' is a "
                "question it owes an answer to. The freeze fraction (pause.set) is in the "
                "denominator and unanswered by design until a witness for it exists"
            ),
        },
        "flow_pricing_decidable": {k: v for k, v in sorted(priced.items()) if v[1]},
        "perimeter_entities": len(perimeter),
        # Entities a signal answers FOR or reaches INTO that the denominator
        # never asked about, so the work is invisible to this figure and, for a
        # reach key, the value is charged into a finding while its own
        # unanswered weight sits in no denominator. With the contracts base
        # population this should be empty; a non-empty list is a discovery gap,
        # published rather than absorbed.
        "signal_entities_outside_perimeter": outside,
        "perimeter_value_weighted_denominator": denominator,
        # Each admission rule, counted where it fired, so a consumer can see
        # what the denominator folded or refused rather than inferring it.
        "implementation_entities_folded": len(folded),
        "zero_address_entities_excluded": len(zero_excluded),
        "proven_codeless_answered": len(codeless_answered),
        "discovery_relation_entities_admitted": discovery_admitted,
        "headline_rule": "report the MINIMUM; any larger figure over-claims",
        "monotonicity": (
            "the denominator is the protocol's contracts rows unioned with the value "
            "plane, the walked control closure and every endpoint of every authority "
            "relation discovery recorded — walked or not — folded through the "
            "discovery-fixed implementation alias map, and built without reference to "
            "the signal population, so analysis work can only move value from "
            "unanswered to answered and declining to walk a relation can only charge "
            "confidence, never free it"
        ),
    }


# ---------------------------------------------------------------- disclosures


def _collect_disclosures(
    signal: FunctionSignal,
    earned_negatives: list[dict[str, Any]],
    seen: set[tuple[str, str]],
    warnings: list[dict[str, Any]],
) -> None:
    entity = entity_key(signal.chain, signal.deployment_address)
    credit = _gate(signal, "exact_empty_credit")
    if credit.is_determined:
        if signal.principal_state != PRINCIPAL_STATE_NOT_DETERMINED:
            # "No resolved caller can reach this" cannot be published beside ANY
            # determined caller state: ``enumerated`` names callers that reach it,
            # and ``none_required`` is a PROVEN PUBLIC PATH — the opposite pole,
            # and the worse contradiction of the two.
            warnings.append(
                _warning(
                    "exact_empty_credit_contradicted_by_principals",
                    signal,
                    (
                        "an earned empty caller set on a function with a proven public path"
                        if signal.principal_state == PRINCIPAL_STATE_NONE_REQUIRED
                        else "an earned empty caller set on a function whose principals resolved"
                    ),
                    principal_state=signal.principal_state,
                )
            )
        elif (entity, signal.function_name) not in seen:
            seen.add((entity, signal.function_name))
            payload = credit.value if isinstance(credit.value, dict) else {}
            earned_negatives.append(
                {
                    "entity": entity,
                    "function": signal.function_name,
                    "capability": signal.claim_id,
                    "fact": "no resolved caller can reach this function",
                    "state": "currently_unreachable",
                    "observed_at_block": payload.get("block"),
                    "empty_reason": payload.get("empty_reason"),
                    "counterfactual": "one ownership/authority write restores reachability",
                    "axiom": (
                        "msg.sender != 0x0, so an owner disjunct of {0x0} is a singleton rather than the empty set"
                    ),
                    "re_enablable_by": NOT_DETERMINED,
                }
            )
    if signal.value_state == VALUE_STATE_PROVEN_NO_REACH and (entity, signal.function_name + ":no_reach") not in seen:
        # An earned negative in its own right: reach was WITNESSED and reached
        # nothing. Publishing it beside the undetermined rows would lose the one
        # value fact on the page that was actually proven.
        seen.add((entity, signal.function_name + ":no_reach"))
        earned_negatives.append(
            {
                "entity": entity,
                "function": signal.function_name,
                "capability": signal.claim_id,
                "fact": "reach was witnessed and reached no value",
                "state": "proven_no_reach",
                "basis": signal.value_basis,
                "counterfactual": "funding the entity would give this capability something to reach",
                "re_enablable_by": NOT_DETERMINED,
            }
        )
    latch = _gate(signal, "latch_witness")
    if latch.is_determined:
        payload = latch.value if isinstance(latch.value, dict) else {}
        warnings.append(
            _warning(
                "one_shot_latch_is_reopenable",
                signal,
                "a consumed latch is a now-fact, re-openable by the upgrade authority of the probed proxy",
                latch_state=payload.get("latch_state"),
                probe_block=payload.get("probe_block"),
            )
        )
    for note in signal.witness_notes:
        if note in _NOTE_WARNINGS:
            warnings.append(_warning(note, signal, _NOTE_WARNINGS[note]))


_NOTE_WARNINGS = {
    "destination_not_determined_row_withheld": (
        "the destination was not proven, so no severity is assigned and the row does not "
        "enter the grade; absence of a resolved constraint is not proof the destination is open"
    ),
    "destination_witnesses_contradict": (
        "two destination witnesses cannot both be true, so neither is adopted and the row is withheld"
    ),
    "caller_arbitrary_escalation_withheld": "caller_arbitrary carries no behavioural existence proof",
    "reach_floor_not_a_bound": "a 0.00 floor is 'no proven bound', not a proven zero",
    "reach_floor_absent": "reach_indeterminate with no floor key: nothing about the balance was witnessed",
    "reach_seeded_balance_only": "the contract's balance was overridden before the payout",
    "reach_partially_priced": "the reach is a proven floor; the unpriced remainder is a confidence gap",
    "freeze_effectiveness_not_determined": (
        "no fork proof that the latch takes effect, so no value membership is charged"
    ),
    "freeze_immobilised_fraction_not_determined": (
        "the value held at the frozen entity is measured; what fraction is immobilised has no witness"
    ),
    "product_claim_reachability_unproven": "treated as product on claim_id alone, but openness is not_determined",
    "claim_type_not_scored": "no severity model exists for this claim type; exclusion is not a benign verdict",
    "restricted_privileged_no_principal": "restricted privileged function with no resolved principal",
    "empty_caller_set_not_earned": (
        "an empty caller set that did not earn the served credit: neither reachable nor "
        "proven unreachable, so no earned negative is published"
    ),
    "registry_escalation_mutators_unverified": "an owner resolves but the role mutator selectors are not present",
    "delay_change_gate_not_self_gated": (
        "the delay-change path's own gate is not the contract itself, so no anti-decoy credit is taken"
    ),
    "destination_redirectable_by_unresolved_setter": "the destination's setter is named by no witness",
    "concrete_destination_existential_not_a_fixed_destination": (
        "an observed sink is existential and cannot prove a fixed destination"
    ),
}


def _warning(kind: str, signal: FunctionSignal, note: str, **extra: Any) -> dict[str, Any]:
    return {
        "kind": kind,
        "entity": entity_key(signal.chain, signal.deployment_address),
        "function": signal.function_name,
        "capability": signal.claim_id,
        "note": note,
        **{k: v for k, v in sorted(extra.items()) if v is not None},
    }


def _summarise_warnings(warnings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        warnings,
        key=lambda w: (
            str(w.get("kind")),
            str(w.get("entity")),
            str(w.get("function")),
            str(w.get("capability")),
            str(w.get("note")),
        ),
    )


def _population_disposition(signals: list[FunctionSignal], findings: list[dict[str, Any]]) -> str:
    if not signals:
        return "no_population(no current signals for this protocol)"
    if not findings:
        return "population_scored_to_nothing(every signal failed closed)"
    return "scored"


def _counterfactual(kind: str) -> str:
    return {
        ANYONE: "gate this capability behind a multisig or timelock",
        "eoa": "move behind a strong multisig (>= 0.67 k/n) or a timelock",
        "safe": "raise the threshold ratio, diversify signers across units, and/or add a timelock in front",
        "timelock": "already timelock-gated; the residual is the proposer quorum and the delay length",
        "contract": "resolve the controlling principal of the gating contract",
    }.get(kind, "n/a")


__all__ = ["GATE_PROVEN_TOKENS", "compute_protocol_score"]
