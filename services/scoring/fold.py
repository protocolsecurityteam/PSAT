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

Every arithmetic branch fails closed. A signal whose severity was not proven is
not scored; a value that could not be priced falls to the unpriced branch rather
than to zero; an unread witness never becomes a default.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from services.scoring import constants as K
from services.scoring import planes as P
from services.scoring.population import current_signals_for_protocol
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
    SCORE_TRIGGER_MANUAL,
    VALUE_STATE_PROVEN_REACH,
)

ANYONE = "anyone"


@dataclass
class _Instance:
    """One signal's contribution to one (unit, capability) row."""

    signal: FunctionSignal
    severity: float
    severity_basis: tuple[str, ...]
    entity_keys: tuple[str, ...]
    magnitude: Tri[float]
    value_bound: str
    pricing_blocked: str | None
    native_only: bool


@dataclass
class _Row:
    unit: str
    capability: str
    principal_label: str = ""
    principal_kind: str = ""
    weakness: float = 0.0
    weakest_label: str | None = None
    instances: list[_Instance] = field(default_factory=list)
    seeds: set[str] = field(default_factory=set)
    tiers: set[str] = field(default_factory=set)
    notes: set[str] = field(default_factory=set)
    citations: list[dict[str, Any]] = field(default_factory=list)


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
    if signals is None:
        signals = current_signals_for_protocol(session, protocol_id)

    value_plane = P.load_value_plane(session, protocol_id)
    closure = P.load_control_closure(session, protocol_id)
    role_floors = P.load_role_holder_floors(session)
    refs = [ref for signal in signals for ref in signal.principal_refs]
    refs.extend(_recovery_refs(signals))
    principal_facts = P.load_principal_plane(session, refs)

    warnings: list[dict[str, Any]] = []
    earned_negatives: list[dict[str, Any]] = []

    units = _UnitResolver(signals, principal_facts, role_floors, warnings)
    rows_by_key: dict[tuple[str, str], _Row] = {}

    for signal in signals:
        _collect_disclosures(signal, earned_negatives, warnings)
        if not signal.enters_grade:
            continue

        if signal.authority_openness == OPENNESS_OPEN:
            severity, severity_basis, extra_notes = _fold_severity(signal, None, principal_facts, warnings)
            instance = _instance(signal, severity, severity_basis)
            unit = entity_key(signal.chain, ANYONE)
            row = rows_by_key.setdefault((unit, signal.claim_id), _Row(unit=unit, capability=signal.claim_id))
            row.principal_label = "ANYONE (permissionless)"
            row.principal_kind = ANYONE
            row.weakness = K.WEAKNESS_ANYONE
            row.weakest_label = "ANYONE"
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
            instance = _instance(signal, severity, severity_basis)
            weakness, label, kind, notes = units.weakness_for(
                facts,
                signal,
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
            row = rows_by_key.setdefault((unit, signal.claim_id), _Row(unit=unit, capability=signal.claim_id))
            row.principal_label = f"{label} {facts.address}"
            row.principal_kind = kind
            if weakness > row.weakness:
                row.weakness = weakness
                row.weakest_label = label
            _attach(row, signal, instance, extra_notes | set(notes))

    findings, subsumed, value_warnings = _aggregate(rows_by_key, value_plane, closure)
    warnings.extend(value_warnings)

    grade_lambda, grade_exposure, exposure_usd = _grade(findings, value_plane)
    confidence = _confidence(signals, value_plane, closure)

    perimeter, perimeter_detail = P.perimeter_state(session, protocol_id)
    provenance = {
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
        },
        "value": value_plane.provenance,
        "value_annotations": value_plane.annotations,
        "unpriced_positions": value_plane.unpriced_positions,
        "upgrade_history": P.load_upgrade_provenance(session, protocol_id),
        "ledgers": P.load_ledgers(session, protocol_id),
        "audit_posture": P.load_audit_posture(session, protocol_id),
        "perimeter": perimeter_detail,
        "earned_negative_scope": (
            "published for claim-bearing functions only, because a signal is keyed on a "
            "capability; a function with an earned empty caller set and no claim carries "
            "no signal and is therefore absent here (1 such row on this corpus)"
        ),
        "determinism": (
            "every query carries a total ORDER BY and every sort a total tiebreak; "
            "the same DB state yields an identical document modulo computed_at"
        ),
    }

    # The three grade figures stand or fall together. An exposure ratio with no
    # priced denominator is not a 100 — it is a quantity that was never
    # measured — so a protocol with findings but no priced value publishes the
    # findings and withholds the grade, with the withheld figure in provenance.
    scored = bool(findings) and grade_exposure is not None
    if findings and not scored:
        provenance["grade_withheld"] = {
            "grade_lambda_computed": grade_lambda,
            "reason": "no priced value in the perimeter, so the exposure denominator is not_determined",
        }
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
        confidence_pct=confidence["pct"] if scored else None,
        findings=findings,
        earned_negatives=sorted(earned_negatives, key=lambda e: (e["entity"], e["function"])),
        warnings=_summarise_warnings(warnings),
        model_parameters={**K.model_parameters(), "confidence_detail": confidence},
        provenance={**provenance, "subsumed_rows": subsumed, "exposure_usd": exposure_usd},
        uncalibrated_arms=K.UNCALIBRATED_ARMS,
    )


# ---------------------------------------------------------------- principals


class _UnitResolver:
    """Principal units: per (chain, address), with the two licensed collapses.

    Safes that can ACT AS each other are one unit — independence is a property of
    owner KEY SETS, and two Safes sharing enough owners are one power. A timelock
    whose sole proposer-executor is a Safe collapses into that Safe: upgrade-by-
    timelock is a subset of exec-by-proposer, so two rows would charge the same
    value twice. Neither collapse ever crosses a chain: the same address on two
    chains is two units, because same-address is not proof of same owner set.
    """

    def __init__(
        self,
        signals: list[FunctionSignal],
        principal_facts: dict[int, P.PrincipalFacts],
        role_floors: dict[tuple[str, str, str], dict[str, Any]],
        warnings: list[dict[str, Any]],
    ) -> None:
        self._facts = principal_facts
        self._role_floors = role_floors
        self._warnings = warnings
        self._safe_by_key = {
            facts.key: facts
            for facts in sorted(principal_facts.values(), key=lambda f: f.key)
            if facts.resolved_type == "safe" and facts.owners
        }
        self._parent = {key: key for key in self._safe_by_key}
        self.overlaps: list[dict[str, Any]] = []
        self._union_overlapping_safes()
        self._proposers = self._timelock_proposers(signals)

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
                k_left = left.threshold or 99
                k_right = right.threshold or 99
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
                    }
                )
                if can_act:
                    root_a, root_b = self._find(a), self._find(b)
                    if root_a != root_b:
                        self._parent[root_b] = root_a
        self.overlaps.sort(key=lambda o: (o["a"], o["b"]))

    def _timelock_proposers(self, signals: list[FunctionSignal]) -> dict[str, dict[str, Any]]:
        """The weakest Safe that can both propose and execute on each timelock."""
        best: dict[str, dict[str, Any]] = {}
        for signal in sorted(signals, key=lambda s: (s.chain, s.deployment_address, s.selector, s.claim_id)):
            if signal.claim_id not in ("timelock.schedule", "timelock.execute"):
                continue
            timelock_key = entity_key(signal.chain, signal.deployment_address)
            for ref in signal.principal_refs:
                facts = self._facts.get(int(ref.function_principal_id))
                if facts is None or facts.resolved_type != "safe" or not facts.owners:
                    continue
                ratio = (facts.threshold or len(facts.owners)) / len(facts.owners)
                candidate = {"key": facts.key, "k": facts.threshold, "n": len(facts.owners), "ratio": ratio}
                # inv.5 is the WEAKEST path, not the strongest.
                if timelock_key not in best or candidate["ratio"] < best[timelock_key]["ratio"]:
                    best[timelock_key] = candidate
        return best

    def unit_for(self, facts: P.PrincipalFacts) -> str:
        key = facts.key
        if facts.resolved_type == "timelock":
            proposer = self._proposers.get(key)
            if proposer:
                key = proposer["key"]
        if key in self._parent:
            # The unit is named by its LOWEST member key, not by whichever root
            # the union order happened to leave: a union-find root is an
            # implementation artefact, and naming a unit with one would make the
            # same set of Safes carry different identities across runs.
            root = self._find(key)
            return min(member for member in self._parent if self._find(member) == root)
        return key

    def proposer_for(self, facts: P.PrincipalFacts) -> dict[str, Any] | None:
        return self._proposers.get(facts.key)

    def weakness_for(
        self, facts: P.PrincipalFacts, signal: FunctionSignal, *, recovery_proven_independent: bool = False
    ) -> tuple[float | None, str, str, list[str]]:
        notes: list[str] = []
        if facts.resolver_bases:
            weak = [b for b in facts.resolver_bases if K.resolver_basis_tier(b) == K.WEAKEST_RESOLVER_BASIS_TIER]
            if weak:
                notes.append("resolver_basis_convention:" + ",".join(sorted(weak)))

        if facts.resolved_type == "eoa":
            weakness, label, kind = K.WEAKNESS_EOA, "EOA", "eoa"
        elif facts.resolved_type == "safe":
            n = len(facts.owners) or facts.threshold
            weakness = K.quorum_weakness(
                facts.threshold,
                n,
                credit_withheld=facts.protection_credit_withheld,
                waive_single_signer_cliff=recovery_proven_independent,
            )
            if facts.protection_credit_withheld:
                notes.append(f"safe_kn_credit_withheld:{facts.protection_basis}")
            label, kind = f"Safe {facts.threshold}/{n}", "safe"
        elif facts.resolved_type == "timelock":
            discount = K.delay_discount(facts.delay_seconds)
            proposer = self.proposer_for(facts)
            if discount is None:
                notes.append("timelock_delay_not_determined")
                weakness, label, kind = K.WEAKNESS_TIMELOCK_UNDETERMINED, "timelock(?)", "timelock"
            elif not proposer:
                # A proven delay whose proposer set is undetermined is not proven
                # protection, so the delay earns no discount.
                notes.append("timelock_proposer_not_determined:no_delay_credit")
                weakness = K.WEAKNESS_TIMELOCK_UNDETERMINED
                label, kind = f"timelock {int(facts.delay_seconds or 0) // 86400}d(proposer?)", "timelock"
            else:
                base = K.quorum_weakness(proposer["k"], proposer["n"], credit_withheld=False)
                weakness = round(base * discount, 4)
                notes.append(f"delay_discount={discount};proposer={proposer['k']}/{proposer['n']}")
                label = f"timelock {int(facts.delay_seconds or 0) // 86400}d via {proposer['k']}/{proposer['n']}"
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

    def _role_breadth(self, facts: P.PrincipalFacts) -> float | None:
        """A proven holder floor above one is proven BREADTH. It may only raise."""
        for registry, role_hash in facts.role_bindings:
            entry = self._role_floors.get((facts.chain, registry, role_hash))
            if entry and entry["holders_floor"] > 1:
                return K.ROLE_BREADTH_MULTI_HOLDER_WEAKNESS
        return None


def _recovery_refs(signals: list[FunctionSignal]) -> list[Any]:
    """Principal references named by pause recovery gates, so the fold can read them."""

    @dataclass(frozen=True)
    class _Ref:
        function_principal_id: int
        chain: str
        address: str

    out: list[Any] = []
    for signal in signals:
        if signal.claim_id != "pause.set":
            continue
        gate = signal.gate_input("freeze_recovery_principals")
        if not gate.is_determined:
            continue
        for entry in gate.value or []:
            if isinstance(entry, dict) and entry.get("function_principal_id") is not None:
                out.append(
                    _Ref(
                        function_principal_id=int(entry["function_principal_id"]),
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
    severity = signal.severity.require(signal.severity.state)
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
        # Neither recoverable nor sustainable is proven, so severity stays at the
        # proven-existence component rather than being assumed either way.
        notes.add(note)
        warnings.append(_warning("freeze_recovery_independence_not_determined", signal, note))
    else:
        notes.add(note)
    return severity, basis, notes


def _keyset_independence(
    signal: FunctionSignal, principal: P.PrincipalFacts, principal_facts: dict[int, P.PrincipalFacts]
) -> tuple[bool | None, int | None, str]:
    """Is the recovery quorum independent of the freezing one, in KEYS?

    Independence is a property of owner key sets: P and U are independent iff
    ``|owners(U) \\ owners(P)| >= threshold(U)``. Comparing principal ADDRESSES
    publishes a protective credit for a configuration where a handful of keys
    freeze the protocol and hold it.
    """
    gate = signal.gate_input("freeze_recovery_principals")
    if not gate.is_determined:
        return None, None, "recovery_path_not_determined_no_unset_claim"
    pauser_owners = principal.owners or frozenset({principal.address})
    saw_safe = False
    best: int | None = None
    for entry in sorted(gate.value or [], key=lambda e: str(e.get("address"))):
        facts = principal_facts.get(int(entry.get("function_principal_id", -1)))
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


def _instance(signal: FunctionSignal, severity: float, basis: tuple[str, ...]) -> _Instance:
    magnitude = signal.gate_input("reach_magnitude_usd")
    pricing_blocked = None
    native_only = False
    if signal.claim_id == "flow.out":
        if signal.gate_input("token_identity").is_determined:
            # Exactly one NON-FUNGIBLE token moves: pricing the row off a
            # fungible balance sheet is forbidden, not merely imprecise.
            pricing_blocked = "token_identity(non-fungible; pricing forbidden)"
        asset_class = signal.gate_input("asset_class")
        native_only = asset_class.is_determined and asset_class.value == "native_only"
    return _Instance(
        signal=signal,
        severity=severity,
        severity_basis=basis,
        entity_keys=signal.value_entity_keys,
        magnitude=magnitude,
        value_bound=signal.value_bound,
        pricing_blocked=pricing_blocked,
        native_only=native_only,
    )


def _attach(row: _Row, signal: FunctionSignal, instance: _Instance, notes: set[str]) -> None:
    row.instances.append(instance)
    row.seeds.add(entity_key(signal.chain, signal.deployment_address))
    row.tiers.add(signal.witness_tier)
    row.notes.update(signal.witness_notes)
    row.notes.update(notes)
    row.citations.extend(signal.citations)


def _aggregate(
    rows_by_key: dict[tuple[str, str], _Row],
    value_plane: P.ValuePlane,
    closure: dict[str, set[str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    warnings: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for key in sorted(rows_by_key):
        row = rows_by_key[key]
        if not row.instances:
            continue
        value_usd, value_basis, undetermined, reach = _row_value(row, value_plane, closure)
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
                "principal": row.principal_label,
                "principal_kind": row.principal_kind,
                "capability": row.capability,
                "chain": row.unit.split("::", 1)[0],
                "value_at_stake_usd": (round(value_usd, 2) if value_usd is not None else None),
                "value_state": (VALUE_STATE_PROVEN_REACH if value_usd is not None else NOT_DETERMINED),
                "value_at_stake_basis": value_basis,
                "value_at_stake_is_floor": bool(value_usd is not None and undetermined),
                "value_band": (
                    ((">= " + K.band_label(value_usd)) if undetermined else K.band_label(value_usd))
                    if value_usd is not None
                    else NOT_DETERMINED
                ),
                "undetermined_instances": undetermined,
                "severity_proven": round(severity, 4),
                "severity_basis": sorted({b for instance in row.instances for b in instance.severity_basis}),
                "weakness": round(row.weakness, 4),
                "weakest_gate": row.weakest_label,
                "raw_points": round(K.SEV_SCALE * severity * row.weakness * band, 4),
                "n_functions": len(row.instances),
                "n_entities": len(row.seeds),
                "reach_entities": sorted(reach),
                "example_functions": sorted({i.signal.function_name for i in row.instances})[:6],
                "witness_tiers": sorted(row.tiers),
                "witness_notes": sorted(row.notes),
                "citations": row.citations[:8],
                "counterfactual": _counterfactual(row.principal_kind),
            }
        )

    by_unit: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_unit[row["principal_unit"]].append(row)
    findings: list[dict[str, Any]] = []
    subsumed: list[dict[str, Any]] = []
    for unit in sorted(by_unit):
        ordered = sorted(by_unit[unit], key=lambda r: (-r["raw_points"], r["capability"]))
        top = dict(ordered[0])
        rest = ordered[1:]
        top["subsumed_capabilities"] = [
            {"capability": r["capability"], "raw_points": r["raw_points"], "n_entities": r["n_entities"]} for r in rest
        ]
        top["subsumed_raw_points"] = round(sum(r["raw_points"] for r in rest), 4)
        if rest:
            top["counterfactual"] += (
                "; this row subsumes " + ", ".join(r["capability"] for r in rest) + " — fixing the top "
                "capability alone does not release them"
            )
        findings.append(top)
        subsumed.extend(rest)
    findings.sort(key=lambda r: (-r["raw_points"], r["capability"], r["principal_unit"]))
    subsumed.sort(key=lambda r: (-r["raw_points"], r["capability"], r["principal_unit"]))
    return findings, subsumed, warnings


def _row_value(
    row: _Row, value_plane: P.ValuePlane, closure: dict[str, set[str]]
) -> tuple[float | None, str, list[dict[str, Any]], set[str]]:
    """Value at stake for one (unit, capability) row: MAX per entity, never SUM.

    Two functions reaching the same vault charge it once, and a witnessed
    magnitude caps what the row may charge against an entity — the entity's whole
    balance sheet is not what a bounded call can move.
    """
    if row.capability in K.TRANSITIVE_CAPABILITIES:
        reach = _closure(row.seeds, closure)
        per_entity: dict[str, float] = {}
        undetermined: list[dict[str, Any]] = []
        for key in sorted(reach):
            total = value_plane.total(key)
            if total is None:
                continue
            per_entity[key] = total
        if not per_entity:
            return None, "transitive_closure(no priced entity; not_determined)", undetermined, reach
        return (
            round(sum(sorted(per_entity.values())), 6),
            "transitive control closure, MAX per (entity, asset)",
            undetermined,
            reach,
        )

    per_entity = {}
    undetermined = []
    for instance in sorted(row.instances, key=lambda i: (i.signal.deployment_address, i.signal.function_name)):
        if instance.pricing_blocked:
            undetermined.append(
                {
                    "function": instance.signal.function_name,
                    "entity": entity_key(instance.signal.chain, instance.signal.deployment_address),
                    "why": instance.pricing_blocked,
                }
            )
            continue
        if instance.signal.value_state != VALUE_STATE_PROVEN_REACH:
            undetermined.append(
                {
                    "function": instance.signal.function_name,
                    "entity": entity_key(instance.signal.chain, instance.signal.deployment_address),
                    "why": instance.signal.value_basis,
                }
            )
            continue
        for key in instance.entity_keys:
            contribution, why = _entity_contribution(instance, key, value_plane)
            if contribution is None:
                undetermined.append({"function": instance.signal.function_name, "entity": key, "why": why})
                continue
            previous = per_entity.get(key)
            if previous is None or contribution > previous:
                per_entity[key] = contribution
    reach = set(per_entity)
    if not per_entity:
        return None, "not_determined", undetermined, reach
    basis = "per-instance witnessed value, MAX per (entity, asset)"
    if undetermined:
        basis = f">= proven floor over {len(per_entity)} entity(ies); {len(undetermined)} instance(s) not_determined"
    return round(sum(sorted(per_entity.values())), 6), basis, undetermined, reach


def _entity_contribution(instance: _Instance, key: str, value_plane: P.ValuePlane) -> tuple[float | None, str]:
    if instance.native_only:
        # A provably native-only flow may only be valued against the native
        # holding, and an absent native row is not_determined, never $0.
        native = P.native_value_state(value_plane, key)
        if not native.is_determined:
            return None, "native_only_flow+absent_native_row(not_determined)"
        return float(native.value or 0.0), "native_only_flow x native_balance"

    held = value_plane.total(key)
    if instance.magnitude.is_determined:
        magnitude = float(instance.magnitude.value or 0.0)
        if instance.magnitude.state == "proven_exact":
            # The witness bounds what this call moves; the entity's sheet bounds
            # what is there to move. Neither alone is the answer.
            return (min(held, magnitude) if held is not None else magnitude), "witnessed_reach(exact)"
        return magnitude, "witnessed_reach(floor)"
    if held is None:
        return None, "entity_value_not_determined"
    return held, "entity_holdings"


def _closure(seeds: set[str], closure: dict[str, set[str]]) -> set[str]:
    seen: set[str] = set()
    stack = sorted(seeds)
    while stack:
        key = stack.pop()
        if key in seen:
            continue
        seen.add(key)
        for nxt in sorted(closure.get(key, ())):
            if nxt not in seen:
                stack.append(nxt)
    return seen


def _grade(findings: list[dict[str, Any]], value_plane: P.ValuePlane) -> tuple[float | None, float | None, float]:
    if not findings:
        return None, None, 0.0
    for index, finding in enumerate(findings):
        finding["net_points_lambda"] = round(finding["raw_points"] * (K.LAMBDA**index), 4)
    cumulative = round(sum(f["net_points_lambda"] for f in findings), 4)
    grade_lambda = round(100.0 - min(cumulative, 100.0), 4)

    claimed: dict[str, float] = defaultdict(float)
    exposure = 0.0
    for finding in findings:
        fraction = finding["severity_proven"] * finding["weakness"]
        mine = 0.0
        for key in finding["reach_entities"]:
            held = value_plane.total(key) or 0.0
            if finding["capability"] not in K.TRANSITIVE_CAPABILITIES and finding["value_at_stake_usd"] is not None:
                # A non-transitive capability can only expose what its own
                # witness says it can move.
                held = min(held, finding["value_at_stake_usd"])
            room = max(0.0, 1.0 - claimed[key])
            take = min(fraction, room)
            if take > 0:
                claimed[key] += take
                mine += take * held
        finding["exposure_usd"] = round(mine, 2)
        exposure += finding["exposure_usd"]
    tracked = value_plane.tracked_total
    grade_exposure = round(100.0 * (1.0 - exposure / tracked), 3) if tracked else None
    if grade_exposure is None:
        # No priced value at all: an exposure ratio has no denominator and is
        # not_determined rather than a perfect score.
        return grade_lambda, None, round(exposure, 2)
    return grade_lambda, grade_exposure, round(exposure, 2)


def _confidence(
    signals: list[FunctionSignal], value_plane: P.ValuePlane, closure: dict[str, set[str]]
) -> dict[str, Any]:
    """Monotone in resolution work: the denominator is the PERIMETER.

    The perimeter is fixed independent of what has been analysed, so every unit
    of resolution work can only move value from unanswered to answered. Two
    figures, and the headline is the MINIMUM: knowing WHO can call something and
    knowing WHAT it does are different questions, and reporting the larger
    over-claims.
    """
    perimeter: dict[str, float] = {}
    for key in sorted(value_plane.per_asset):
        perimeter[key] = K.band(value_plane.total(key))
    for key in sorted(closure):
        perimeter.setdefault(key, K.band(value_plane.total(key)))
        for source in sorted(closure[key]):
            perimeter.setdefault(source, K.band(value_plane.total(source)))
    for signal in signals:
        perimeter.setdefault(
            entity_key(signal.chain, signal.deployment_address),
            K.band(value_plane.total(entity_key(signal.chain, signal.deployment_address))),
        )
    denominator = round(sum(sorted(perimeter.values())), 6)

    reach: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    scored: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for signal in signals:
        key = entity_key(signal.chain, signal.deployment_address)
        answered = (
            signal.authority_openness == OPENNESS_OPEN
            or signal.principal_state == PRINCIPAL_STATE_ENUMERATED
            or signal.gate_input("exact_empty_credit").is_determined
        )
        reach[key][1] += 1
        scored[key][1] += 1
        if answered:
            reach[key][0] += 1
        if answered and signal.enters_grade:
            scored[key][0] += 1

    def weighted(table: dict[str, list[int]]) -> float:
        total = 0.0
        for key in sorted(table):
            answered, seen = table[key]
            if seen and key in perimeter:
                total += perimeter[key] * (answered / seen)
        return round(total, 6)

    reach_pct = round(100.0 * weighted(reach) / denominator, 1) if denominator else 0.0
    capability_pct = round(100.0 * weighted(scored) / denominator, 1) if denominator else 0.0
    return {
        "pct": min(reach_pct, capability_pct),
        "reachability_answered_pct": reach_pct,
        "capability_scored_pct": capability_pct,
        "perimeter_entities": len(perimeter),
        "perimeter_value_weighted_denominator": denominator,
        "headline_rule": "report the MINIMUM; the larger figure over-claims",
        "monotonicity": (
            "the denominator is the perimeter and is fixed independent of what has "
            "been analysed, so resolution work can only move value from unanswered "
            "to answered"
        ),
    }


# ---------------------------------------------------------------- disclosures


def _collect_disclosures(
    signal: FunctionSignal, earned_negatives: list[dict[str, Any]], warnings: list[dict[str, Any]]
) -> None:
    credit = signal.gate_input("exact_empty_credit")
    if credit.is_determined:
        payload = credit.value if isinstance(credit.value, dict) else {}
        earned_negatives.append(
            {
                "entity": entity_key(signal.chain, signal.deployment_address),
                "function": signal.function_name,
                "capability": signal.claim_id,
                "fact": "no resolved caller can reach this function",
                "state": "currently_unreachable",
                "observed_at_block": payload.get("block"),
                "empty_reason": payload.get("empty_reason"),
                "counterfactual": "one ownership/authority write restores reachability",
                "axiom": ("msg.sender != 0x0, so an owner disjunct of {0x0} is a singleton rather than the empty set"),
                "re_enablable_by": NOT_DETERMINED,
            }
        )
    latch = signal.gate_input("latch_witness")
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
    "registry_escalation_mutators_unverified": "an owner resolves but the role mutators are not present",
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


__all__ = ["compute_protocol_score"]
