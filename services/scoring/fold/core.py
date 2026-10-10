"""The fold's orchestrators (``compute_protocol_score``, ``_aggregate``, ``_row_value``) and unit resolution."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from services.scoring import constants as K
from services.scoring import planes as P
from services.scoring.fold.ceilings import (
    _bound_direction,
    _ceiling_bearing_basis,
    _coverage_bearing_basis,
    _disclose_order_ties,
    _partially_priced_entities,
    _reconcile_sheet_ceilings,
    _sheet_ceiling_records,
    _sheet_ceiling_totals,
    _unresolved_levers,
    _unresolved_stake,
)
from services.scoring.fold.closure import _behind_the_frontier, _closure, _hop_census
from services.scoring.fold.composition import (
    _admit_composed,
    _compose,
    _ComposedMagnitude,
    _composition_report,
    _counted,
    _destination_magnitudes,
    _pool_composed,
    _select_composed,
)
from services.scoring.fold.confidence import _confidence
from services.scoring.fold.contributions import _instance_contributions, _witnessed_magnitude
from services.scoring.fold.disclosures import (
    _collect_disclosures,
    _counterfactual,
    _population_disposition,
    _summarise_warnings,
    _uncharged_product,
    _warning,
)
from services.scoring.fold.gates import (
    ANYONE,
    SINGLE_ASSET_CLASSES,
    _gate,
    _is_principal_ref,
    _malformed_gates,
    _row_for,
    _signal_identity,
)
from services.scoring.fold.grade import _grade
from services.scoring.fold.readings import _BAND_PREFIX, BOUND_DIRECTION_FLOOR, CEILING_KIND_SHEET, _round_published
from services.scoring.fold.types import (
    _AdmissionPlanes,
    _DestinationMagnitude,
    _gate_claim,
    _Instance,
    _Row,
    _RowValue,
    _WithheldComposition,
)
from services.scoring.population import current_signals_with_faults
from services.scoring.schema import NOT_DETERMINED, FunctionSignal, ScoreDocument, entity_key
from utils import claim_ids as C
from utils import execution_record as EX
from utils.execution_record import PROVING_EXECUTION_KEY
from utils.scoring_status import (
    GRADE_FAULT_DEGRADED,
    GRADE_STATE_COMPUTED,
    GRADE_STATE_NOT_DETERMINED,
    MODEL_VERSION,
    OPENNESS_NOT_DETERMINED,
    OPENNESS_OPEN,
    PRINCIPAL_SET_NOT_EXACT_NOTE,
    PRINCIPAL_STATE_ENUMERATED,
    SCORE_TRIGGER_MANUAL,
    SEVERITY_STATE_PROVEN,
    VALUE_STATE_PROVEN_NO_REACH,
    VALUE_STATE_PROVEN_REACH,
)


def compute_protocol_score(
    session: Session,
    protocol_id: int,
    *,
    signals: list[FunctionSignal] | None = None,
    trigger: str = SCORE_TRIGGER_MANUAL,
    trigger_job_id: Any | None = None,
    computed_at: datetime | None = None,
) -> ScoreDocument:
    """The protocol's score document over its current signal rows.

    ``signals`` is only for the offline CLI's in-memory mode (in :func:`order_signals` order); otherwise the population
    comes from the one pinned query, so no caller can filter or reorder it.
    """
    row_faults: list[dict[str, Any]] = []
    if signals is None:
        # A row with malformed persisted JSONB withholds only itself.
        signals, row_faults = current_signals_with_faults(session, protocol_id)

    value_plane = P.load_value_plane(session, protocol_id)
    closure = P.load_control_closure(session, protocol_id)
    conditions = P.load_condition_plane(session, protocol_id)
    conferral = P.load_conferral_plane(session, protocol_id)
    act_as = P.load_act_as_plane(session, protocol_id)
    # Not protocol-scoped: it asks about global (chain, address) identities, and scoping would drop setter rows and mint
    # false negatives.
    admission = _AdmissionPlanes(P.load_deletability_plane(session), P.load_router_flow_plane(session, protocol_id))
    role_floors = P.load_role_holder_floors(session, protocol_id)
    refs = [ref for signal in signals for ref in signal.principal_refs]
    refs.extend(_recovery_refs(signals))
    principal_facts = P.load_principal_plane(session, refs)
    stale_inputs = _stale_principal_inputs(signals, principal_facts)

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
    uncharged_product_rows = 0

    units = _UnitResolver(signals, principal_facts, role_floors)
    rows_by_key: dict[tuple[str, str, str], _Row] = {}

    for signal in signals:
        malformed = _malformed_gates(signal)
        if malformed:
            # One unreadable envelope withholds its own row, not the whole grade.
            warnings.append(_warning("gate_input_malformed", signal, f"unreadable gate envelopes: {malformed}"))
            continue

        _collect_disclosures(signal, earned_negatives, seen_negatives, warnings)
        if not signal.enters_grade:
            continue

        if _uncharged_product(signal, warnings):
            # A proven benign payout of the caller's own value: counted in confidence, but no row or exposure (not a
            # finding worth zero).
            uncharged_product_rows += 1
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

    composed_signals: set[tuple[Any, ...]] = set()
    ceiling_signals: set[tuple[Any, ...]] = set()
    composition_census: dict[str, Any] = {}
    findings, subsumed, value_warnings = _aggregate(
        rows_by_key,
        value_plane,
        closure,
        conditions,
        conferral,
        act_as,
        _destination_magnitudes(signals),
        admission,
        units,
        composed_signals,
        ceiling_signals,
    )
    warnings.extend(value_warnings)
    composition_census = _composition_totals(findings, subsumed)

    # Transport faults move the grade, so they're announced at the top rather than left in execution blocks.
    execution_faults = _execution_fault_census(findings, subsumed)
    if execution_faults is not None:
        warnings.append(_execution_fault_warning(execution_faults))

    grade_lambda, grade_exposure, exposure_usd, exposure_gaps, exposure_coverage = _grade(findings, value_plane)
    confidence = _confidence(
        signals,
        value_plane,
        closure,
        P.load_proven_eoa_entities(session, protocol_id),
        P.discovery_relation_entities(session, protocol_id),
        composed_signals,
        ceiling_signals,
        unanswered_signals={_signal_identity(signal) for signal in stale_inputs},
    )

    perimeter, perimeter_detail = P.perimeter_state(session, protocol_id)
    provenance: dict[str, Any] = {
        "plane_row_counts": P.plane_row_counts(session, protocol_id),
        "population": {
            "signals": len(signals),
            "signals_entering_grade": sum(1 for s in signals if s.enters_grade),
            "findings": len(findings),
            "subsumed_rows": len(subsumed),
            # Distinguishes un-analysed from fully undetermined, which both read as grade_state=not_determined.
            "disposition": _population_disposition(signals, findings),
            "rows_withheld_malformed": len(row_faults),
            # Signals that entered the grade but created no row, so they aren't found only by subtraction.
            "rows_uncharged_product": uncharged_product_rows,
        },
        "value": value_plane.provenance,
        "value_annotations": value_plane.annotations,
        # Each closure admission rule counted whether or not it fired; a refusal and an earned negative are different
        # facts.
        "closure_admission": {
            "refusals": closure.refusal_counts(),
            "renounced": closure.renounced_counts(),
            "controller_enumeration_not_determined": dict(closure.controllers_not_determined),
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
        # What bounds reach hops, and where the bound couldn't be established.
        "reach_bounds": {
            "code_control_capabilities": sorted(K.CODE_CONTROL_CAPABILITIES),
            "gate_control_capabilities": sorted(K.GATE_CONTROL_CAPABILITIES),
            "caller_conditions": conditions.provenance,
            "gate_conferral": conferral.provenance,
            "act_as_composition": {**act_as.provenance, "census": composition_census},
            "hop_census": _hop_census(closure, conditions, conferral),
            "reading": (
                "code control expands over the whole closure of the controlled node — owning "
                "the code exercises everything the code is authorized to exercise. Gate control "
                "expands only through edges it passes a test on, and the test is no longer the "
                "label-presence test that walked any edge whose label named a scope at all. The "
                "two scope kinds are tested differently and the two tests are not equally strong. "
                "A `roles N` edge is walked where function_principals.details.trace[].selector, "
                "joined to effective_functions.selector at the destination, names the functions "
                "role N licenses there — a positive witness of what the hop delivers, published "
                "per finding as reach_licensed_functions. A state-variable edge is tested by a "
                "SAME-KIND BOUND, which is weaker and is not a conferral witness: the gate's own "
                "function is observed (effective_functions.state_writes, origin=body) to rewrite "
                "a variable of that name on ITS contract, while the edge's label names the "
                "authority slot on the DESTINATION's, so the match is a name match across two "
                "contracts' storage and witnesses no composition step. What it does is REFUSE "
                "hops whose authority is of a different kind from the one the gate seizes "
                "('hook', 'vault', 'roleRegistry'); the same-kind hops that survive it walk on no "
                "more evidence than the label-presence test gave them. A refused hop is NOT "
                "disproved: whether it composes anyway turns on the intermediate node's own "
                "function surface, and this plane DOES NOT CONSULT IT — a refusal here is "
                "therefore a join not performed, and nothing in it says the surface that would "
                "answer the question is absent. The join that would decide it is the intermediate "
                "node's own functions against its outbound targets "
                "(effective_functions.sinks/effect_targets and the external_call_target edges "
                "CONTROL_RELATIONS excludes). Until it runs the hop is withheld as "
                "not_determined. That join NOW RUNS, under act_as_composition, and it is worth "
                "being exact about what it decides: it bounds the MAGNITUDE of a licensed hop, "
                "not the membership of the walk. A hop with no act-as witness is still walked as "
                "reach — the licence witnessed it — and simply carries no composed dollars. "
                "Widening the reach on the same join is a separate change nobody has argued for "
                "here. Both classes are bounded by the destination's own caller "
                "conditions. Every hop neither class could establish is published per finding as "
                "reach_hops_not_determined, never dropped, and reach_withheld_behind_hops sizes "
                "the subtree each withheld frontier hop hides"
            ),
        },
        "unpriced_positions": value_plane.unpriced_positions,
        "exposure_gaps": exposure_gaps,
        # How much of the perimeter ``grade_exposure`` covers, so the ratio isn't read as a safety measurement.
        "exposure_coverage": exposure_coverage,
        # The sheet-ceiling dollars held out of exposure, rolled up so grade readers can see what was bounded and not
        # charged. The credited-signal count is the confidence pass's own.
        "sheet_ceilings": _sheet_ceiling_totals(
            findings,
            subsumed,
            confidence["reach_magnitude_signals"]["sheet_ceiling_by_capability"],
        ),
        "unresolved_levers": _unresolved_levers(findings),
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

    # The grade figures stand or fall together: with findings but no priced denominator, or with signals whose
    # principal set is gone or not proven whole, derived numbers go to provenance instead of beside a withheld grade.
    partial_inputs = _partial_principal_inputs(signals)
    withheld_basis: str | None = None
    withheld_signals: list[FunctionSignal] = []
    if stale_inputs:
        warnings.append(_stale_inputs_warning(stale_inputs))
        withheld_basis, withheld_signals = GRADE_WITHHELD_STALE_INPUTS, stale_inputs
    elif partial_inputs:
        withheld_basis, withheld_signals = GRADE_WITHHELD_PARTIAL_PRINCIPAL_SETS, partial_inputs
    elif findings and grade_exposure is None:
        withheld_basis = GRADE_WITHHELD_EXPOSURE_UNPRICED
    scored = bool(findings) and withheld_basis is None
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
        if withheld_basis is not None:
            provenance["grade_withheld"] = {
                "grade_lambda_computed": grade_lambda,
                "confidence_pct_computed": confidence.pop("pct", None),
                "exposure_usd_computed": exposure_usd,
                "per_finding": withheld_rows,
                "basis": withheld_basis,
                "reason": _WITHHELD_REASONS[withheld_basis].format(signals=len(withheld_signals)),
            }
            if withheld_signals:
                provenance["grade_withheld"]["withheld_by_signals"] = [
                    {
                        "entity": entity_key(s.chain, s.deployment_address),
                        "function": s.function_name,
                        "capability": s.claim_id,
                    }
                    for s in withheld_signals
                ]
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
        execution_evidence_faults=execution_faults,
    )


class _UnitResolver:
    """Principal units per (chain, address), with two collapses: Safes that can act as each other (enough shared
    owners) are one unit, and a timelock whose proposer-executor is a Safe folds into that Safe
    (upgrade-by-timelock is a subset of exec-by-proposer). Both halves must be proven, and neither crosses chains.
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
        # Last row wins (which contradictory owner set to use is an open ruling), but disagreement is published.
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
        self.proposers_not_determined: dict[str, list[str]] = {}
        # The weakest proven proposer-executor of a timelock whose entry is withheld: its price is a floor, never
        # undercut by the undetermined rung.
        self._proposer_floors: dict[str, dict[str, Any]] = {}
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
                # An unread threshold can't license a merge.
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
        """The weakest principal proven able to both propose and execute on each timelock; propose-only doesn't let it
        act as the timelock.

        A proposer-executor whose own weakness isn't proven (no row, an unread Safe owner set, a contract or an unknown
        type) could be the weakest path, so its timelock gets no entry and is recorded in
        ``proposers_not_determined``.
        """
        by_role: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"schedule": set(), "execute": set()})
        facts_by_key: dict[str, P.PrincipalFacts | None] = {}
        for signal in sorted(signals, key=lambda s: (s.chain, s.deployment_address, s.selector, s.claim_id)):
            role = {C.TIMELOCK_SCHEDULE: "schedule", C.TIMELOCK_EXECUTE: "execute"}.get(signal.claim_id)
            if role is None:
                continue
            timelock_key = entity_key(signal.chain, signal.deployment_address)
            for ref in signal.principal_refs:
                facts = self._facts.get(int(ref.function_principal_id))
                key = facts.key if facts is not None else entity_key(ref.chain, ref.address)
                by_role[timelock_key][role].add(key)
                if facts is not None or key not in facts_by_key:
                    facts_by_key[key] = facts

        out: dict[str, dict[str, Any]] = {}
        for timelock_key in sorted(by_role):
            both = sorted(by_role[timelock_key]["schedule"] & by_role[timelock_key]["execute"])
            entries: list[dict[str, Any]] = []
            unpriced: list[str] = []
            for key in both:
                entry = _proposer_entry(facts_by_key.get(key))
                if entry is None:
                    unpriced.append(key)
                else:
                    entries.append(entry)
            if unpriced:
                self.proposers_not_determined[timelock_key] = unpriced
                if entries:
                    self._proposer_floors[timelock_key] = min(entries, key=_proposer_rank)
            elif entries:
                # Weakest path. Within one weakness rung an unread threshold sorts first, then the smaller k/n, then the
                # key, so the published proposer is stable.
                out[timelock_key] = min(entries, key=_proposer_rank)
        return out

    def unit_for(self, facts: P.PrincipalFacts) -> str:
        key = facts.key
        if facts.resolved_type == "timelock":
            proposer = self._proposers.get(key)
            if proposer:
                key = str(proposer["key"])
        if key in self._parent:
            # Named by the lowest member key, not the union-find root, for stable identities.
            root = self._find(key)
            members = {member for member in self._parent if self._find(member) == root}
            unit = min(members)
            self._members[unit] |= members
            return unit
        self._members[key].add(key)
        return key

    def published_units(self) -> dict[str, Any]:
        """The unit memberships folded, so consumers can check the collapse."""
        return {
            "members": {unit: sorted(members) for unit, members in sorted(self._members.items())},
            "timelock_collapses": {
                timelock: {
                    "into": entry["key"],
                    "proposer_kind": entry["kind"],
                    "proposer_k_of_n": (
                        "not_applicable"
                        if entry["kind"] == "eoa"
                        else f"{entry['k']}/{entry['n']}"
                        if entry["k"] is not None
                        else "not_determined"
                    ),
                    "basis": "proven proposer AND executor",
                }
                for timelock, entry in sorted(self._proposers.items())
            },
            "timelock_proposers_not_determined": {
                timelock: {
                    "principals": keys,
                    "basis": "a proposer-executor whose own weakness is not proven could be the weakest path",
                }
                for timelock, keys in sorted(self.proposers_not_determined.items())
            },
            "owner_set_contradictions": self.owner_set_contradictions,
        }

    def proposer_for(self, facts: P.PrincipalFacts) -> dict[str, Any] | None:
        return self._proposers.get(facts.key)

    def path_for(self, facts: P.PrincipalFacts) -> str:
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
            # An EOA controlling the gating contract isn't an EOA calling the function; a confidence fact only.
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
        unpriced = self.proposers_not_determined.get(facts.key)
        if unpriced:
            notes.append("timelock_proposer_weakness_not_determined:" + ",".join(unpriced))
        if proposer is not None and proposer["credit_withheld"]:
            notes.append(f"safe_kn_credit_withheld:{proposer['protection_basis']}")
        floor = proposer or self._proposer_floors.get(facts.key)
        if discount is None:
            notes.append("timelock_delay_not_determined")
            return (
                self._floored(K.WEAKNESS_TIMELOCK_UNDETERMINED, floor, 1.0, notes),
                "timelock(delay not_determined)",
                notes,
            )
        delay_seconds = float(facts.delay_seconds) if facts.delay_seconds is not None else 0.0
        days = int(delay_seconds // 86400)
        if delay_seconds == 0:
            # A proven zero delay is proven-absent protection.
            notes.append("timelock_delay_proven_zero:no_protection")
            if proposer is None:
                return (
                    self._floored(K.WEAKNESS_SAFE_UNCREDITED, floor, 1.0, notes),
                    "timelock(0d, proposer not_determined)",
                    notes,
                )
            notes.append(f"proposer={_kn(proposer)}")
            return proposer["weakness"], f"timelock 0d via {_kn(proposer)}", notes
        if proposer is None:
            # Undetermined proposer-executors earn no delay credit.
            notes.append("timelock_proposer_not_determined:no_delay_credit")
            return (
                self._floored(K.WEAKNESS_TIMELOCK_UNDETERMINED, floor, discount, notes),
                f"timelock {days}d(proposer not_determined)",
                notes,
            )
        notes.append(f"delay_discount={discount};proposer={_kn(proposer)}")
        return round(proposer["weakness"] * discount, 4), f"timelock {days}d via {_kn(proposer)}", notes

    @staticmethod
    def _floored(weakness: float, floor: dict[str, Any] | None, discount: float, notes: list[str]) -> float:
        """An undetermined rung never reads safer than a proposer-executor proven to be there."""
        if floor is None:
            return weakness
        proven = round(floor["weakness"] * discount, 4)
        if proven <= weakness:
            return weakness
        notes.append(f"weakest_proven_proposer_floor={_kn(floor)}:{proven}")
        return proven

    def _role_breadth(self, facts: P.PrincipalFacts) -> float | None:
        """A proven holder floor above one is breadth; it only raises."""
        for registry, role_hash in facts.role_bindings:
            entry = self._role_floors.get((facts.chain, registry, role_hash))
            if entry and entry["holders_floor"] > 1:
                return K.ROLE_BREADTH_MULTI_HOLDER_WEAKNESS
        return None


def _kn(proposer: dict[str, Any]) -> str:
    """A proposer's k/n, or a refusal; never a fabricated ratio."""
    if proposer["kind"] == "eoa":
        return "EOA"
    return f"{proposer['k']}/{proposer['n']}" if proposer["k"] is not None else "k not_determined"


def _proposer_rank(entry: dict[str, Any]) -> tuple[float, int, float, str]:
    k, n = entry["k"], entry["n"]
    ratio = 0.0 if k is None or not n else k / n
    return (-entry["weakness"], 0 if k is None else 1, ratio, entry["key"])


def _proposer_entry(facts: P.PrincipalFacts | None) -> dict[str, Any] | None:
    """A timelock proposer-executor priced as itself, or ``None`` where its own weakness isn't proven."""
    if facts is None:
        return None
    if facts.resolved_type == "eoa":
        return {
            "key": facts.key,
            "kind": "eoa",
            "k": None,
            "n": None,
            "weakness": K.WEAKNESS_EOA,
            "credit_withheld": False,
        }
    if facts.resolved_type == "safe" and facts.owners:
        return {
            "key": facts.key,
            "kind": "safe",
            "k": facts.threshold,
            "n": len(facts.owners),
            "weakness": K.quorum_weakness(
                facts.threshold, len(facts.owners), credit_withheld=facts.protection_credit_withheld
            ),
            "credit_withheld": facts.protection_credit_withheld,
            "protection_basis": facts.protection_basis,
        }
    return None


def _safe_weakness(
    facts: P.PrincipalFacts, notes: list[str], recovery_proven_independent: bool
) -> tuple[float, str, list[str]]:
    """A Safe's weakness from proven k and n, else the uncredited rung (backfilling n from k would fabricate a k-of-k
    Safe).
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

    @dataclass(frozen=True)
    class _Ref:
        function_principal_id: int
        chain: str
        address: str

    out: list[Any] = []
    for signal in signals:
        # Repeats the malformed check, since this runs first.
        if signal.claim_id != C.PAUSE_SET or _malformed_gates(signal):
            continue
        gate = _gate(signal, "freeze_recovery_principals")
        if not gate.is_determined or not isinstance(gate.value, list):
            continue
        for entry in gate.value:
            if _is_principal_ref(entry):
                out.append(
                    _Ref(
                        function_principal_id=int(entry["function_principal_id"]),
                        # Same contract as the pause signal, so the same chain.
                        chain=str(entry.get("chain") or signal.chain),
                        address=str(entry.get("address") or ""),
                    )
                )
    return out


def _fold_severity(
    signal: FunctionSignal,
    principal: P.PrincipalFacts | None,
    principal_facts: dict[int, P.PrincipalFacts],
    warnings: list[dict[str, Any]],
) -> tuple[float, tuple[str, ...], set[str]]:
    """Distilled severity plus fold-only components, per principal: recoverability compares the freezing key set with
    the recovery key set.
    """
    severity = signal.severity.require(SEVERITY_STATE_PROVEN)
    basis = tuple(signal.severity_basis)
    notes: set[str] = set()
    if signal.claim_id != C.PAUSE_SET or principal is None:
        return severity, basis, notes

    verdict, coalition, note = _keyset_independence(signal, principal, principal_facts)
    if verdict is False:
        # Proven: this key set can freeze and deny the recovery quorum.
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
        # Undetermined arms leave the rung where it was and publish the question.
        notes.add(note)
        basis = basis + ("freeze_recovery_independence_not_determined",)
        warnings.append(_warning("freeze_recovery_independence_not_determined", signal, note))
    else:
        # Proven independence: credited rung (currently equal to existence), changing the basis only.
        severity = min(severity, K.FREEZE_KEYSET_RECOVERABLE)
        notes.add(note)
        basis = basis + ("freeze_keyset_independent",)
    return severity, basis, notes


def _keyset_independence(
    signal: FunctionSignal, principal: P.PrincipalFacts, principal_facts: dict[int, P.PrincipalFacts]
) -> tuple[bool | None, int | None, str]:
    """Whether the recovery quorum is key-independent of the freezing one: ``|owners(U) \\ owners(P)| >=
    threshold(U)``.

    Addresses only stand in for key sets for EOAs; unread owner sets make it uncomputable, not favourable.
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


def _instance(
    signal: FunctionSignal, severity: float, basis: tuple[str, ...], principal_address: str = ""
) -> _Instance:
    magnitude = _gate(signal, "reach_magnitude_usd")
    pricing_blocked = None
    native_only = False
    asset_identity_undecidable = False
    if signal.claim_id == C.FLOW_OUT:
        if _gate(signal, "token_identity").is_determined:
            # One non-fungible token moves; pricing it from a fungible sheet is forbidden.
            pricing_blocked = "token_identity(non-fungible; pricing forbidden)"
        asset_class = _gate(signal, "asset_class")
        native_only = asset_class.is_determined and asset_class.value == "native_only"
        # Single-asset pricing needs a decidable token identity; otherwise unpriced.
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
    # The burn address is refused as a reach key.
    kept = tuple(key for key in instance.entity_keys if not P.is_zero_key(key))
    if len(kept) != len(instance.entity_keys):
        row.zero_reach_keys_refused += len(instance.entity_keys) - len(kept)
        row.notes.add("zero_address_reach_key_refused")
        if not kept:
            # Every reach key was the sentinel, so it witnesses nothing; recorded rather than read as proven no reach.
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
    row: _Row,
    per_entity: dict[str, float],
    value_plane: P.ValuePlane,
    closure: P.ControlClosure,
    conditions: P.ConditionPlane,
    conferral: P.ConferralPlane,
    act_as: P.ActAsPlane,
    magnitudes: dict[tuple[str, str], _DestinationMagnitude],
    admission: _AdmissionPlanes,
) -> tuple[dict[str, float], float, tuple[str, str, str]]:
    """A merged unit's weakness per reached entity: each entity priced at the max over only members proven to reach
    it, and the row's union at the hardest (min) of those rungs. Not the overlap record's coalition size (keyed on
    k, not k/n). Unattributable instances keep the unit-level rung.
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
        # Reach is read from ``.reach``, not the value map (magnitude caps can empty the value map without changing
        # reach).
        reached = _row_value(probe, value_plane, closure, conditions, conferral, act_as, magnitudes, admission).reach
        reach_by_member[address] = reached

    weakness_by_entity: dict[str, float] = {}
    holders_by_entity: dict[str, list[str]] = {}
    for key in sorted(per_entity):
        holders = sorted(a for a, reached in reach_by_member.items() if key in reached)
        if not holders:
            # An entity no single member reaches: keep the unit rung rather than guess.
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


CITATION_CAP = 8


# Citations that point at evidence; others are restatements or prose.
_CITATION_EVIDENCE_KEYS = ("transcript_ptr", "verdict", "block_source")


def _cited(citations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Citations, evidence first, capped for display; stable within tiers (a prose reading once evicted transcript
    pointers).
    """

    def rank(citation: dict[str, Any]) -> int:
        if not isinstance(citation, dict):
            return 1
        if any(key in citation for key in _CITATION_EVIDENCE_KEYS):
            return 0
        return 2 if "reading" in citation else 1

    return sorted(citations, key=rank)[:CITATION_CAP]


def _aggregate(
    rows_by_key: dict[tuple[str, str, str], _Row],
    value_plane: P.ValuePlane,
    closure: P.ControlClosure,
    conditions: P.ConditionPlane,
    conferral: P.ConferralPlane,
    act_as: P.ActAsPlane,
    magnitudes: dict[tuple[str, str], _DestinationMagnitude],
    admission: _AdmissionPlanes,
    units: _UnitResolver,
    composed_signals: set[tuple[Any, ...]],
    ceiling_signals: set[tuple[Any, ...]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    warnings: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for key in sorted(rows_by_key):
        row = rows_by_key[key]
        if not row.instances:
            continue
        valued = _row_value(row, value_plane, closure, conditions, conferral, act_as, magnitudes, admission)
        composed_signals.update(valued.composed_signals)
        # Kept apart from the composed set: different evidence answered the magnitude question.
        ceiling_signals.update(valued.ceiling_signals)
        per_entity, value_usd, undetermined = valued.per_entity, valued.total_usd, valued.undetermined
        value_basis = valued.basis
        if row.zero_reach_stripped:
            undetermined = undetermined + row.zero_reach_stripped
            value_basis += f"; {len(row.zero_reach_stripped)} instance(s) reached only the refused zero address"
        # An entity with unpriced assets makes the total a floor.
        partially_priced = _partially_priced_entities(value_plane, valued.reach)
        # Direction reads coverage and attribution together.
        direction = _bound_direction(
            value_usd,
            frozenset(per_entity),
            valued.ceiling_entities,
            bool(undetermined or partially_priced),
            # Always a dict; read its counts.
            bool(
                valued.hops_not_determined
                or valued.withheld_behind_hops.get("hops")
                or valued.withheld_behind_hops.get("entities")
            ),
            valued.non_attributed_entities,
        )
        # Only rows with a total and a graded entity get a direction basis, written here where both axes are known.
        if valued.ceiling_entities:
            value_basis = _ceiling_bearing_basis(
                direction,
                per_entity,
                valued.ceiling_entities - valued.sheet_ceiling_entities,
                valued.sheet_ceiling_entities,
                undetermined,
                partially_priced,
                valued.proven_no_reach,
                row.zero_reach_stripped,
                valued.hops_not_determined,
                valued.withheld_behind_hops,
                valued.composed_magnitudes,
                value_plane,
            )
        elif value_usd is not None and (undetermined or partially_priced):
            value_basis = _coverage_bearing_basis(
                direction,
                per_entity,
                undetermined,
                partially_priced,
                valued.non_attributed_entities,
                valued.proven_no_reach,
                row.zero_reach_stripped,
            )
        is_floor = direction == BOUND_DIRECTION_FLOOR
        weakness_by_entity, weakness, weakest = _member_weakness(
            row, per_entity, value_plane, closure, conditions, conferral, act_as, magnitudes, admission
        )
        severity = max(instance.severity for instance in row.instances)
        band = K.band(value_usd)
        unresolved = _unresolved_stake(
            undetermined,
            valued.withheld_behind_hops,
            set(per_entity),
            value_plane,
            hops_not_determined=valued.hops_not_determined,
        )
        # Points at the unresolved ceiling (proven severity x weakness x the ceiling's band); never in lambda. A
        # proven-$0 ceiling bounds at zero; an unbounded one bounds nothing.
        ceiling_usd = unresolved["ceiling_usd"]
        if ceiling_usd is None:
            unresolved["points_ceiling"] = None
        elif ceiling_usd == 0.0:
            unresolved["points_ceiling"] = 0.0
        else:
            unresolved["points_ceiling"] = round(K.SEV_SCALE * severity * weakness * K.band(ceiling_usd), 4)
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
                # The principal that set the weakness.
                "principal": f"{weakest[0]} {weakest[2]}",
                "access_path": row.path,
                "principal_addresses": sorted(row.principal_addresses),
                "principal_kind": weakest[1],
                "capability": row.capability,
                "chain": row.unit.split("::", 1)[0],
                # The total and per-entity figures share the ceiling records' rounding (``_round_published``), so
                # sub-cent entities aren't shown as "$0.00 at stake". Graded values use unrounded figures, but
                # ``value_by_entity`` feeds exposure in ``_grade``; sheet ceilings are held out of exposure, and
                # elsewhere the change can only raise exposure, never improve the grade.
                "value_at_stake_usd": (_round_published(value_usd) if value_usd is not None else None),
                "value_state": (VALUE_STATE_PROVEN_REACH if value_usd is not None else NOT_DETERMINED),
                "value_by_entity": {k: _round_published(v) for k, v in sorted(per_entity.items())},
                "value_at_stake_basis": value_basis,
                # Which way the total bounds the principal (a sum of composed ceilings isn't an at-least);
                # ``not_determined`` unless proven.
                "value_at_stake_bound_direction": direction,
                # Derived: true only where the direction is a floor.
                "value_at_stake_is_floor": is_floor,
                # Entities priced from a composed ceiling, named; separate from sheet ceilings (different claims, only
                # one spends exposure).
                "entities_priced_from_a_composed_ceiling": sorted(
                    valued.ceiling_entities - valued.sheet_ceiling_entities
                ),
                # Entities priced from their own sheet (replaced code); disjoint from the composed list.
                "entities_priced_from_a_sheet_ceiling": sorted(valued.sheet_ceiling_entities),
                # The composed refusals, so an empty ceiling list isn't confused with never composing.
                "entities_withheld_from_a_composed_ceiling": [
                    {
                        "entity": record.entity,
                        "selector": record.selector,
                        "arm_taken": record.arm,
                        "withheld_reason": record.reason,
                        "authority_deletability_state": record.deletability.state,
                        "authority_deletability_reason": record.deletability.reason,
                    }
                    for record in valued.withheld_composed_magnitudes
                ],
                "entities_holding_unpriced_assets": partially_priced,
                "value_band": (
                    (_BAND_PREFIX.get(direction, "") + K.band_label(value_usd))
                    if value_usd is not None
                    else NOT_DETERMINED
                ),
                "undetermined_instances": undetermined,
                "proven_no_reach_instances": valued.proven_no_reach,
                "witnessed_magnitude_caps": valued.magnitude_caps,
                # A floor witness the sheet couldn't bound; the figure stands alone.
                "unbounded_floor_magnitudes": valued.unbounded_floor_magnitudes,
                # Dollars from a destination function's own flow.out witness, with the licensing act-as chain.
                "reach_composed_magnitudes": [
                    entry.as_json() for _, entry in sorted(valued.composed_magnitudes.items())
                ],
                # Candidates that cleared the witnesses but lost their figure to the three-arm rule: gate claim,
                # execution record and refusal, no dollars.
                "reach_composed_magnitudes_withheld": [
                    record.as_json() for record in valued.withheld_composed_magnitudes
                ],
                # Sheet ceilings per entity. Proven by a balance observation, not a call, so ``proving_execution`` is
                # ``not_determined`` under a registered non-fault reason.
                "reach_sheet_ceiling_magnitudes": _sheet_ceiling_records(
                    valued.sheet_ceiling_entities, per_entity, value_plane, row.capability
                ),
                # Ceiling labels withheld because the figure didn't reconcile with the sheet; the dollars stand,
                # ungraded, and charge exposure.
                "reach_sheet_ceiling_magnitudes_withheld": valued.sheet_ceilings_withheld,
                "reach_composition_census": valued.composition_census,
                # Calls capped by a witness, witnessed within bound, and never witnessed, so unwitnessed calls aren't
                # read as checked.
                "magnitude_witness_census": {
                    **valued.magnitude_census,
                    "reading": (
                        "magnitude_not_witnessed is the population whose dollar figure is "
                        "not_determined and whose weight therefore sits at the unpriced band's "
                        "floor: no witness proved how much this reach moves, so nothing is "
                        "published as if one had. magnitude_composed is counted apart from both "
                        "— those calls carry no witness of their own and were priced on the "
                        "DESTINATION function's, itemised under reach_composed_magnitudes. "
                        "magnitude_sheet_ceiling is the third answer and is counted apart from "
                        "all of them: those calls carry no witness of their own either and were "
                        "priced from the CONTROLLED NODE's own sheet, which bounds them from "
                        "above rather than measuring them, itemised under "
                        "reach_sheet_ceiling_magnitudes. "
                        "within_witnessed_bound means a witness exists "
                        "and did not have to trim; it is not the same fact as no witness. "
                        "hops_not_determined counts every hop this row could not establish, of "
                        "which hops_not_determined_withholding_reach are the ones no other path "
                        "reached anyway — the rest bound nothing and are listed nowhere"
                    ),
                },
                # Hops established neither way, deduped by (caller, destination).
                "reach_hops_not_determined": valued.hops_not_determined,
                "zero_address_reach_keys_refused": row.zero_reach_keys_refused,
                # Filled after sorting; null is the proven "nothing tied".
                "exposure_order_tie": None,
                "severity_proven": round(severity, 4),
                "severity_basis": sorted({b for instance in row.instances for b in instance.severity_basis}),
                "weakness": round(weakness, 4),
                "weakest_gate": weakest[0],
                # Present only where a merged unit's members reach entities at different rungs.
                "weakness_by_entity": {k: round(v, 4) for k, v in sorted(weakness_by_entity.items())},
                "raw_points": round(K.SEV_SCALE * severity * weakness * band, 4),
                "n_functions": len({(i.signal.deployment_address, i.signal.selector) for i in row.instances}),
                "n_entities": len(row.seeds),
                # Deployments the instances were witnessed on, distinct from the reach closure (membership, not filtered
                # by pricing).
                "host_entities": sorted(row.seeds),
                "reach_entities": sorted(valued.reach),
                # What the walked gate hops license per destination (canonical keys, ``{selector, name}``). A reached
                # entity absent here was reached through a hop naming no function.
                "reach_licensed_functions": valued.licensed_functions,
                # The size of what withheld hops hide.
                "reach_withheld_behind_hops": valued.withheld_behind_hops,
                # The at-most behind unanswered questions; outside lambda and exposure.
                "unresolved_stake": unresolved,
                # Proven actor and act, unsized consequence; lambda unchanged.
                "partial_proof": bool(unresolved["entities_total"]),
                "example_functions": sorted({i.signal.function_name for i in row.instances})[:6],
                "witness_tiers": sorted(row.tiers),
                "witness_notes": sorted(row.notes),
                "citations": _cited(row.citations),
                # The display cap's total, so the slice isn't read as everything.
                "citations_total": len(row.citations),
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
        # Subsumption removes points, not reach: value only a subsumed row names still enters exposure, at that row's
        # own fraction. A sheet ceiling isn't occupancy (the top row charges nothing there).
        occupied = set(top["value_by_entity"]) - set(top["entities_priced_from_a_sheet_ceiling"])
        exclusive: dict[str, dict[str, float]] = {}
        # Exclusive keys that arrived as a subsumed row's sheet ceiling, so they stay out of the budget like the top
        # row's own.
        exclusive_ceilings: set[str] = set()
        for row in rest:
            per_entity_weakness = row["weakness_by_entity"]
            row_ceilings = set(row["entities_priced_from_a_sheet_ceiling"])
            for key, held in row["value_by_entity"].items():
                if key in occupied:
                    continue
                fraction = row["severity_proven"] * per_entity_weakness.get(key, row["weakness"])
                previous = exclusive.get(key)
                if previous is None or held * fraction > previous["usd"] * previous["fraction"]:
                    exclusive[key] = {"usd": held, "fraction": round(fraction, 6)}
                    exclusive_ceilings.discard(key)
                    if key in row_ceilings:
                        exclusive_ceilings.add(key)
        top["subsumed_exclusive_value_by_entity"] = dict(sorted(exclusive.items()))
        # Published because the exposure loop needs it and readers look for it.
        top["subsumed_exclusive_sheet_ceiling_entities"] = sorted(exclusive_ceilings)
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


def _row_value(
    row: _Row,
    value_plane: P.ValuePlane,
    closure: P.ControlClosure,
    conditions: P.ConditionPlane,
    conferral: P.ConferralPlane,
    act_as: P.ActAsPlane,
    magnitudes: dict[tuple[str, str], _DestinationMagnitude],
    admission: _AdmissionPlanes,
) -> _RowValue:
    """Value at stake for one row: MAX per entity, never SUM.

    A dollar figure needs a magnitude witness (the sheet says what is there, not what can move), and one call's
    magnitude caps that call across all its keys.

    Reach is bounded by capability class (code control expands over the controlled node's closure; gate control only
    through conferred edges) and by destinations not pinning their caller to themselves. Without its own magnitude
    witness, a gate may reuse the destination function's (:func:`_compose`), capped at that witness and the
    destination's sheet. Conferral uses each instance's own function grant.
    """
    per_entity: dict[str, float] = {}
    # Standing-figure entities that bound from above, and which kind of ceiling; only knowable where the figure is
    # chosen.
    ceiling_kinds: dict[str, str] = {}
    non_attributed_entities: set[str] = set()
    reached: set[str] = set()
    undetermined: list[dict[str, Any]] = []
    proven_no_reach: list[dict[str, Any]] = []
    magnitude_caps: list[dict[str, Any]] = []
    unbounded_floors: list[dict[str, Any]] = []
    # All candidates per entity, so ties can be seen and published.
    composition_candidates: dict[str, list[_ComposedMagnitude]] = {}
    composition_census: dict[str, int] = {}
    composition_refusals: dict[str, int] = defaultdict(int)
    # Composed candidates whose figure the three-arm rule refused, keyed by call.
    withheld_composed: dict[tuple[str, str], _WithheldComposition] = {}
    composed_signals: set[tuple[Any, ...]] = set()
    # Signals whose sheet ceiling is the standing figure per entity, so a replaced figure loses its credit.
    ceiling_signals_by_entity: dict[str, set[tuple[Any, ...]]] = {}
    hops: dict[tuple[str, str], dict[str, Any]] = {}
    licensed: dict[str, set[P.LicensedFunction]] = defaultdict(set)
    census: dict[str, Any] = dict.fromkeys(
        (
            "instances",
            "magnitude_witnessed",
            "magnitude_composed",
            "magnitude_sheet_ceiling",
            "magnitude_not_witnessed",
            "capped",
            "within_witnessed_bound",
        ),
        0,
    )
    code_control = row.capability in K.CODE_CONTROL_CAPABILITIES
    transitive = code_control or row.capability in K.GATE_CONTROL_CAPABILITIES

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
            # Reach witnessed and reached nothing: an earned negative.
            proven_no_reach.append(
                {"function": instance.signal.function_name, "entity": entity, "basis": instance.signal.value_basis}
            )
            continue
        if instance.signal.value_state != VALUE_STATE_PROVEN_REACH:
            # No witnessed reach contributes no seed.
            undetermined.append(
                {"function": instance.signal.function_name, "entity": entity, "why": instance.signal.value_basis}
            )
            continue

        keys = set(instance.entity_keys)
        composed: dict[str, _ComposedMagnitude] = {}
        if transitive:
            grant = (
                None
                if code_control
                else conferral.grant_for(
                    instance.signal.claim_id,
                    instance.signal.function_id,
                    entity=entity,
                    selector=instance.signal.selector,
                )
            )
            seeds = set(keys)
            keys, withheld, licensed_here, walked_hops = _closure(keys, closure, conditions, grant=grant)
            for hop in withheld:
                hops.setdefault((hop["caller"], hop["destination"]), hop)
            # Canonical keys, matching ``reached``, so folded destinations join.
            for destination, functions in licensed_here.items():
                licensed[value_plane.canonical(destination)].update(functions)
            if not code_control:
                # Code control asks no conferral question, so it has no compositional source.
                composed, counts, refused, refused_entries = _compose(
                    seeds,
                    walked_hops,
                    act_as,
                    magnitudes,
                    value_plane,
                    conditions,
                    admission,
                    row.principal_addresses,
                )
                for record in refused_entries:
                    # One refusal per (entity, selector).
                    withheld_composed.setdefault((record.entity, record.selector), record)
                _pool_composed(composition_candidates, composed)
                for name, count in counts.items():
                    composition_census[name] = composition_census.get(name, 0) + count
                for reason, hits in refused.items():
                    composition_refusals[reason] += hits
                if composed:
                    composed_signals.add(_signal_identity(instance.signal))
        # Reach is membership, witnessed here; it can't be read from the value map, which drops undetermined entities.
        reached.update(value_plane.canonical(key) for key in keys)
        contributions, gaps, cap, unbounded, from_ceilings, non_attributed = _instance_contributions(
            instance, keys, value_plane, transitive=transitive, composed=composed
        )
        unbounded_floors.extend(unbounded)
        census["instances"] += 1
        if _witnessed_magnitude(instance) is None:
            # Composed and sheet-ceiling figures get their own counters (neither is a call's own witness nor missing).
            if from_ceilings and CEILING_KIND_SHEET in from_ceilings.values():
                census["magnitude_sheet_ceiling"] += 1
            else:
                census["magnitude_composed" if composed else "magnitude_not_witnessed"] += 1
        else:
            census["magnitude_witnessed"] += 1
            census["capped" if cap is not None else "within_witnessed_bound"] += 1
        undetermined.extend(gaps)
        if cap is not None:
            magnitude_caps.append(cap)
        for canonical, contribution in contributions.items():
            previous = per_entity.get(canonical)
            if previous is None or contribution > previous:
                per_entity[canonical] = contribution
                ceiling_kinds.pop(canonical, None)
                # The credit goes with the figure it proved.
                ceiling_signals_by_entity.pop(canonical, None)
                non_attributed_entities.discard(canonical)
            # Ties go to the weaker claim: a ceiling equal to a witnessed figure is still a ceiling.
            if canonical in from_ceilings and contribution >= per_entity[canonical]:
                ceiling_kinds[canonical] = from_ceilings[canonical]
                if from_ceilings[canonical] == CEILING_KIND_SHEET:
                    # Ties are common (several calls read the same sheet); only a ceiling strictly beaten loses credit.
                    ceiling_signals_by_entity.setdefault(canonical, set()).add(_signal_identity(instance.signal))
            # An attribution-derived tie also revokes the grade.
            if contribution >= per_entity[canonical]:
                if canonical in non_attributed:
                    non_attributed_entities.add(canonical)
                else:
                    non_attributed_entities.discard(canonical)

    # Reconcile every ceiling label against its sheet, per key.
    sheet_ceilings_withheld = _reconcile_sheet_ceilings(ceiling_kinds, per_entity, value_plane)
    for record in sheet_ceilings_withheld:
        ceiling_signals_by_entity.pop(record["entity"], None)

    # One selection over every candidate, so the published details come from the chosen candidate.
    composition = {key: _select_composed(pool) for key, pool in sorted(composition_candidates.items())}
    # Reapply the rule to the published selection (a no-op today, kept so the published entry is always the one the rule
    # saw).
    composition, refused_again = _admit_composed(
        composition, principal_addresses=row.principal_addresses, planes=admission
    )
    for record in refused_again:
        withheld_composed.setdefault((record.entity, record.selector), record)
    refused_composed: dict[str, int] = defaultdict(int)
    for record in withheld_composed.values():
        refused_composed[record.counter_key] += 1
    hop_gaps = [hops[pair] for pair in sorted(hops) if value_plane.canonical(pair[1]) not in reached]
    census["hops_not_determined"] = len(hops)
    census["hops_not_determined_withholding_reach"] = len(hop_gaps)
    withheld_behind = _behind_the_frontier(hop_gaps, closure, conditions, value_plane, reached)
    licensed_out = {key: [fn.as_json() for fn in sorted(rows)] for key, rows in sorted(licensed.items())}
    refusals_out = dict(sorted(refused_composed.items()))
    withheld_out = tuple(withheld_composed[key] for key in sorted(withheld_composed))
    # Counted over republished and withheld entries alike.
    gate_claims = _counted(
        _gate_claim(entry.chain, entry.execution)["state"] for entry in (*composition.values(), *withheld_out)
    )
    composition_report = _composition_report(
        composition, composition_census, dict(composition_refusals), withheld_out, refusals_out, gate_claims
    )
    if not per_entity:
        basis = "proven_no_reach" if proven_no_reach and not undetermined else "not_determined"
        return _RowValue(
            per_entity,
            None,
            basis,
            undetermined,
            proven_no_reach,
            reached,
            magnitude_caps,
            hop_gaps,
            census,
            licensed_out,
            withheld_behind,
            unbounded_floors,
            composition,
            composition_report,
            frozenset(composed_signals),
            withheld_composed_magnitudes=withheld_out,
            refused_composed_magnitudes=refusals_out,
        )
    basis = (
        "witnessed reach magnitude over the "
        + ("code-control" if code_control else "gate-control")
        + " closure, MAX per entity"
        if transitive
        else "per-instance witnessed value, MAX per entity over latest-observation sheets"
    )
    # The gap doesn't decide direction alone; :func:`_coverage_bearing_basis` writes that sentence.
    if proven_no_reach:
        basis += f"; {len(proven_no_reach)} instance(s) proven_no_reach"
    # A sheet ceiling is capped by its node's sheet per key (checked per key, never on the total, which sums hosts and
    # can exceed any one sheet).
    total = round(sum(sorted(per_entity.values())), 6)
    return _RowValue(
        per_entity,
        total,
        basis,
        undetermined,
        proven_no_reach,
        reached,
        magnitude_caps,
        hop_gaps,
        census,
        licensed_out,
        withheld_behind,
        unbounded_floors,
        composition,
        composition_report,
        frozenset(composed_signals),
        ceiling_entities=frozenset(ceiling_kinds),
        sheet_ceiling_entities=frozenset(k for k, v in ceiling_kinds.items() if v == CEILING_KIND_SHEET),
        ceiling_signals=frozenset().union(*ceiling_signals_by_entity.values())
        if ceiling_signals_by_entity
        else frozenset(),
        sheet_ceilings_withheld=sheet_ceilings_withheld,
        non_attributed_entities=frozenset(non_attributed_entities),
        withheld_composed_magnitudes=withheld_out,
        refused_composed_magnitudes=refusals_out,
    )


def _composition_totals(findings: list[dict[str, Any]], subsumed: list[dict[str, Any]]) -> dict[str, Any]:
    """Every row's composition census summed to the protocol.

    Findings and subsumed rows are rolled up separately (a subsumed row usually repeats the same walk), though
    subsumed-only entities still enter the top row's exposure. Entities are distinct within each population; dollars sum
    per row, as they enter the grade.
    """

    # Per-row maxima don't sum.
    maxima = ("longest_composed_chain",)
    # Per-reason maps merge rather than sum.
    breakdowns = (
        "composed_withheld_by_deletability",
        "composed_withheld_by_arm",
        "composed_withheld_by_reason",
        "gate_claim_by_state",
    )

    def roll(rows: list[dict[str, Any]]) -> dict[str, Any]:
        totals: dict[str, int] = defaultdict(int)
        longest: dict[str, int] = dict.fromkeys(maxima, 0)
        refused: dict[str, int] = defaultdict(int)
        broken: dict[str, dict[str, int]] = {key: defaultdict(int) for key in breakdowns}
        entities: set[str] = set()
        withheld_entities: set[str] = set()
        usd = 0.0
        for row in rows:
            census = row.get("reach_composition_census") or {}
            for key, value in census.items():
                if key in ("reading", "act_as_refused", "composed", "composed_usd"):
                    continue
                if key in broken:
                    for token, hits in (value or {}).items():
                        broken[key][token] += int(hits)
                    continue
                if key in longest:
                    longest[key] = max(longest[key], int(value))
                    continue
                totals[key] += int(value)
            for reason, hits in (census.get("act_as_refused") or {}).items():
                refused[reason] += int(hits)
            for entry in row.get("reach_composed_magnitudes") or []:
                entities.add(str(entry["entity"]))
                usd += float(entry["published_usd"])
            for entry in row.get("reach_composed_magnitudes_withheld") or []:
                withheld_entities.add(str(entry["entity"]))
        return {
            **dict(sorted(totals.items())),
            **longest,
            "act_as_refused": dict(sorted(refused.items())),
            **{key: dict(sorted(rows_here.items())) for key, rows_here in broken.items()},
            "rows_composing": sum(1 for row in rows if row.get("reach_composed_magnitudes")),
            "rows_withholding_every_composed_figure": sum(
                1
                for row in rows
                if row.get("reach_composed_magnitudes_withheld") and not row.get("reach_composed_magnitudes")
            ),
            "entities_composed": len(entities),
            "entities_withheld": len(withheld_entities),
            "composed_usd_summed_over_rows": round(usd, 2),
        }

    # Counted rather than asserted in the sentence.
    exclusive: set[str] = set()
    for row in findings:
        exclusive.update(row.get("subsumed_exclusive_value_by_entity") or {})
    charged = sorted(
        exclusive.intersection(
            str(entry["entity"]) for row in subsumed for entry in (row.get("reach_composed_magnitudes") or [])
        )
    )
    charging = (
        f"and {len(charged)} composed subsumed entity(ies) do so here"
        if charged
        else "and no composed subsumed entity does so here — the fold looked, and the two "
        "populations do not meet on this corpus"
    )
    return {
        "findings": roll(findings),
        "subsumed_rows": roll(subsumed),
        "reading": (
            "the composition pass rolled up to the protocol, findings and subsumed rows kept "
            "APART because a subsumed row is usually the same walk under a weaker capability "
            "and summing the two would double one composition and read as twice the recovery. "
            "It is NOT that a subsumed row's dollars stay out of the grade: its entities that "
            "no surviving row reaches charge the top row's exposure at that row's own fraction "
            f"(subsumed_exclusive_value_by_entity), {charging}. licensed_selectors is every "
            "(hop, licensed function) pair a gate-control walk offered; act_as_witnessed is "
            "the subset where the caller is witnessed able to make that call at that "
            "destination; the pairs under act_as_refused are the ones whose magnitude stayed "
            "not_determined and went to confidence instead of the grade. composed_usd is "
            "summed over ROWS and entities are counted distinct, so the two disagree wherever "
            "two rows compose the same entity; the exposure budget, not this figure, is what "
            "stops that entity being paid for twice. act_as_refused standing far above "
            "entities_composed is not a shortfall in the pass but its arithmetic: a licensed "
            "hop composes only where the licensed party is ALSO witnessed makeable to use the "
            "licence, and act_as_refused counts, by reason, every pair where it was not"
        ),
    }


def _execution_carriers(node: Any) -> Iterator[dict[str, Any]]:
    """Every published dict with a ``proving_execution`` block, found structurally so new carriers are counted."""
    if isinstance(node, dict):
        if isinstance(node.get(PROVING_EXECUTION_KEY), dict):
            yield node
        for value in node.values():
            yield from _execution_carriers(value)
    elif isinstance(node, list):
        for item in node:
            yield from _execution_carriers(item)


def _execution_fault_census(findings: list[dict[str, Any]], subsumed: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Published magnitudes whose proving execution couldn't be read, or ``None`` (every block examined, none
    faulted).

    These reasons (:data:`EX.FAULT_REASONS`) take ``_admit_composed``'s withheld arm before the deletability join, so a
    fault moves the grade and is announced at top level. Reasons are counted apart; none names a cause.
    """
    populations = (("findings", findings), ("subsumed_rows", subsumed))
    examined = 0
    reasons: list[str] = []
    by_population: dict[str, int] = {name: 0 for name, _ in populations}
    entities: set[str] = set()
    for name, rows in populations:
        for carrier in _execution_carriers(rows):
            examined += 1
            reason = carrier[PROVING_EXECUTION_KEY].get("reason")
            if reason not in EX.FAULT_REASONS:
                continue
            reasons.append(str(reason))
            by_population[name] += 1
            entity = carrier.get("entity")
            if isinstance(entity, str):
                entities.add(entity)
    if not reasons:
        return None
    return {
        # Not a ``grade_state`` value; see ``utils.scoring_status.GRADE_FAULT_DEGRADED``.
        "grade_qualifier": GRADE_FAULT_DEGRADED,
        "records_faulted": len(reasons),
        # The denominator.
        "execution_records_examined": examined,
        "faulted_by_reason": _counted(reasons),
        "faulted_by_population": by_population,
        "entities_affected": sorted(entities),
        "registered_fault_reasons": sorted(EX.FAULT_REASONS),
        "reading": (
            "every published magnitude names the execution that proved it — or, where the proof "
            "was never a call, the registered reason no execution names it: a sheet ceiling under "
            "reach_sheet_ceiling_magnitudes[] is proven by a BALANCE OBSERVATION of the controlled "
            "node and carries magnitude_not_proven_by_a_call, which is not a fault and is counted "
            "in execution_records_examined below without being counted as one. records_faulted "
            "of them name a typed reason that execution could not be READ. Each one was withheld "
            "by the composition rule's fault arm whatever the authority-deletability join "
            "licensed, so grade_lambda, grade_exposure and confidence_pct here were computed over "
            "fewer composed figures than the same database state yields when every transcript "
            "body reads. THIS DOCUMENT MUST NOT BE COMPARED AGAINST A FAULT-FREE RUN: a moved "
            "grade is not evidence the protocol changed. What is proven is that these bodies "
            "could not be read on this fold — nothing here proves the object storage was "
            "unavailable, and faulted_by_reason keeps the registered situations apart because a "
            "transcript that was never stored and a fetch that did not return are different "
            "facts. entities_affected is the distinct entity of each faulted carrier, published "
            "so the census can be checked against the rows rather than taken on the fold's word"
        ),
    }


def _execution_fault_warning(census: dict[str, Any]) -> dict[str, Any]:
    breakdown = ", ".join(f"{reason} x{hits}" for reason, hits in census["faulted_by_reason"].items())
    return {
        "kind": "execution_evidence_unreadable",
        "note": (
            f"{census['records_faulted']} of {census['execution_records_examined']} published "
            f"proving-execution records could not be read: {breakdown}. Every one of them was "
            "withheld by the composition rule's fault arm regardless of what the "
            "authority-deletability join licensed, so the grade, exposure and confidence in this "
            "document moved with what could be read here and not only with the protocol. Do not "
            "compare this document against a fault-free run. This is not proof the artifact store "
            "was unavailable — what is proven is that these bodies could not be read on this fold; "
            "see execution_evidence_faults for the per-reason census"
        ),
        "records_faulted": census["records_faulted"],
        "faulted_by_reason": dict(census["faulted_by_reason"]),
    }


GRADE_WITHHELD_STALE_INPUTS = "stale_scoring_inputs"
GRADE_WITHHELD_PARTIAL_PRINCIPAL_SETS = "partial_principal_sets"
GRADE_WITHHELD_EXPOSURE_UNPRICED = "exposure_denominator_not_determined"
_WITHHELD_REASONS = {
    GRADE_WITHHELD_STALE_INPUTS: (
        "stale scoring inputs: {signals} enumerated signal(s) name principal rows that no longer exist, so the "
        "findings they would produce are not_determined"
    ),
    GRADE_WITHHELD_PARTIAL_PRINCIPAL_SETS: (
        "partial principal sets: {signals} restricted signal(s) rest on a role set not proven whole, so who can call "
        "them, and the findings that would follow, are not_determined"
    ),
    GRADE_WITHHELD_EXPOSURE_UNPRICED: "no priced value in the perimeter, so the exposure denominator is not_determined",
}


def _stale_principal_inputs(
    signals: list[FunctionSignal], principal_facts: dict[int, P.PrincipalFacts]
) -> list[FunctionSignal]:
    """Enumerated signals naming a principal row that is gone, in population order.

    A policy re-run replaces principal rows under new ids; signals a failed distillation left behind still name the
    old ones, and folding what survives would drop exactly the findings whose rows were replaced.
    """
    return [
        signal
        for signal in signals
        if signal.principal_state == PRINCIPAL_STATE_ENUMERATED
        and any(int(ref.function_principal_id) not in principal_facts for ref in signal.principal_refs)
    ]


def _partial_principal_inputs(signals: list[FunctionSignal]) -> list[FunctionSignal]:
    """Grade-bearing signals whose principal set distillation found short of ``exact``: folding without them would
    drop findings their unfound members carry.
    """
    return [
        signal
        for signal in signals
        if signal.enters_grade
        and signal.principal_state != PRINCIPAL_STATE_ENUMERATED
        and any(note.startswith(PRINCIPAL_SET_NOT_EXACT_NOTE) for note in signal.witness_notes)
    ]


def _stale_inputs_warning(stale: list[FunctionSignal]) -> dict[str, Any]:
    return {
        "kind": "stale_scoring_inputs",
        "signals": len(stale),
        "note": "enumerated signals name principal rows that no longer exist; the grade is withheld",
    }
