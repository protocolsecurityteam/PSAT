"""The three orchestrators — compute_protocol_score, _aggregate, _row_value — plus unit resolution."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

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
from utils import execution_record as EX
from utils.execution_record import PROVING_EXECUTION_KEY
from utils.scoring_status import (
    GRADE_FAULT_DEGRADED,
    GRADE_STATE_COMPUTED,
    GRADE_STATE_NOT_DETERMINED,
    MODEL_VERSION,
    OPENNESS_NOT_DETERMINED,
    OPENNESS_OPEN,
    PRINCIPAL_STATE_ENUMERATED,
    SCORE_TRIGGER_MANUAL,
    SEVERITY_STATE_PROVEN,
    VALUE_STATE_PROVEN_NO_REACH,
    VALUE_STATE_PROVEN_REACH,
)

if TYPE_CHECKING:
    from services.scoring.distill import ProtocolUniverse


def compute_protocol_score(
    session: Session,
    protocol_id: int,
    *,
    signals: list[FunctionSignal] | None = None,
    trigger: str = SCORE_TRIGGER_MANUAL,
    trigger_job_id: Any | None = None,
    computed_at: datetime | None = None,
    universe: ProtocolUniverse | None = None,
) -> ScoreDocument:
    """The protocol's score document, folded over its current signal rows.

    ``signals`` is the §7.5 in-memory feeding mode and nothing else: the offline
    CLI distils every contract without persisting, and passes the result in the
    population order :func:`order_signals` pins. Left unset — every persisted
    path — the population comes from the one pinned query and from nowhere else,
    so no caller can hand the fold a filtered or re-ordered population.

    ``universe`` is the protocol's discovered address set, built in ``distill``
    because assembling it reads object storage and this fold may not. UNSET is
    the fail-closed default and it means no reading is disposed anywhere: the
    predicate it feeds condemns what is ABSENT from the set, so an absent set
    would condemn everything. Every hand-built plane in the suite relies on that
    default, and so does every caller that has no storage to read.
    """
    row_faults: list[dict[str, Any]] = []
    if signals is None:
        # A row whose persisted JSONB does not hold its declared shape withholds
        # ITSELF: the schema's canonical-key checks are the right checks, but
        # raising them through the population read costs the whole protocol its
        # score over one bad column.
        signals, row_faults = current_signals_with_faults(session, protocol_id)

    value_plane = P.load_value_plane(session, protocol_id, universe=universe)
    closure = P.load_control_closure(session, protocol_id)
    conditions = P.load_condition_plane(session, protocol_id)
    conferral = P.load_conferral_plane(session, protocol_id)
    act_as = P.load_act_as_plane(session, protocol_id)
    # ``load_deletability_plane`` takes NO protocol_id, unlike every loader
    # around it: it asks about specific (chain, address) contracts, which are
    # global on-chain identities, and scoping it would drop setter rows on
    # contracts this protocol does not own — turning our own scoping into an
    # earned negative about somebody's control.
    admission = _AdmissionPlanes(P.load_deletability_plane(session), P.load_router_flow_plane(session, protocol_id))
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
    uncharged_product_rows = 0

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

        if _uncharged_product(signal, warnings):
            # A proven benign payout of the caller's own value: it kept its
            # confidence credit above (it entered the grade), and here it creates
            # NO row — so no finding, no value_at_stake, no exposure key. Its
            # disclosures already left on the earned-negative record above; this
            # is the finding-half of the decoupling the ruling needs (inv. 3 — a
            # permissionless self-service payout is not a finding worth zero).
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

    # A transport fault takes the composition rule's withheld arm and moves the
    # grade, so it must not be discoverable only by reading every execution
    # block: an artifact store that stops answering would otherwise look exactly
    # like a code regression.
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
            # Signals that entered the grade (their confidence credit stands) but
            # created no row: proven benign product surface, excluded from the
            # ledger. Without this counter a reader can only find them by
            # subtraction — a zero here is a zero, not an absence.
            "rows_uncharged_product": uncharged_product_rows,
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
        # What bounds a reach hop, and where the bound could not be established.
        # A closure that walks every edge publishes reach it never proved; one
        # that silently drops the edges it cannot establish publishes a smaller
        # number with the same defect. Both classes' populations are counted.
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
        # How much of the perimeter grade_exposure was measured over. Without
        # it the ratio's numerator (a few findings) and its denominator (the
        # whole priced perimeter) are not comparable quantities, and the figure
        # reads as a measurement of safety rather than of coverage.
        "exposure_coverage": exposure_coverage,
        # The sheet-ceiling population at the document level. Every entry it
        # counts is published per row too, and it is still worth assembling
        # once: these dollars are the one class of published magnitude that is
        # deliberately absent from exposure_usd, so a consumer that reads only
        # the grade figures would have no way to see how much money the model
        # bounded from above and then declined to charge. Its credited-signal
        # count is the confidence pass's own, not a second derivation of it.
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
        execution_evidence_faults=execution_faults,
    )


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
        reached = _row_value(probe, value_plane, closure, conditions, conferral, act_as, magnitudes, admission).reach
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


CITATION_CAP = 8


# A citation that points AT evidence: a transcript pointer, a verdict, the block
# a reading was pinned to. Everything else is a field restatement, and a
# ``reading`` key marks the ones that are prose about how to read a field rather
# than a pointer to anything.
_CITATION_EVIDENCE_KEYS = ("transcript_ptr", "verdict", "block_source")


def _cited(citations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The row's citations, evidence first, capped for display.

    The cap is a display bound and the eviction it causes is arbitrary, so the
    order it evicts in must not be. A citation pointing at a transcript is the
    one a reader can check; a prose ``reading`` restating how to read a field is
    not, and it evicted two transcript pointers off a shipped row. Stable within
    each tier, so the population order still decides among equals.
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
        # Rolled up beside the composed set and never merged into it. Both name
        # signals whose magnitude question the FOLD answered rather than the
        # signal, and they answered it with different evidence — a destination's
        # own flow.out witness against a balance observation — so a consumer
        # crediting either has to be able to say which one it credited.
        ceiling_signals.update(valued.ceiling_signals)
        per_entity, value_usd, undetermined = valued.per_entity, valued.total_usd, valued.undetermined
        value_basis = valued.basis
        if row.zero_reach_stripped:
            undetermined = undetermined + row.zero_reach_stripped
            value_basis += f"; {len(row.zero_reach_stripped)} instance(s) reached only the refused zero address"
        # A priced total over an entity that also holds assets the priced sheet
        # never covered is a FLOOR over that entity, not its value: an instance
        # that answered is not the same fact as an entity that was answered.
        partially_priced = _partially_priced_entities(value_plane, valued.reach)
        # Coverage alone decides nothing about direction. A contribution that is
        # itself an extraction ceiling cannot be summed into a floor because
        # OTHER contributions are missing, so the two axes are read together.
        direction = _bound_direction(
            value_usd,
            frozenset(per_entity),
            valued.ceiling_entities,
            bool(undetermined or partially_priced),
            # The withheld-reach block is ALWAYS a dict — it carries its own
            # reading even when nothing was withheld — so its counts are what is
            # read here and never its truthiness.
            bool(
                valued.hops_not_determined
                or valued.withheld_behind_hops.get("hops")
                or valued.withheld_behind_hops.get("entities")
            ),
            valued.non_attributed_entities,
        )
        # Only a row that HAS a total and something in it to grade has a
        # direction to explain. A row whose value is not_determined publishes
        # that word as its basis, and a proven_no_reach row publishes an earned
        # negative consumers branch on by name — neither is a bound claim.
        #
        # Both writers live HERE and not in :func:`_row_value` for one reason:
        # the string names a direction, and the direction is not known until the
        # attribution axis has been read beside the coverage one. A basis built
        # from coverage alone said ">= proven floor" beside a header refusing to
        # publish a floor.
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
        # The at-most in the grade's own units: the raw points this row would
        # earn if every open question resolved against the protocol at its
        # ceiling. Proven severity x proven weakness x the ceiling's band —
        # nothing here is minted, and it never enters lambda. A proven-$0
        # ceiling bounds points at zero (the band floor is for unpriced, not
        # for an earned nothing); an unbounded ceiling bounds nothing.
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
                # The published principal IS the one that set the weakness, not
                # whichever row was folded last.
                "principal": f"{weakest[0]} {weakest[2]}",
                "access_path": row.path,
                "principal_addresses": sorted(row.principal_addresses),
                "principal_kind": weakest[1],
                "capability": row.capability,
                "chain": row.unit.split("::", 1)[0],
                # The row's total and its per-entity breakdown are the SAME
                # floats the per-entity ceiling records publish — one derivation,
                # three keys, one finding object — so they take one rounding
                # (``_round_published``). Measured: five live upgrade.implementation
                # rows carry a sub-cent entity, and at cents the header said
                # "$0.00 at stake" and the breakdown said 0.0 while the record
                # beside them published the bound that was proven. The total is
                # included DELIBERATELY and not only the breakdown: on a row whose
                # one entity is that sheet, the header IS the row's claim, and
                # "$0.00 at stake" is the false-safety reading this whole change
                # exists to remove. It is immaterial today only because those five
                # sit inside a $4.2B row — a fact about this corpus, not a
                # property of the rule.
                #
                # Nothing GRADED moves with either key: ``value_band``,
                # ``value_at_stake_bound_direction`` and ``value_at_stake_is_floor``
                # are derived above from the UNROUNDED ``value_usd``, and the
                # weakness axis reads the unrounded ``per_entity``. But
                # ``value_by_entity`` is NOT inert — do not read this rounding as
                # a presentation-only key. ``_grade`` takes the exposure
                # numerator from it (``held = finding["value_by_entity"][key]``,
                # then ``mine += take * held`` into ``exposure_usd`` and so into
                # ``grade_exposure``), and the subsumed-exclusive selection
                # compares candidates on ``held * fraction`` and charges the
                # winner through the same loop.
                #
                # What keeps THIS change out of the numerator is §6.4, not an
                # absence of readers: a sheet ceiling is held out of exposure
                # entirely (``held = None`` there), and every sub-cent entity on
                # this corpus is a sheet ceiling. That is a rule with its own
                # lifetime and it may be revisited. Where a sub-cent entity is
                # NOT a sheet ceiling the charge can only GROW — the unrounded
                # figure is larger than the 0.00 it replaced — so exposure rises
                # and ``grade_exposure`` falls, and this rounding can never
                # manufacture an improvement.
                "value_at_stake_usd": (_round_published(value_usd) if value_usd is not None else None),
                "value_state": (VALUE_STATE_PROVEN_REACH if value_usd is not None else NOT_DETERMINED),
                "value_by_entity": {k: _round_published(v) for k, v in sorted(per_entity.items())},
                "value_at_stake_basis": value_basis,
                # Which direction the total bounds the principal in, and the
                # reason the flag below is no longer the whole answer: a sum of
                # composed extraction ceilings is not an at-least. Three-valued,
                # and ``not_determined`` is the fall-through — a direction is
                # published only where one was proven.
                "value_at_stake_bound_direction": direction,
                # Retained, and now derived: it is TRUE only where the direction
                # is a floor, so a consumer reading the boolean alone can no
                # longer read a ceiling as an at-least.
                "value_at_stake_is_floor": is_floor,
                # The entities whose published figure is a composed extraction
                # ceiling, named rather than left to be counted out of
                # reach_composed_magnitudes — that list holds every candidate,
                # including ones an entity's own witness beat. SPLIT from the
                # sheet ceilings below rather than widened to hold both: the two
                # are different claims about how the bound was earned, only one
                # of them spends the exposure budget, and a consumer joining
                # this list to reach_composed_magnitudes[] would find no entry
                # for a sheet entity that had been folded into it.
                "entities_priced_from_a_composed_ceiling": sorted(
                    valued.ceiling_entities - valued.sheet_ceiling_entities
                ),
                # The other ceiling: entities whose published figure is their OWN
                # priced sheet, admitted because this row's capability replaces
                # their code. Disjoint from the list above by construction — a
                # standing figure came from one branch — and the two together are
                # the row's ceiling-bearing population.
                "entities_priced_from_a_sheet_ceiling": sorted(valued.sheet_ceiling_entities),
                # Its refusal counterpart, and the reason it is published rather
                # than left to be counted out of the list above: on a row whose
                # every composed figure was withheld the ceiling list is EMPTY,
                # and an empty list there is otherwise the same shape as an
                # empty list on a row that never composed anything. One is a
                # typed refusal, the other is a question nobody asked, and
                # spelling them identically is the collapse three-valued logic
                # exists to prevent.
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
                # The entities behind the coverage gap, named rather than left to
                # be inferred from the direction alone.
                "entities_holding_unpriced_assets": partially_priced,
                "value_band": (
                    (_BAND_PREFIX.get(direction, "") + K.band_label(value_usd))
                    if value_usd is not None
                    else NOT_DETERMINED
                ),
                "undetermined_instances": undetermined,
                "proven_no_reach_instances": valued.proven_no_reach,
                "witnessed_magnitude_caps": valued.magnitude_caps,
                # A floor witness the entity's own sheet could not bound. The
                # published dollars for these entities are the witness's figure
                # standing alone, which is a different fact from a figure two
                # witnesses agreed on.
                "unbounded_floor_magnitudes": valued.unbounded_floor_magnitudes,
                # Phase 6: every dollar this row carries that came from a
                # DESTINATION function's own flow.out witness rather than from a
                # witness on this row's own call, with the act-as chain that
                # licensed it published beside it (inv. 9 exact decomposition).
                "reach_composed_magnitudes": [
                    entry.as_json() for _, entry in sorted(valued.composed_magnitudes.items())
                ],
                # The other half of the same population: every candidate that
                # cleared all three composition witnesses and then lost its
                # FIGURE to the three-arm rule. Each one publishes its gate
                # claim, its execution record and its typed refusal, and no
                # dollar figure of any kind.
                "reach_composed_magnitudes_withheld": [
                    record.as_json() for record in valued.withheld_composed_magnitudes
                ],
                # The sheet ceilings this row publishes, one entry per entity,
                # each carrying the observation-shaped answer to #170's question:
                # a sheet ceiling is proven by a BALANCE OBSERVATION and not by a
                # call, so its proving_execution is not_determined under a
                # registered non-fault reason that says exactly that. Published
                # rather than left implicit, because a magnitude with no
                # execution block reads as one whose execution nobody asked about.
                "reach_sheet_ceiling_magnitudes": _sheet_ceiling_records(
                    valued.sheet_ceiling_entities, per_entity, value_plane, row.capability
                ),
                # Its refusal counterpart, published for the reason every refusal
                # on this row is: an entity silently absent from the list above
                # is indistinguishable from one the branch never fired on. These
                # are entities whose standing figure did not reconcile against
                # the sheet it claimed to be, so the ceiling LABEL was withheld —
                # the dollars stand, graded in no direction, and they charge the
                # exposure budget like any other figure.
                "reach_sheet_ceiling_magnitudes_withheld": valued.sheet_ceilings_withheld,
                "reach_composition_census": valued.composition_census,
                # ``witnessed_magnitude_caps`` lists only the calls a witness
                # actually TRIMMED. Read alone it says nothing about the calls
                # that carried no witness at all, which are the majority and
                # which a reader would otherwise take for "checked and within
                # bound". The census separates the three: capped, witnessed and
                # within its bound, and never witnessed.
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
                # Hops the walk could establish neither way, deduped on the
                # distinct (caller, destination) pair. Reach withheld is still
                # reach this row does not claim — published so the bound is
                # visible instead of the closure quietly getting smaller.
                "reach_hops_not_determined": valued.hops_not_determined,
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
                # What the gate hops this row walked LICENSE at each destination
                # — the role -> selector join's named functions, keyed on the
                # canonical entity the reach set uses, as {selector, name}
                # objects rather than a string a consumer would have to re-parse.
                # A reached entity absent from this map was reached through a hop
                # that named no function, which is a reach whose "to do what" is
                # unanswered and not a reach to nothing.
                "reach_licensed_functions": valued.licensed_functions,
                # The size of what the withheld hops hide. Two published hops can
                # withhold twenty-two entities; without this the other twenty
                # appear nowhere in the document.
                "reach_withheld_behind_hops": valued.withheld_behind_hops,
                # The at-most behind this row's unanswered questions, from the
                # unresolved entities' own sheets. Out of lambda and exposure.
                "unresolved_stake": unresolved,
                # Proven actor and act (ledger membership), unsized consequence.
                # The row's lambda contribution is unchanged by this stamp.
                "partial_proof": bool(unresolved["entities_total"]),
                "example_functions": sorted({i.signal.function_name for i in row.instances})[:6],
                "witness_tiers": sorted(row.tiers),
                "witness_notes": sorted(row.notes),
                "citations": _cited(row.citations),
                # The slice above is a display cap, and a cap that is not counted
                # reads as the whole population. Two witness citations were
                # evicted by a reading-string on one shipped row before the
                # ordering below existed; the total says how many were not shown.
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
        # Subsumption removes a row's POINTS, never the unit's reach. Value that
        # only a subsumed row names is still value this unit provably reaches, and
        # dropping it from the exposure accounting would publish a smaller
        # exposure for a unit that got no smaller.
        #
        # The contributing row's OWN fraction travels with the value. The top row
        # is a different access path — often an undelayed one — and charging the
        # delayed row's value at the undelayed fraction would re-merge in the
        # exposure term exactly what keying rows by access path separated.
        #
        # A SHEET CEILING is not occupancy. The top row publishes a figure at
        # such an entity and charges nothing for it, so treating the key as
        # taken would discard a subsumed row's genuinely witnessed value there
        # and take it out of the exposure accounting altogether — a leak in the
        # direction the budget exists to prevent.
        occupied = set(top["value_by_entity"]) - set(top["entities_priced_from_a_sheet_ceiling"])
        exclusive: dict[str, dict[str, float]] = {}
        # Which exclusive keys arrived as a SUBSUMED row's sheet ceiling. The
        # skip in ``_grade`` reads the TOP row's ceilings, and value carried in
        # from a subsumed row is not on that list — so without this the ceiling
        # a subsumed row published would charge the budget the top row's own is
        # kept out of. Tracked per key beside the winning figure, because the
        # answer belongs to whichever row's figure actually won.
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
        # Published rather than left to be re-derived from the subsumed rows: the
        # exposure loop needs it, and a reader checking why an exclusive entity
        # was not charged has nowhere else to look.
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

    Two functions reaching the same vault charge it once, and the only dollar
    figure this function will publish against an entity is one a magnitude
    WITNESS proved — the entity's whole balance sheet answers "what is there",
    never "what this reach can move". The magnitude is also one number for the
    whole CALL, so it caps that call's sum across the keys it reached rather than
    being re-charged at each of them.

    The reach itself is bounded by the capability's class: code control expands
    over the whole closure of the controlled node, gate control only through
    edges whose scope the gate confers, and both only where the destination's
    own conditions do not pin their caller to the destination itself.

    Where a gate's own call carries no magnitude witness, the DESTINATION
    function's may supply one (:func:`_compose`, Phase 6). That is a reuse of an
    existing witness and never a second source of dollars: it applies only where
    the instance proved no magnitude itself, and each composed figure is capped
    at the destination's own witness and at the destination's own sheet.

    The conferral question is asked with the WITNESSED FUNCTION's own grant, per
    instance: two ownership.transfer functions that rewrite different variables
    confer different hops, and asking the capability class would walk one row's
    reach on another row's witness.
    """
    per_entity: dict[str, float] = {}
    # The entities whose standing figure in ``per_entity`` bounds this principal
    # from above, each mapped to WHICH ceiling it is — a composed extraction
    # ceiling or the controlled node's own sheet. Maintained beside the MAX
    # rather than after it: which branch produced a figure is only knowable where
    # the figure is chosen.
    ceiling_kinds: dict[str, str] = {}
    # Maintained beside the MAX for the same reason ``ceiling_entities`` is: the
    # witness behind a figure is only knowable where that figure is chosen.
    non_attributed_entities: set[str] = set()
    reached: set[str] = set()
    undetermined: list[dict[str, Any]] = []
    proven_no_reach: list[dict[str, Any]] = []
    magnitude_caps: list[dict[str, Any]] = []
    unbounded_floors: list[dict[str, Any]] = []
    # Every candidate every instance offered per entity, kept rather than
    # collapsed on arrival: the merge below has to choose between candidates
    # that tie on dollars, and a running MAX destroys the losers before the tie
    # can be seen, let alone published.
    composition_candidates: dict[str, list[_ComposedMagnitude]] = {}
    composition_census: dict[str, int] = {}
    composition_refusals: dict[str, int] = defaultdict(int)
    # Every composed candidate whose FIGURE the three-arm rule refused, keyed on
    # the call it refused so two instances reaching it report one refusal.
    withheld_composed: dict[tuple[str, str], _WithheldComposition] = {}
    composed_signals: set[tuple[Any, ...]] = set()
    # The signals whose sheet ceiling is the STANDING figure at each entity,
    # kept per entity so a figure the MAX later replaces takes its credit with
    # it. Built on ``composed_signals``' pattern and kept apart from it: a
    # ceiling and a composed destination witness answer the same question with
    # different evidence, and a consumer crediting either has to be able to say
    # which.
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
            # Keyed on the CANONICAL entity, the same key ``reached`` uses. The
            # walk speaks in raw edge anchors and an implementation folded onto
            # its proxy is one entity under two of them, so a consumer joining
            # the licensed functions to the reach set would silently miss every
            # destination that folds.
            for destination, functions in licensed_here.items():
                licensed[value_plane.canonical(destination)].update(functions)
            if not code_control:
                # Phase 6. Code control asks no conferral question, so it names
                # no destination function and has no compositional source; its
                # magnitude question is a different one and stays where Phase 4
                # left it.
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
                    # Deduped on (entity, selector): two instances of one row
                    # reaching the same call refused it once, and counting it
                    # twice would double the refusal a reader is shown.
                    withheld_composed.setdefault((record.entity, record.selector), record)
                _pool_composed(composition_candidates, composed)
                for name, count in counts.items():
                    composition_census[name] = composition_census.get(name, 0) + count
                for reason, hits in refused.items():
                    composition_refusals[reason] += hits
                if composed:
                    composed_signals.add(_signal_identity(instance.signal))
        # Reach is MEMBERSHIP, and it is witnessed here. It may not be read off
        # the value map: an entity drops out of that map whenever its dollars
        # are not_determined — an unpriced sheet today, a refused magnitude once
        # the magnitude discipline lands — and deleting a proven fact because an
        # unproven one is missing is the whole error this fold is being repaired
        # for. Priced or not, the row reaches these entities.
        reached.update(value_plane.canonical(key) for key in keys)
        contributions, gaps, cap, unbounded, from_ceilings, non_attributed = _instance_contributions(
            instance, keys, value_plane, transitive=transitive, composed=composed
        )
        unbounded_floors.extend(unbounded)
        census["instances"] += 1
        if _witnessed_magnitude(instance) is None:
            # A composed magnitude is a witness — the DESTINATION's — so it is
            # counted apart from both the calls that carried their own and the
            # calls that carry none. Folding it into either reports a different
            # fact than the one that was proved, and leaving it at zero on the
            # rows that composed says no witness answered where one did.
            #
            # A sheet ceiling is a THIRD answer and gets a third counter for the
            # same reason: it carries no call witness, so it was landing in
            # magnitude_not_witnessed — the population this census says publishes
            # not_determined at the unpriced band's floor, which is exactly what
            # a priced ceiling does not do.
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
                # The credit goes with the figure it proved. A ceiling a larger
                # contribution has just displaced proves nothing the row
                # publishes, and leaving its signal credited would answer the
                # magnitude question with a number no carrier in the document
                # holds.
                ceiling_signals_by_entity.pop(canonical, None)
                non_attributed_entities.discard(canonical)
            # The bound travels with the figure that stands, and a tie is
            # settled by the weaker of the two claims: an extraction ceiling
            # equal to a witnessed figure is still only a ceiling.
            if canonical in from_ceilings and contribution >= per_entity[canonical]:
                ceiling_kinds[canonical] = from_ceilings[canonical]
                if from_ceilings[canonical] == CEILING_KIND_SHEET:
                    # Ties are the common case and not an edge: several calls on
                    # one node read the same sheet and produce the identical
                    # figure, so each of them proved the number the row
                    # publishes. Only a ceiling STRICTLY beaten above loses its
                    # credit.
                    ceiling_signals_by_entity.setdefault(canonical, set()).add(_signal_identity(instance.signal))
            # Same rule, same direction: an attribution-derived figure tying the
            # standing one revokes the grade, because either candidate may be
            # the number published.
            if contribution >= per_entity[canonical]:
                if canonical in non_attributed:
                    non_attributed_entities.add(canonical)
                else:
                    non_attributed_entities.discard(canonical)

    # Every ceiling label the row is about to publish, checked against the sheet
    # it claims to be — per KEY, which is the only level the cap holds at.
    sheet_ceilings_withheld = _reconcile_sheet_ceilings(ceiling_kinds, per_entity, value_plane)
    for record in sheet_ceilings_withheld:
        ceiling_signals_by_entity.pop(record["entity"], None)

    # One selection over every instance's candidates, not a running MAX: the
    # figure is the same either way, but the selector, destination function,
    # witness state and chain published beside it are the CHOSEN candidate's own
    # and must be taken from it together.
    composition = {key: _select_composed(pool) for key, pool in sorted(composition_candidates.items())}
    # The rule again, on the row's own selection. The pool holds only entries an
    # instance-level pass already admitted, so this changes nothing today — it is
    # here so that the PUBLISHED entry is the one the rule was applied to,
    # whatever a later edit does to the two selection points.
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
    # §7.2 arm 1's conjunct, counted over every entry this row publishes —
    # republished and withheld alike, because the gate claim is published on
    # both and the conjunct qualifies it on both.
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
    # The coverage gap is NOT written into the basis here. A gap alone does not
    # decide the direction — :func:`_bound_direction` reads the attribution axis
    # beside it — and this function cannot see that axis's verdict, so the
    # direction-bearing sentence is :func:`_coverage_bearing_basis`'s to write.
    if proven_no_reach:
        basis += f"; {len(proven_no_reach)} instance(s) proven_no_reach"
    # A sheet ceiling is capped by its node's own sheet BY CONSTRUCTION — it is
    # that sheet, and the MAX below only ever replaces it with something larger
    # that is no longer a ceiling. The cap therefore holds PER KEY and is checked
    # per key (``tests/test_scoring_redteam.py``'s sheet-ceiling cases); it may
    # NOT be checked on the total, because a row's value sums across every priced
    # host it reaches and legitimately exceeds any single sheet — $4.217B over
    # eight hosts on the reference corpus, more than the largest of them.
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
    """Every row's composition census, summed to the protocol.

    Findings and subsumed rows are rolled up SEPARATELY because a subsumed row is
    usually the same walk seen through a weaker capability: adding the two counts
    one composition twice and publishes twice the recovery. That is the whole
    reason for the split, and it is NOT that a subsumed row's dollars stay out of
    the grade — they do not. A subsumed row's entities that no surviving row
    reaches are charged to the top row's exposure at its own fraction
    (``subsumed_exclusive_value_by_entity``), and on the reference corpus a
    subsumed ``authority.replace`` row's composed ``ethereum::0x657e8c86``
    ($11,358,880.43) enters the top finding's published exposure that way.

    Entities are counted DISTINCT within each population — two findings composing
    the same vault composed one entity — while the dollars are summed per row,
    because that is how they enter the grade: each row is charged what it reaches
    and the exposure budget, not this figure, is what keeps one entity from being
    paid for twice.
    """

    # Per-row counts sum; a per-row MAXIMUM does not, and summing chain lengths
    # across rows would publish an arithmetic artefact as the longest chain the
    # corpus grows.
    maxima = ("longest_composed_chain",)
    # Census keys whose value is itself a count-per-token map. They roll by
    # merging the maps, never by summing them into one number: the whole point
    # of keying a refusal on its reason is that the reasons stay apart.
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

    # How many entities actually take the subsumed-exclusive route into a top
    # row's exposure, counted rather than stated: the sentence below used to
    # assert "one … does so here", a measurement of this corpus baked into a
    # literal and false the moment a second row composes one.
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
    """Every published dict carrying a ``proving_execution`` block, wherever it sits.

    Walked structurally rather than read off the two list names the composition
    rule uses today: a census that names its carriers cannot count a carrier
    added after it was written, and an execution block this document publishes
    but the census never looked at is exactly the silent miss the census exists
    to stop.
    """
    if isinstance(node, dict):
        if isinstance(node.get(PROVING_EXECUTION_KEY), dict):
            yield node
        for value in node.values():
            yield from _execution_carriers(value)
    elif isinstance(node, list):
        for item in node:
            yield from _execution_carriers(item)


def _execution_fault_census(findings: list[dict[str, Any]], subsumed: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The published magnitudes whose proving execution could not be read, or ``None``.

    ``None`` where the walk covered every published execution block and none of
    them carried a registered fault reason — a completed count of zero, which is
    why the document omits the field rather than publishing an empty census.

    The reasons counted here are :data:`EX.FAULT_REASONS`, the subset
    :func:`_admit_composed` takes the ``withheld`` arm on. That arm fires BEFORE
    the deletability join is consulted, so a faulted entry loses its dollars
    however the join answered — which is why a fault is a fact about the GRADE
    and not only about one entry, and why it is announced at the document's top
    level instead of being left to be found by reading forty blocks.

    Nothing here names a cause. A body that could not be read is not a store
    that was unavailable, and the four reasons are not even one situation
    between them: ``transcript_unstored`` is a record that was never written,
    while ``fetch_failed`` is a read that did not come back. They are published
    apart and counted apart.
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
        # The machine-checkable marker. Not a ``grade_state`` value — see
        # ``utils.scoring_status.GRADE_FAULT_DEGRADED`` for why the two
        # vocabularies are kept apart.
        "grade_qualifier": GRADE_FAULT_DEGRADED,
        "records_faulted": len(reasons),
        # The denominator, so a reader can tell one unreadable block in forty
        # from forty in forty without counting them.
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
    """The census's top-level warning, with its counts derived from the census."""
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
