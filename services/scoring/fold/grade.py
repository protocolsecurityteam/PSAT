"""The grade fold and exposure coverage."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from services.scoring import constants as K
from services.scoring import planes as P


def _gap_reading(
    exposure: float | None,
    unpriced: list[Any],
    exhausted: list[Any],
    partial: list[Any],
    ceilings_excluded: list[Any],
) -> str:
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
    if ceilings_excluded:
        parts.append(
            "the entities under ceiling_entities_excluded_from_exposure are priced from their own "
            "SHEET CEILING and are deliberately outside this numerator: what is proven there is an "
            "at-most on a move nobody witnessed, which is not expected loss, and it spends none of "
            "their exposure budget either — so their dollars are absent from the figure by rule "
            "and not by a lookup that failed"
        )
    return "; ".join(parts)


def _grade(
    findings: list[dict[str, Any]], value_plane: P.ValuePlane
) -> tuple[float | None, float | None, float | None, list[dict[str, Any]], dict[str, Any]]:
    if not findings:
        return None, None, None, [], _exposure_coverage([], value_plane, value_plane.tracked_total)
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
        # §6.4: a SHEET ceiling stays out of the exposure numerator entirely. It
        # is a risk-weighted upper bound on a move nobody witnessed, and charging
        # it here would do two things at once — inflate exposure_usd off bounds,
        # and SPEND that entity's budget, which silently displaces a later row
        # that measured a real extraction at the same entity down to its
        # marginal share.
        #
        # The set is the SHEET half only. A composed extraction ceiling is a
        # destination function's own witnessed flow, charges the budget today,
        # and keeps charging: the two are published apart precisely so this loop
        # can tell them apart.
        sheet_ceilings = set(finding.get("entities_priced_from_a_sheet_ceiling") or [])
        exclusive_ceilings = set(finding.get("subsumed_exclusive_sheet_ceiling_entities") or [])
        ceilings_excluded: list[str] = []
        for key in charged_entities:
            # The row's OWN per-entity contribution, not its total: charging the
            # row total against each entity would multiply one witnessed
            # magnitude by the number of entities it was spread across.
            held = finding["value_by_entity"].get(key)
            # An entity only a subsumed row reaches is charged at THAT row's
            # fraction, never at this one's.
            key_fraction = finding["severity_proven"] * per_entity_weakness.get(key, finding["weakness"])
            excluded = False
            if key in sheet_ceilings:
                # §6.4: this row's own figure here is a proven upper bound on a
                # move nobody witnessed. It charges nothing — which is not the
                # same as the entity being unmeasurable, so the fall-through to a
                # subsumed row's WITNESSED figure below still runs.
                held = None
                excluded = True
            if held is None and key in exclusive:
                if key in exclusive_ceilings:
                    # The exclusive figure is itself a sheet ceiling, published by
                    # a subsumed row. The skip is about the FIGURE, so it applies
                    # wherever the figure came from: the top row's ceiling list
                    # does not name this key, and reading only that list is how a
                    # ceiling charges a budget its own row's copy is exempt from.
                    excluded = True
                else:
                    held = exclusive[key]["usd"]
                    key_fraction = exclusive[key]["fraction"]
                    # A real measurement is charged after all. The row's own
                    # ceiling here was skipped and nothing was lost by it, so
                    # there is nothing to disclose as excluded at this key.
                    excluded = False
            if held is None:
                if excluded:
                    # Named, not silently skipped. A row whose every priced entity
                    # is a sheet ceiling publishes exposure_usd null, and a null
                    # with no stated reason is indistinguishable from one nobody
                    # could price.
                    ceilings_excluded.append(key)
                    continue
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
        # The keys a ceiling left contributing nothing are not "charged", and the
        # set is the loop's own answer rather than the two ceiling lists re-read:
        # a key whose ceiling was skipped and whose witnessed exclusive figure
        # was then charged belongs here, and no re-derivation off the lists can
        # tell that case from a key that charged nothing.
        ceiling_only = set(ceilings_excluded)
        finding["exposure_entities_charged"] = sorted(
            key
            for key in charged_entities
            if key not in ceiling_only and (finding["value_by_entity"].get(key) is not None or key in exclusive)
        )
        if measured_entities:
            any_priced = True
            finding["exposure_usd"] = round(mine, 2)
        else:
            # Either no priced entity in reach, or every priced one's budget was
            # already spent: the exposure of this finding is a quantity nobody
            # measured, and null is the only honest answer.
            finding["exposure_usd"] = None
        if unpriced or exhausted or partial or ceilings_excluded or finding["exposure_usd"] is None:
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
                    # Present on every entry, empty where it did not happen: an
                    # absent key would read as a question nobody asked.
                    "ceiling_entities_excluded_from_exposure": sorted(ceilings_excluded),
                    "exposure_usd": finding["exposure_usd"],
                    "reading": _gap_reading(
                        finding["exposure_usd"], unpriced_entities, exhausted, partial, ceilings_excluded
                    ),
                }
            )
        # A finding whose exposure is not_determined contributes nothing to the
        # total and is disclosed in exposure_gaps; it is never summed as a zero.
        if finding["exposure_usd"] is not None:
            exposure += finding["exposure_usd"]

    tracked = value_plane.tracked_total
    coverage = _exposure_coverage(findings, value_plane, tracked)
    if not tracked or not any_priced:
        return grade_lambda, None, round(exposure, 2), gaps, coverage
    return grade_lambda, round(100.0 * (1.0 - exposure / tracked), 3), round(exposure, 2), gaps, coverage


def _exposure_coverage(findings: list[dict[str, Any]], value_plane: P.ValuePlane, tracked: float) -> dict[str, Any]:
    """How much of the perimeter the exposure ratio was actually measured over.

    ``grade_exposure`` is ``100 * (1 - exposure / tracked_total)``. The
    denominator is the whole priced perimeter; the numerator is a sum over only
    the findings whose exposure could be measured at all. Once an unwitnessed
    magnitude publishes ``not_determined`` instead of a balance sheet, most
    findings contribute nothing to that numerator — and a ratio near 100 then
    reads as "almost nothing is exposed" when what it says is "almost nothing
    was measurable". The ratio is not adjusted for this: adjusting it would mint
    a number out of the same absence. It is DISCLOSED, so the figure cannot be
    read as a measurement it is not.

    ``perimeter_usd_charged`` is the priced value of the entities that received
    a charge, and ``perimeter_usd_reached_unmeasured`` the priced value reached
    by findings whose own exposure is ``not_determined`` and which no charged
    row covers — the weight the ratio is silent about.
    """
    determined = [f for f in findings if f.get("exposure_usd") is not None]
    undetermined = [f for f in findings if f.get("exposure_usd") is None]
    charged: set[str] = set()
    for finding in determined:
        charged.update(finding.get("exposure_entities_charged") or [])

    def priced(keys: set[str]) -> float:
        total = 0.0
        for key in sorted(keys):
            value = value_plane.total(value_plane.canonical(key))
            if value is not None:
                total += value
        return round(total, 2)

    unmeasured: set[str] = set()
    for finding in undetermined:
        unmeasured.update(value_plane.canonical(key) for key in finding.get("reach_entities") or [])
    unmeasured -= {value_plane.canonical(key) for key in charged}
    charged_usd = priced(charged)
    return {
        "findings": len(findings),
        "findings_with_determined_exposure": len(determined),
        "findings_with_exposure_not_determined": len(undetermined),
        "entities_charged": len(charged),
        "perimeter_usd_charged": charged_usd,
        "perimeter_usd_reached_unmeasured": priced(unmeasured),
        "tracked_total_usd": round(tracked, 2) if tracked else None,
        "tracked_share_measured_pct": (round(100.0 * charged_usd / tracked, 3) if tracked else None),
        "reading": (
            "grade_exposure divides a numerator summed over "
            f"{len(determined)} of {len(findings)} findings by the WHOLE priced perimeter. The "
            "other findings publish exposure_usd null — no witness proved how much their reach "
            "moves — and contribute nothing rather than a zero, so a grade_exposure near 100 is "
            "'this much of the perimeter was not measured against', never 'this much is safe'. "
            "perimeter_usd_reached_unmeasured is the priced value those findings reach that no "
            "charged row covers"
        ),
    }
