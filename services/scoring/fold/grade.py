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
    """How to read one gap entry, from the reasons that fired.

    Null and published exposure get different sentences: the second is a marginal share that understates.
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
    # So a later row finding the budget empty can name who spent it.
    claimed_by: dict[str, list[dict[str, Any]]] = defaultdict(list)
    exposure = 0.0
    gaps: list[dict[str, Any]] = []
    any_priced = False
    for finding in findings:
        # W2c/R9: inv.5 is the weakest path to that entity, so charge per-entity rungs, not the unit's weakest.
        per_entity_weakness = finding.get("weakness_by_entity") or {}
        mine = 0.0
        # Excludes entities whose budget earlier rows spent, so exhaustion isn't published as zero.
        measured_entities = 0
        exhausted: list[dict[str, Any]] = []
        partial: list[dict[str, Any]] = []
        unpriced: list[str] = []
        exclusive = finding.get("subsumed_exclusive_value_by_entity") or {}
        charged_entities = list(finding["reach_entities"]) + [
            k for k in exclusive if k not in finding["reach_entities"]
        ]
        # §6.4: sheet ceilings stay out of the exposure numerator; charging them would inflate exposure and spend budget
        # a later real measurement needs. Composed extraction ceilings are witnessed flows and still charge.
        sheet_ceilings = set(finding.get("entities_priced_from_a_sheet_ceiling") or [])
        exclusive_ceilings = set(finding.get("subsumed_exclusive_sheet_ceiling_entities") or [])
        ceilings_excluded: list[str] = []
        for key in charged_entities:
            # Per-entity contribution, not the row total, or one magnitude would be multiplied by the entity count.
            held = finding["value_by_entity"].get(key)
            # Charged at the subsumed row's fraction.
            key_fraction = finding["severity_proven"] * per_entity_weakness.get(key, finding["weakness"])
            excluded = False
            if key in sheet_ceilings:
                # §6.4: this row's own figure is a sheet ceiling and charges nothing, but a subsumed row's witnessed
                # figure may still apply below.
                held = None
                excluded = True
            if held is None and key in exclusive:
                if key in exclusive_ceilings:
                    # The skip is about the figure, wherever it came from; the top row's ceiling list doesn't name this
                    # key.
                    excluded = True
                else:
                    held = exclusive[key]["usd"]
                    key_fraction = exclusive[key]["fraction"]
                    excluded = False
            if held is None:
                if excluded:
                    # Named so a null exposure has a stated reason.
                    ceilings_excluded.append(key)
                    continue
                # Disclosed, not read as $0.
                unpriced.append(key)
                continue
            room = max(0.0, 1.0 - claimed[key])
            if room <= 0.0:
                # The remainder isn't a measured $0; disclose which rows took it.
                exhausted.append({"entity": key, "claimed_by": list(claimed_by[key])})
                continue
            measured_entities += 1
            take = min(key_fraction, room)
            if room < key_fraction:
                # A partial charge is this row's marginal share, which depends on sort order; disclosed so the
                # understatement isn't silent.
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
        # Taken from the loop, not re-derived from the lists, which can't distinguish a skipped ceiling later charged
        # via a witnessed figure.
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
            # Nothing measurable; null is the honest answer.
            finding["exposure_usd"] = None
        if unpriced or exhausted or partial or ceilings_excluded or finding["exposure_usd"] is None:
            # One gap per finding with every key present; an empty list is a proven negative, not a missing key. S5:
            # unpriced entities come from the row's undetermined instances.
            unpriced_entities = sorted(set(unpriced) | {row["entity"] for row in finding["undetermined_instances"]})
            gaps.append(
                {
                    "principal_unit": finding["principal_unit"],
                    "capability": finding["capability"],
                    "unpriced_entities": unpriced_entities,
                    "undetermined_instances": finding["undetermined_instances"],
                    "budget_exhausted_entities": exhausted,
                    "budget_partially_exhausted_entities": partial,
                    "ceiling_entities_excluded_from_exposure": sorted(ceilings_excluded),
                    "exposure_usd": finding["exposure_usd"],
                    "reading": _gap_reading(
                        finding["exposure_usd"], unpriced_entities, exhausted, partial, ceilings_excluded
                    ),
                }
            )
        # Not-determined exposure is disclosed in exposure_gaps, never summed as zero.
        if finding["exposure_usd"] is not None:
            exposure += finding["exposure_usd"]

    tracked = value_plane.tracked_total
    coverage = _exposure_coverage(findings, value_plane, tracked)
    if not tracked or not any_priced:
        return grade_lambda, None, round(exposure, 2), gaps, coverage
    return grade_lambda, round(100.0 * (1.0 - exposure / tracked), 3), round(exposure, 2), gaps, coverage


def _exposure_coverage(findings: list[dict[str, Any]], value_plane: P.ValuePlane, tracked: float) -> dict[str, Any]:
    """How much of the perimeter the exposure ratio was actually measured over.

    ``grade_exposure`` divides by the whole priced perimeter, but the numerator only includes measurable findings, so a
    ratio near 100 can mean "little was measurable". The ratio isn't adjusted; this discloses it.
    ``perimeter_usd_charged`` is the priced value that was charged; ``perimeter_usd_reached_unmeasured`` is priced value
    reached only by unmeasured findings.
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
