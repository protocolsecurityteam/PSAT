"""Promote completed jobs' tracking plans into the versioned store (F4b).

The monitored fleet reads its watch list from ``contract_materializations``,
which until F4a had exactly one writer — the authority recursion, materializing
whichever dependencies it happened to visit. The plans themselves were never
missing: 115 of 116 latest completed jobs for monitored addresses hold a
substantive ``control_tracking_plan`` artifact. They were simply in the wrong
store, so 136 of 183 contracts enrolled on the baseline registry alone.

This sweep lifts each monitored address's newest completed job's bundle into a
materialization row, stamped with the source job. It re-analyzes nothing and
spends nothing: the artifacts already exist.

**Invariant 7 is why this is a promotion and not a read-through.** Enrollment
must never reach into per-job artifacts ad hoc — an unversioned per-run snapshot
read at watch time is a fact with no provenance and no schema stamp. Promotion
is the only door: the row records ``source_job_id`` and
``ANALYSIS_SCHEMA_VERSION``, and every later reader sees which job spoke.

What it refuses to promote, each a visible not-determined rather than fabricated
coverage:

``no_completed_job`` / ``job_plan_artifact_absent``
    Nothing was ever analyzed at this address (proxies whose impl carries the
    analysis, unverified sources, third-party infra). Proxy→implementation plan
    bundling is deliberately out of scope here.
``job_analysis_artifact_absent``
    A plan without its analysis would make a ready row whose ``analysis``
    hydrates to None — read downstream as *this contract has no analysis*, which
    a missing artifact never said.
``job_schema_version_not_current``
    The job carries no ``analysis_schema_version``, or an older one. A v5 row
    holding a pre-v5 plan is a version claim nothing witnessed.
``bytecode_keccak_not_cached``
    The row is keyed on bytecode. This sweep does no RPC — an address with no
    cached keccak is left to the operator-run mutating path, which may fetch it.
``plan_unreadable``
    The blob could not be read. The bucket not answering is not a plan.

**Dry run is the default.** ``--apply`` writes rows and marks the affected
protocols for re-enrollment; it is operator-run, and no agent executes it.
Operator caveat: the dirty mark is protocol-scoped, so a caller-authored
``monitoring_config`` in the same protocol is rebuilt from the analyzer on that
pass — enrollment's existing wholesale-rebuild behaviour, brought forward by
this sweep rather than introduced by it (the fleet's two caller-supplied
configs both sit in protocol 1)::

    uv run python -m scripts.promote_tracking_plans                  # report only
    uv run python -m scripts.promote_tracking_plans --markdown out.md
    uv run python -m scripts.promote_tracking_plans --apply          # operator

The report is the F4b verification artifact: for every monitored config it
shows the plan state today, whether a plan would be supplied, the spec counts by
witness tier before and after, and — for every spec that would gain notify
rights — the qualification that earns them.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, load_only

from db.contract_materializations import (
    ANALYSIS_SCHEMA_VERSION,
    PRODUCED_BY_PROMOTION_SWEEP,
    PUBLISH_ADDRESS_BOUND_TO_OTHER_KECCAK,
    PUBLISH_ALREADY_CURRENT,
    PUBLISH_KECCAK_BOUND_TO_OTHER_ADDRESS,
    PUBLISH_WRITTEN,
    build_provenance,
    hydrate_tracking_plan,
    publish_materialization,
)
from db.models import (
    Artifact,
    BytecodeCache,
    ContractMaterialization,
    Job,
    JobStatus,
    MonitoredContract,
    SessionLocal,
)
from db.queue import _job_chain_name, get_artifact
from services.monitoring.enrollment import mark_enrollment_dirty
from services.monitoring.event_topics import (
    WITNESS_TIER_SELF_DESCRIBING,
    _event_states_the_change,
    _is_canonical_family,
    extract_governance_topics,
    is_member_witness,
    normalized_writer_openness,
)
from services.monitoring.tracking_plan_state import classify_plan_state
from utils.chains import chain_cache_token, require_chain

logger = logging.getLogger(__name__)

# Why a monitored config would not receive a promoted plan.
NO_COMPLETED_JOB = "no_completed_job"
JOB_PLAN_ARTIFACT_ABSENT = "job_plan_artifact_absent"
JOB_ANALYSIS_ARTIFACT_ABSENT = "job_analysis_artifact_absent"
JOB_SCHEMA_VERSION_NOT_CURRENT = "job_schema_version_not_current"
BYTECODE_KECCAK_NOT_CACHED = "bytecode_keccak_not_cached"
PLAN_UNREADABLE = "plan_unreadable"

#: The row would be written.
PROMOTABLE = "promotable"

#: Where the specs in the "after" column come from. A contract that already has
#: a current row is not promoted, but its plan is what re-enrollment will read,
#: so its after-tiers belong in the table just the same.
AFTER_FROM_PROMOTED_JOB = "promoted_job_artifact"
AFTER_FROM_EXISTING_ROW = "existing_materialization"
AFTER_NONE = "none"

#: Tier recorded on a spec written before the taxonomy existed. Not a tier — the
#: absence of one, kept distinct from ``activity`` (which is a classification).
TIER_UNSTAMPED = "unstamped"


@dataclass
class Promotion:
    """One monitored config's before/after, promotable or not."""

    address: str
    chain: str
    contract_name: str | None = None
    protocol_id: int | None = None
    plan_state_before: str = ""
    outcome: str = ""
    source_job_id: str | None = None
    bytecode_keccak: str | None = None
    after_source: str = AFTER_NONE
    tiers_before: dict[str, int] = field(default_factory=dict)
    tiers_after: dict[str, int] = field(default_factory=dict)
    notify_gains: list[dict[str, Any]] = field(default_factory=list)
    #: Populated only on ``--apply``.
    applied: str | None = None

    @property
    def promotable(self) -> bool:
        return self.outcome == PROMOTABLE


def _tier_counts(specs: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for spec in specs:
        tier = spec.get("witness_tier")
        key = tier if isinstance(tier, str) and tier else TIER_UNSTAMPED
        counts[key] = counts.get(key, 0) + 1
    return counts


def qualification_witness(spec: dict) -> dict[str, Any] | None:
    """Why *spec* may publish a change claim directly, or None when it may not.

    Attribution, not classification: the arms are read in the same order
    ``event_topics.classify_witness_tier`` applies them, using that module's own
    predicates, so this cannot drift into a second opinion. A self_describing
    spec that matches no arm returns ``{"kind": "unattributed"}`` — visible as a
    defect rather than passed off as qualified.
    """
    if spec.get("witness_tier") != WITNESS_TIER_SELF_DESCRIBING:
        return None
    event_type = spec.get("event_type")
    witness = spec.get("member_witness")
    openness = normalized_writer_openness(spec.get("writer_openness"))
    if is_member_witness(witness) and openness == "restricted":
        return {
            "kind": "member_witness",
            "mapping_name": witness.get("mapping_name"),
            "key_position": witness.get("key_position"),
            "value_position": witness.get("value_position"),
            "direction": witness.get("direction"),
            "writer_function": witness.get("function") or witness.get("writer"),
            "writer_openness": openness,
        }
    if _is_canonical_family(event_type):
        return {"kind": "canonical_family", "family": event_type, "signature": spec.get("signature")}
    effect_tags = spec.get("effect_tags") if isinstance(spec.get("effect_tags"), dict) else None
    if _event_states_the_change(list(spec.get("inputs") or []), effect_tags, spec.get("controller_id")):
        return {
            "kind": "old_new_args_single_writer",
            "writes": (effect_tags or {}).get("writes"),
            "args": [i.get("name") for i in spec.get("inputs") or [] if isinstance(i, dict)],
        }
    return {"kind": "unattributed"}


def _notify_gains(before: list[dict], after: list[dict]) -> list[dict[str, Any]]:
    """Specs that would publish-and-notify after but did not before.

    Notify rights are the tier: only ``self_describing`` occurrences reach the
    notifier (``notifier._NON_NOTIFYING_TIERS``). A topic0 already carrying that
    tier on the row today gains nothing.
    """
    already = {(s.get("topic0") or "").lower() for s in before if s.get("witness_tier") == WITNESS_TIER_SELF_DESCRIBING}
    gains: list[dict[str, Any]] = []
    for spec in after:
        if spec.get("witness_tier") != WITNESS_TIER_SELF_DESCRIBING:
            continue
        topic0 = (spec.get("topic0") or "").lower()
        if topic0 in already:
            continue
        gains.append(
            {
                "topic0": topic0,
                "signature": spec.get("signature"),
                "event_type": spec.get("event_type"),
                "controller_id": spec.get("controller_id"),
                "witness": qualification_witness(spec),
            }
        )
    return gains


def _newest_completed_job_with_plan(session: Session, address: str, chain: str) -> tuple[Job | None, bool]:
    """``(newest completed job that left a tracking plan, any completed job)``.

    Both halves are reported because they are different facts about a monitored
    contract: *nothing was ever analyzed here* (a proxy shell, an unverified
    source) and *it was analyzed and the plan phase produced nothing* have
    different remedies, and collapsing them would put 51 contracts under one
    token that only fits some of them.

    Chain-qualified through ``_job_chain_name`` (the first-class ``chain_id``
    column, request chain as fallback): the same address on another chain is a
    different deployment, and its plan is not this one's.
    """
    jobs = (
        session.execute(
            select(Job)
            .where(func.lower(Job.address) == address.lower(), Job.status == JobStatus.completed)
            .order_by(Job.updated_at.desc())
        )
        .scalars()
        .all()
    )
    any_completed = False
    for job in jobs:
        if _job_chain_name(job) != chain:
            continue
        any_completed = True
        if session.execute(
            select(Artifact.id).where(Artifact.job_id == job.id, Artifact.name == "control_tracking_plan").limit(1)
        ).scalar_one_or_none():
            return job, True
    return None, any_completed


def _has_artifact(session: Session, job_id: Any, name: str) -> bool:
    return (
        session.execute(
            select(Artifact.id).where(Artifact.job_id == job_id, Artifact.name == name).limit(1)
        ).scalar_one_or_none()
        is not None
    )


def _cached_keccak(session: Session, chain: str, address: str) -> str | None:
    try:
        chain_id = require_chain(chain=chain, context="promotion sweep").chain_id
    except Exception:
        return None
    return session.execute(
        select(BytecodeCache.code_keccak).where(
            BytecodeCache.chain_id == chain_id,
            BytecodeCache.address == address.lower(),
            BytecodeCache.selfdestructed_at.is_(None),
        )
    ).scalar_one_or_none()


#: The planner reads a materialization row for four things: is it current, whose
#: address does it hold, and what plan does it serve. Loading the whole entity
#: would pull ``analysis`` — inline JSONB is multi-megabyte on pre-blob rows, and
#: the planner never looks at it.
_ROW_COLUMNS = (
    ContractMaterialization.address,
    ContractMaterialization.contract_name,
    ContractMaterialization.status,
    ContractMaterialization.analysis_schema_version,
    ContractMaterialization.tracking_plan,
    ContractMaterialization.tracking_plan_blob_key,
)


def _existing_row(session: Session, chain: str, address: str) -> ContractMaterialization | None:
    return session.execute(
        select(ContractMaterialization)
        .options(load_only(*_ROW_COLUMNS))
        .where(
            ContractMaterialization.chain == chain_cache_token(chain),
            ContractMaterialization.address == address.lower(),
        )
    ).scalar_one_or_none()


def _row_is_current(row: ContractMaterialization | None) -> bool:
    return row is not None and row.status == "ready" and row.analysis_schema_version == ANALYSIS_SCHEMA_VERSION


def _after_from_existing(row: ContractMaterialization) -> list[dict]:
    """The specs re-enrollment would derive from a row that is already current."""
    try:
        plan = hydrate_tracking_plan(row)
    except Exception as exc:
        logger.warning("existing materialization for %s unreadable: %s", row.address, exc)
        return []
    return extract_governance_topics(plan) if isinstance(plan, dict) else []


def plan_promotions(
    session: Session,
    *,
    chain: str | None = None,
    address: str | None = None,
) -> list[Promotion]:
    """The sweep's proposal for every active monitored contract. Reads only."""
    stmt = select(MonitoredContract).where(MonitoredContract.is_active.is_(True))
    if chain:
        stmt = stmt.where(MonitoredContract.chain == chain)
    if address:
        stmt = stmt.where(MonitoredContract.address == address.lower())
    stmt = stmt.order_by(MonitoredContract.chain, MonitoredContract.address)

    out: list[Promotion] = []
    for mc in session.execute(stmt).scalars().all():
        config = mc.monitoring_config if isinstance(mc.monitoring_config, dict) else {}
        before = [s for s in (config.get("tracked_topics") or []) if isinstance(s, dict)]
        promotion = Promotion(
            address=mc.address,
            chain=mc.chain,
            protocol_id=mc.protocol_id,
            plan_state_before=classify_plan_state(config),
            tiers_before=_tier_counts(before),
        )
        out.append(promotion)

        existing = _existing_row(session, mc.chain, mc.address)
        if _row_is_current(existing):
            assert existing is not None
            promotion.outcome = PUBLISH_ALREADY_CURRENT
            promotion.bytecode_keccak = existing.bytecode_keccak
            promotion.contract_name = existing.contract_name
            after = _after_from_existing(existing)
            promotion.after_source = AFTER_FROM_EXISTING_ROW
            promotion.tiers_after = _tier_counts(after)
            promotion.notify_gains = _notify_gains(before, after)
            continue

        job, any_completed = _newest_completed_job_with_plan(session, mc.address, mc.chain)
        if job is None:
            promotion.outcome = JOB_PLAN_ARTIFACT_ABSENT if any_completed else NO_COMPLETED_JOB
            continue
        promotion.source_job_id = str(job.id)
        promotion.contract_name = job.name
        if job.analysis_schema_version != ANALYSIS_SCHEMA_VERSION:
            # None (a static-cache job that never reached the stamp) and an older
            # number are the same refusal for different reasons: neither proves
            # the artifacts were produced by the current analyzer.
            promotion.outcome = JOB_SCHEMA_VERSION_NOT_CURRENT
            continue
        if not _has_artifact(session, job.id, "contract_analysis"):
            promotion.outcome = JOB_ANALYSIS_ARTIFACT_ABSENT
            continue
        keccak = _cached_keccak(session, mc.chain, mc.address)
        if not keccak:
            promotion.outcome = BYTECODE_KECCAK_NOT_CACHED
            continue
        promotion.bytecode_keccak = keccak
        if existing is not None and existing.bytecode_keccak != keccak:
            promotion.outcome = PUBLISH_ADDRESS_BOUND_TO_OTHER_KECCAK
            continue
        keccak_row = session.execute(
            select(ContractMaterialization)
            .options(load_only(*_ROW_COLUMNS))
            .where(
                ContractMaterialization.chain == chain_cache_token(mc.chain),
                ContractMaterialization.bytecode_keccak == keccak,
            )
        ).scalar_one_or_none()
        if _row_is_current(keccak_row) and (keccak_row.address or "").lower() != mc.address.lower():  # type: ignore[union-attr]
            # One row per (chain, bytecode): a second address sharing this
            # bytecode cannot be served by address lookup. Saying so beats
            # moving the row off the address that already resolves to it.
            promotion.outcome = PUBLISH_KECCAK_BOUND_TO_OTHER_ADDRESS
            continue

        try:
            plan = get_artifact(session, job.id, "control_tracking_plan")
        except Exception as exc:
            logger.warning("tracking plan for job %s unreadable: %s", job.id, exc)
            promotion.outcome = PLAN_UNREADABLE
            continue
        if not isinstance(plan, dict):
            promotion.outcome = PLAN_UNREADABLE
            continue

        after = extract_governance_topics(plan)
        promotion.outcome = PROMOTABLE
        promotion.after_source = AFTER_FROM_PROMOTED_JOB
        promotion.tiers_after = _tier_counts(after)
        promotion.notify_gains = _notify_gains(before, after)
    return out


def apply_promotions(session: Session, promotions: list[Promotion]) -> dict[str, int]:
    """Write the promotable rows and queue re-enrollment. Operator-run only.

    Re-enrollment is *marked*, not performed: ``mark_enrollment_dirty`` hands the
    protocol to the monitor's own enrollment pass, which is the single code path
    that knows how to merge a config (F5) — reimplementing that here would be a
    second, divergent writer of ``monitoring_config``.
    """
    counts: dict[str, int] = {}
    protocols: set[int] = set()
    for promotion in promotions:
        if not promotion.promotable:
            continue
        job_id = promotion.source_job_id
        analysis = get_artifact(session, job_id, "contract_analysis")
        plan = get_artifact(session, job_id, "control_tracking_plan")
        trees = get_artifact(session, job_id, "predicate_trees")
        job = session.get(Job, job_id)
        outcome = publish_materialization(
            chain=promotion.chain,
            address=promotion.address,
            bytecode_keccak=promotion.bytecode_keccak or "",
            contract_name=promotion.contract_name,
            analysis=analysis if isinstance(analysis, dict) else None,
            tracking_plan=plan if isinstance(plan, dict) else None,
            predicate_trees=trees if isinstance(trees, dict) else None,
            source_content_hash=job.source_content_hash if job is not None else None,
            provenance=build_provenance(PRODUCED_BY_PROMOTION_SWEEP, source_job_id=job_id),
        )
        promotion.applied = outcome
        counts[outcome] = counts.get(outcome, 0) + 1
        if outcome == PUBLISH_WRITTEN and promotion.protocol_id:
            protocols.add(promotion.protocol_id)

    for protocol_id in sorted(protocols):
        mark_enrollment_dirty(session, protocol_id, "tracking_plan_promoted")
    counts["protocols_marked_for_re_enrollment"] = len(protocols)
    return counts


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

_TIER_ORDER = ("self_describing", "hint", "activity", TIER_UNSTAMPED)


def _tiers_str(counts: dict[str, int]) -> str:
    if not counts:
        return "-"
    keys = [k for k in _TIER_ORDER if k in counts] + sorted(k for k in counts if k not in _TIER_ORDER)
    return " ".join(f"{k[:4]}={counts[k]}" for k in keys)


def as_dicts(promotions: list[Promotion]) -> list[dict[str, Any]]:
    return [
        {
            "address": p.address,
            "chain": p.chain,
            "contract_name": p.contract_name,
            "plan_state_before": p.plan_state_before,
            "outcome": p.outcome,
            "promoted_plan_present": p.promotable,
            "after_source": p.after_source,
            "source_job_id": p.source_job_id,
            "bytecode_keccak": p.bytecode_keccak,
            "tiers_before": p.tiers_before,
            "tiers_after": p.tiers_after,
            "notify_gains": p.notify_gains,
            "applied": p.applied,
        }
        for p in promotions
    ]


def summarize(promotions: list[Promotion]) -> dict[str, Any]:
    outcomes: dict[str, int] = {}
    tiers_before: dict[str, int] = {}
    tiers_after: dict[str, int] = {}
    gains = 0
    by_kind: dict[str, int] = {}
    contracts_gaining_topics = 0
    for p in promotions:
        outcomes[p.outcome] = outcomes.get(p.outcome, 0) + 1
        for tier, n in p.tiers_before.items():
            tiers_before[tier] = tiers_before.get(tier, 0) + n
        for tier, n in p.tiers_after.items():
            tiers_after[tier] = tiers_after.get(tier, 0) + n
        gains += len(p.notify_gains)
        for gain in p.notify_gains:
            kind = (gain.get("witness") or {}).get("kind") or "unattributed"
            by_kind[kind] = by_kind.get(kind, 0) + 1
        if p.promotable and sum(p.tiers_after.values()) > sum(p.tiers_before.values()):
            contracts_gaining_topics += 1
    return {
        "configs": len(promotions),
        "outcomes": outcomes,
        "contracts_gaining_topics": contracts_gaining_topics,
        "specs_by_tier_before": tiers_before,
        "specs_by_tier_after": tiers_after,
        "notify_rights_gains": gains,
        # The mechanical gate, as a number: every gain must name the arm that
        # qualifies it. A non-zero ``unattributed`` is a spec publishing under a
        # tier nothing in this report can justify.
        "notify_rights_gains_by_witness": by_kind,
        "notify_rights_gains_unattributed": by_kind.get("unattributed", 0),
    }


def format_table(promotions: list[Promotion]) -> str:
    header = (
        f"{'address':<44}{'chain':<9}{'plan state before':<28}{'outcome':<32}"
        f"{'plan?':<7}{'tiers before':<26}{'tiers after':<26}{'notify+':>8}"
    )
    lines = [header, "-" * len(header)]
    for p in promotions:
        lines.append(
            f"{p.address:<44}{p.chain:<9}{p.plan_state_before:<28}{p.outcome:<32}"
            f"{('yes' if p.promotable else 'no'):<7}{_tiers_str(p.tiers_before):<26}"
            f"{_tiers_str(p.tiers_after):<26}{len(p.notify_gains):>8}"
        )
    return "\n".join(lines)


def format_markdown(promotions: list[Promotion], summary: dict[str, Any]) -> str:
    lines = [
        "# Promotion dry run (F4b)",
        "",
        "Every active monitored config, its tracking-plan state today, and what the",
        "sweep would supply. `tiers after` is derived by the real enrollment classifier",
        "(`event_topics.extract_governance_topics`) over the plan that would be read —",
        "the promoted job artifact, or the existing materialization for rows already",
        "current. `unst` counts specs recorded before the taxonomy existed: an absent",
        "stamp, not a tier.",
        "",
        "## Summary",
        "",
        "```json",
        json.dumps(summary, indent=2, sort_keys=True),
        "```",
        "",
        "## Per-config",
        "",
        "| address | chain | plan state before | outcome | plan supplied | tiers before | tiers after | notify gains |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for p in promotions:
        lines.append(
            f"| `{p.address}` | {p.chain} | {p.plan_state_before} | {p.outcome} | "
            f"{'yes' if p.promotable else 'no'} | {_tiers_str(p.tiers_before)} | "
            f"{_tiers_str(p.tiers_after)} | {len(p.notify_gains)} |"
        )
    lines += [
        "",
        "## Watches gaining notify rights, with their qualification witness",
        "",
        "Only `self_describing` occurrences reach the notifier. Each row below is a",
        "spec that would publish and notify after the sweep and did not before, with",
        "the arm of `classify_witness_tier` that earns it.",
        "",
        "| address | event | controller | witness kind | witness |",
        "|---|---|---|---|---|",
    ]
    any_gain = False
    for p in promotions:
        for gain in p.notify_gains:
            any_gain = True
            witness = gain.get("witness") or {}
            kind = witness.get("kind", "?")
            detail = {k: v for k, v in witness.items() if k != "kind"}
            lines.append(
                f"| `{p.address}` | {gain.get('signature') or gain.get('topic0')} "
                f"({gain.get('event_type')}) | {gain.get('controller_id')} | {kind} | "
                f"`{json.dumps(detail, sort_keys=True)}` |"
            )
    if not any_gain:
        lines.append("| _none_ | | | | |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="Write the rows. Off by default (dry run reports only).")
    ap.add_argument("--chain", default=None, help="Restrict to one chain (monitored_contracts.chain name).")
    ap.add_argument("--address", default=None, help="Restrict to one address.")
    ap.add_argument("--json", dest="json_out", default=None, help="Write the full per-config report as JSON.")
    ap.add_argument("--markdown", dest="md_out", default=None, help="Write the report table as markdown.")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    with SessionLocal() as session:
        promotions = plan_promotions(session, chain=args.chain, address=args.address)
        summary = summarize(promotions)
        print(format_table(promotions))
        print()
        print(json.dumps(summary, indent=2, sort_keys=True))

        if args.apply:
            applied = apply_promotions(session, promotions)
            print()
            print("applied: " + json.dumps(applied, sort_keys=True))
        else:
            print(
                f"\ndry run: {summary['outcomes'].get(PROMOTABLE, 0)} row(s) would be written. "
                "Re-run with --apply to promote."
            )

        if args.json_out:
            with open(args.json_out, "w", encoding="utf-8") as fh:
                json.dump({"summary": summary, "configs": as_dicts(promotions)}, fh, indent=2, sort_keys=True)
        if args.md_out:
            with open(args.md_out, "w", encoding="utf-8") as fh:
                fh.write(format_markdown(promotions, summary))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
