"""Policy worker — computes effective permissions and labels principals."""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Mapping, Sequence
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.deployment import deployment_scope, normalize_deployment
from db.models import (
    Contract,
    EffectiveFunction,
    Job,
    JobStage,
    JobStatus,
    PrincipalLabel,
    SessionLocal,
    derive_job_chain_id,
)
from db.nested_artifacts import ARTIFACT_KINDS, KEY_PREFIX, parse_key
from db.nested_artifacts import store_bundle as store_nested_artifacts
from db.queue import get_artifact, store_artifact
from db.queue.typed import (
    ArtifactSchemaError,
    load_assessment,
)
from schemas.control_tracking import ControlSnapshot
from schemas.effective_permissions import EffectivePermissions, PrincipalResolution
from services.clients.rpc import require_rpc_url
from services.concurrency import parallel_map
from services.discovery import membership_gate
from services.discovery.perimeter import (
    PERIMETER_SPAWN_DEPTH_CAP,
    PERIMETER_SPAWN_LIMIT,
    new_fp_materialization_result,
    new_spawn_result,
    queue_discovered_contracts,
)
from services.effects.config import effects_stage_enabled
from services.governance.control_graph_types import FP_MATERIALIZE_LIMIT, materialize_fp_principal_nodes
from services.policy import build_effective_permissions, build_principal_labels
from services.policy.effective_permissions_writer import write_effective_function_rows
from services.policy.principal_enrichment import load_protocol_deployer_groups, load_protocol_safe_owner_sets
from services.policy.principal_history import build_principal_history
from services.resolution.capability_resolver import _load_state_var_values
from services.resolution.cross_chain_authority import make_cross_chain_recognizer
from services.resolution.graph_tables import replace_control_graph_rows
from services.resolution.recursive import LoadedArtifacts, resolve_control_graph
from services.resolution.tracking import classify_resolved_address_with_status, read_contract_controllers
from services.static.claims import EffectMatch, resolve_claim_precedence
from utils.chains import UnknownChainError, chain_by_id, chain_by_name, require_chain
from utils.logging import log_timed_phase, record_degraded, record_stage_metric
from workers.base import BaseWorker

logger = logging.getLogger("workers.policy_worker")

RECURSION_MAX_DEPTH = int(os.getenv("PSAT_RECURSION_MAX_DEPTH", "6"))

# Phase timing convention for ``process()``.
#
# Each pipeline sub-step below is wrapped in ``utils.logging.log_timed_phase``
# (the canonical facility shared with ``resolution_worker``/``static_worker``)
# rather than a bespoke timer. On a clean exit it emits one ``phase complete``
# INFO line carrying ``duration_ms``/``phase`` and folds ``phase_ms_<phase>``
# into the ``stage_timing`` artifact the monitor UI reads; the duration is
# recorded in ``finally`` so a raising sub-step still books its partial cost.
#
# The motivation is historical: ``process()`` used to carry only lifecycle
# markers and no sub-step timing, so a pathologically slow run (the 780s
# CumulativeMerkleDrop policy job) surfaced as one opaque ``[JOB] elapsed_s``
# number with nothing to attribute it to. The named phases below — semantic
# capabilities, effective permissions, row writes, principal history, graph
# refresh, principal labels, cross-contract enrichment, auto-enrollment —
# let a slow job be localised to the offending step without grepping logs.
# ``durations_ms`` accumulates per-phase totals for the closing profile line.


def _make_principal_type_resolver(
    classify_cache: dict[str, tuple[str, dict[str, object]]],
    rpc_url: str | None,
    cross_chain_recognizer: Callable[[str], tuple[str, dict[str, object]] | None] | None = None,
    *,
    chain_id: int | None = None,
) -> Callable[[str], tuple[str | None, dict[str, object] | None]]:
    """Build an ``address -> (resolved_type, details)`` classifier for the FP
    writer. Reuses the resolution stage's classify cache, falling back to a
    live (process-cached) ``classify_resolved_address`` probe for misses — the
    same path ``build_principal_labels`` uses, so FunctionPrincipal rows carry
    the same Safe/Timelock/EOA typing as principal labels.

    ``cross_chain_recognizer``, when supplied, takes priority: an
    aliased L1 owner / bridge predeploy is labelled ``cross_chain_authority``
    before the generic classification runs. ``None`` (mainnet and every chain
    without bridge constants) preserves the prior typing exactly."""
    cache_lc = {k.lower(): v for k, v in classify_cache.items()}

    def _resolve(address: str) -> tuple[str | None, dict[str, object] | None]:
        if cross_chain_recognizer is not None:
            recognized = cross_chain_recognizer(address)
            if recognized is not None:
                return recognized
        cached = cache_lc.get((address or "").lower())
        if cached:
            return cached[0], cached[1]
        if not rpc_url:
            return None, None
        resolved_type, details, _cacheable = classify_resolved_address_with_status(rpc_url, address, chain_id=chain_id)
        return resolved_type, details

    return _resolve


def _make_terminal_controller_resolver(
    rpc_url: str | None, *, chain_id: int | None = None
) -> Callable[[str], list[dict[str, object]] | None] | None:
    """Build the ``address -> [controller-step, ...] | None`` resolver that
    drives the contract-principal terminal walk. Reads a contract's
    controllers via canonical getters (``owner()``/``authority()``/``admin()``)
    and classifies each, so ``resolve_terminal_principal`` can chain contract ->
    ... -> Safe/EOA and fail closed on parallel control planes (Solmate/Solady
    ``Auth`` exposes owner AND authority). ``None`` when there is no RPC URL (the
    walk is then skipped and every contract principal stays a non-terminal
    way-point)."""
    if not rpc_url:
        return None

    def _resolve(address: str) -> list[dict[str, object]] | None:
        controllers = read_contract_controllers(rpc_url, address, chain_id=chain_id)
        if controllers is None:
            # A probe error: the plane set is NOT dispositively known this round
            # (see read_contract_controllers). ``None`` propagates that to the
            # walk as ``unknown_unfetched``.
            return None
        if not controllers:
            # Every canonical getter answered cleanly and named nothing —
            # probe-set silence, which the walk reports as
            # ``controllers_not_determined`` with its basis. Kept distinct from
            # ``None`` (probe error): the two are different not-determined
            # states, but NEITHER is a proven absence — the finite getter set
            # cannot prove no controller exists.
            return []
        steps: list[dict[str, object]] = []
        for owner in controllers:
            resolved_type, details, _cacheable = classify_resolved_address_with_status(
                rpc_url, owner, chain_id=chain_id
            )
            steps.append({"address": owner, "resolved_type": resolved_type, "details": details})
        return steps

    return _resolve


def _known_addresses_for_scope(resolved_control_graph: Any, target_address: str | None) -> set[str]:
    """The run's known-address set for cross-chain alias recognition:
    every resolved control-graph node address plus the target contract. An
    aliased L1 owner is only labelled when its implied L1 address is one of
    these — same-address L1/L2 deployments are the case this catches."""
    known: set[str] = set()
    if target_address:
        known.add(target_address.lower())
    nodes = resolved_control_graph.get("nodes") if isinstance(resolved_control_graph, dict) else None
    for node in nodes or []:
        addr = str((node or {}).get("address", "")).lower()
        if addr.startswith("0x") and len(addr) == 42:
            known.add(addr)
    return known


def _rpc_url_for_job(job: Job) -> str:
    """eRPC URL for the job's own chain, resolved via the first-class
    ``jobs.chain_id`` column (``_chain_id_for_job``), not the request JSONB —
    a chainless ``/api/analyze`` submission carries the mainnet edge default
    only in the column, so a request-only read fails loud on every such job."""
    request = job.request if isinstance(job.request, dict) else {}
    explicit = request.get("rpc_url")
    return require_rpc_url(
        explicit_rpc_url=explicit if isinstance(explicit, str) else None,
        chain_id=_chain_id_for_job(job),
        context=f"policy rpc for job {job.id}",
    )


def _chain_id_for_job(job: Job) -> int:
    """The job's first-class ``chain_id`` (invariant 1): the populated
    ``jobs.chain_id`` column, else derived from ``request["chain"]`` via the
    canonical registry, else mainnet for a chain-less row."""
    chain_id = getattr(job, "chain_id", None)
    if isinstance(chain_id, int):
        return chain_id
    request = job.request if isinstance(job.request, dict) else {}
    return derive_job_chain_id(request.get("chain"), job.address) or 1


def _chain_name_for_job(job: Job) -> str:
    """Canonical chain name for the job (mainnet → ``"ethereum"``). Used for the
    ``contract_materializations`` cache key + monitoring enrollment so both agree
    with the name the resolution stage materialized under."""
    try:
        return chain_by_id(_chain_id_for_job(job)).name
    except UnknownChainError:
        return "ethereum"


def _persist_spawn_summary(
    session: Session,
    job: Job,
    spawn_result: Mapping[str, Any],
    *,
    artifact_name: str = "perimeter_spawn_summary",
) -> None:
    """Write the perimeter ledger, including after the walk raised.

    Best-effort by design, and it must never mask the exception that brought us
    here. When the walk raised mid-loop the primary session is usually poisoned
    (a failed INSERT aborts the transaction), so the write is retried on a fresh
    session — the same pattern ``BaseWorker._persist_stage_errors`` uses, and for
    the same reason: the record of what happened has to outlive the transaction
    that failed.

    *artifact_name* selects which ledger: the perimeter's own spawn summary, or
    ``fp_materialization_summary`` (the FP→control-graph mint pass). Both carry
    the same absence semantics, so both need the same survive-a-poisoned-session
    write.
    """
    try:
        store_artifact(session, job.id, artifact_name, data=spawn_result)
        session.commit()
        return
    except Exception:
        try:
            session.rollback()
        except Exception:
            logger.debug("Job %s: rollback before spawn-summary retry failed", job.id, exc_info=True)
    # Bound to the SAME engine as the session it replaces: the ledger belongs
    # to the database the job lives in, and the global default is a different
    # one wherever the two are split (the test harness; any future multi-DB).
    fresh = Session(bind=session.get_bind())
    try:
        store_artifact(fresh, job.id, artifact_name, data=spawn_result)
        fresh.commit()
    except Exception as exc:
        # A lost ledger is a real degradation, not a cosmetic one: an absent
        # ledger artifact is defined to mean "this job predates the ledger", so
        # silently failing to write it would publish that false meaning.
        # Surface it rather than let the artifact's absence lie.
        record_degraded(
            phase=artifact_name,
            exc=exc,
            context={"job_id": str(job.id)},
        )
        logger.warning(
            "Job %s: could not persist %s (non-fatal)",
            job.id,
            artifact_name,
            exc_info=True,
        )
    finally:
        try:
            fresh.close()
        except Exception:
            logger.debug("spawn-summary fresh session close failed", exc_info=True)


def _root_artifacts(
    contract_analysis: Mapping[str, Any],
    tracking_plan: Mapping[str, Any],
    snapshot: ControlSnapshot,
) -> LoadedArtifacts:
    return {
        "analysis": contract_analysis,
        "tracking_plan": tracking_plan,
        "snapshot": snapshot,
    }


def _load_nested_artifacts(session: Session, job_id, *, chain: str) -> dict[str, LoadedArtifacts]:
    """Hydrate ``recursive.*`` artifacts written by the resolution stage.

    Resolution writes only the runtime-state slices (snapshot,
    effective_permissions) to ``recursive.*`` rows. The static slices
    (analysis, tracking_plan) live in ``contract_materializations``
    (content-addressed by ``(chain, bytecode_keccak)``); we hydrate them
    here per-address so the rest of policy still sees a full
    ``LoadedArtifacts`` bundle. A bundle missing analysis/snapshot is
    dropped — ``_resolve_authority`` and the post-policy
    ``resolve_control_graph`` refresh both require both fields.
    """
    import copy

    from db import contract_materializations as cm
    from db.models import Artifact

    prefix = f"{KEY_PREFIX}."
    rows = (
        session.execute(select(Artifact).where(Artifact.job_id == job_id, Artifact.name.like(f"{prefix}%")))
        .scalars()
        .all()
    )
    bundles: dict[str, dict] = {}
    for row in rows:
        parsed = parse_key(row.name)
        if parsed is None:
            continue
        address, kind = parsed
        if kind not in ARTIFACT_KINDS:
            continue
        payload = get_artifact(session, job_id, row.name)
        if payload is None:
            continue
        bundles.setdefault(address, {})[kind] = payload

    # Hydrate analysis + tracking_plan from contract_materializations.
    # Address-keyed lookup keyed on the job's chain (the same name the resolution
    # stage materialized under); on a row miss we drop the bundle below since the
    # downstream consumers can't operate without analysis. ``chain`` is the job's
    # resolved chain name — a chainless call is a data bug, so fail loud
    # rather than defaulting to mainnet via the old PSAT_DEFAULT_CHAIN env read.
    require_chain(chain=chain, context="policy nested-artifact hydration")
    for address, bundle in bundles.items():
        try:
            mrow = cm.find_by_address(session, chain=chain, address=address)
        except Exception as exc:
            # A failed query leaves the session pending-rollback; roll back before
            # the next address's lookup so one DB hiccup doesn't drop every
            # remaining bundle. The bundle is dropped either way, but a row miss
            # is an expected outcome (silent, above) and a DB error is not.
            session.rollback()
            # ``bundle_*``, not ``address``/``chain``: the job's own address and
            # chain are already bound as context fields, and the formatter drops
            # an ``extra`` whose key collides with one of them.
            record_degraded(
                phase="nested_artifact_hydration",
                exc=exc,
                context={"job_id": str(job_id), "bundle_address": address, "bundle_chain": chain},
            )
            logger.warning(
                "Materialization hydration failed for %s on %s; bundle dropped from policy analysis",
                address,
                chain,
                extra={"exc_type": type(exc).__name__, "bundle_address": address, "bundle_chain": chain},
            )
            mrow = None
        if mrow is None:
            continue
        if mrow.analysis:
            bundle["analysis"] = copy.deepcopy(mrow.analysis)
        if mrow.tracking_plan:
            bundle["tracking_plan"] = copy.deepcopy(mrow.tracking_plan)

    # Only keep bundles that have the minimum fields resolve_control_graph needs.
    return {
        addr: cast(LoadedArtifacts, bundle)
        for addr, bundle in bundles.items()
        if {"analysis", "snapshot"} <= bundle.keys()
    }


def _resolve_semantic_capabilities(
    session: Session,
    *,
    contract_address: str,
    job_id: Any,
    chain: str | None = None,
    chain_id: int,
) -> dict[str, dict[str, Any]] | None:
    """Run the semantic capability resolver for ``contract_address`` against
    the in-progress job. Returns ``{function_signature: capability_dict}``
    or None on miss / failure.

    ``chain`` (e.g. ``"ethereum"``) plumbs through to the resolver's
    ``_load_state_var_values`` so the controller-value lookup is
    scoped by ``(job_id, chain)``. The resolver also
    derives this from ``job.request['chain']`` when None is passed,
    so passing it here is belt-and-suspenders.

    ``chain_id`` is required: it binds the resolver's RPC/event reads
    to the job's real chain. Without it the predicate-eval tree would run as
    chain 1 even for an L2 job; a chainless call is now a hard error, not a
    silent mainnet default. The caller threads the job's ``chain_id``."""
    try:
        from services.resolution.capability_resolver import resolve_contract_capabilities
    except Exception as exc:  # pragma: no cover — import-error handled defensively
        record_degraded(
            phase="semantic_capability_resolution",
            exc=exc,
            context={"address": contract_address, "job_id": str(job_id)},
        )
        logger.warning(
            "semantic capability resolver unavailable for %s: %s",
            contract_address,
            exc,
            extra={"exc_type": type(exc).__name__},
        )
        return None

    try:
        result = resolve_contract_capabilities(
            session,
            address=contract_address,
            job_id=job_id,
            chain=chain,
            chain_id=chain_id,
        )
        if result is None:
            exc = RuntimeError("semantic capability resolver produced no output")
            record_degraded(
                phase="semantic_capability_resolution",
                exc=exc,
                context={"address": contract_address, "job_id": str(job_id), "chain": chain},
            )
            logger.warning(
                "semantic capability resolver produced no output for %s",
                contract_address,
                extra={"chain": chain},
            )
        return result
    except Exception as exc:
        record_degraded(
            phase="semantic_capability_resolution",
            exc=exc,
            context={"address": contract_address, "job_id": str(job_id), "chain": chain},
        )
        logger.warning(
            "semantic capability resolution skipped for %s: %s",
            contract_address,
            exc,
            extra={"exc_type": type(exc).__name__},
        )
        return None


def _safe_address_lookup_from_graph(
    control_graph_nodes: list[dict] | None,
) -> dict[str, str]:
    """Build ``{<function_signature>: <safe_contract_address>}`` from the
    resolved control graph. The threshold_group writer reads this when
    populating the synthetic Safe row's address. Falls back to
    ``{"default": <first_safe>}`` so single-Safe contracts don't need
    per-function graph metadata.

    Returns ``{}`` when no Safe nodes are present — the writer then
    drops back to the zero-address sentinel.
    """
    out: dict[str, str] = {}
    safes: list[str] = []
    for node in control_graph_nodes or []:
        if str(node.get("resolved_type", "")).lower() != "safe":
            continue
        address = str(node.get("address", "")).lower()
        if not (address.startswith("0x") and len(address) == 42):
            continue
        if address not in safes:
            safes.append(address)
        details = node.get("details") or {}
        controller_label = str(details.get("controller_label", ""))
        if controller_label:
            out.setdefault(controller_label, address)
    if safes and "default" not in out:
        out["default"] = safes[0]
    return out


def _semantic_controller_context_address(
    snapshot: Mapping[str, Any],
    nested_artifacts: dict[str, LoadedArtifacts],
) -> str | None:
    addresses: set[str] = set()
    for value in snapshot.get("controller_values", {}).values():
        if not isinstance(value, dict):
            continue
        address = str(value.get("value", "")).lower()
        if address == "0x0000000000000000000000000000000000000000":
            continue
        if not (address.startswith("0x") and len(address) == 42):
            continue
        bundle = nested_artifacts.get(address)
        if isinstance(bundle, dict):
            addresses.add(address)
    return sorted(addresses)[0] if addresses else None


def _selector_by_function_key(function_records: Sequence[Mapping[str, Any]] | None) -> dict[str, str]:
    """``{function key -> selector}`` from the effective-permissions payload, so a
    consumer holding either signature can find the row that payload produced.

    Both keys are indexed because the two planes name a function differently: the
    effects artifact and the predicate trees use Slither's ``full_name``, while
    the row stores the canonical ABI signature — the same function under two
    strings whenever a parameter is a contract, struct or enum. The selector is
    the one value both sides agree on, and it is taken from the payload rather
    than re-derived so it is byte-identical to what the writer stored."""
    out: dict[str, str] = {}
    for record in function_records or []:
        if not isinstance(record, dict):
            continue
        selector = record.get("selector")
        if not isinstance(selector, str) or not selector:
            continue
        for key in (record.get("function"), record.get("abi_signature")):
            if isinstance(key, str) and key:
                out.setdefault(key, selector.lower())
    return out


class PolicyWorker(BaseWorker):
    stage = JobStage.policy

    # Read-only by contract: nothing ever assigns ``self.next_stage``, so a
    # property satisfies every consumer — but the base declares it as a plain
    # writable attribute, which pyright cannot reconcile with an override.
    @property
    def next_stage(self) -> JobStage:  # pyright: ignore[reportIncompatibleVariableOverride]
        """Flag-dynamic transition: route into ``effects``
        only when ``PSAT_EFFECTS_STAGE`` is armed, else straight to
        ``coverage``. The flag gates the *transition itself* — with it off no
        job ever enters ``effects`` (a job parked at a stage no worker drains
        would sit forever, since the stale sweep only rescues claimed rows)."""
        return JobStage.effects if effects_stage_enabled() else JobStage.coverage

    def process(self, session: Session, job: Job) -> None:
        logger.info(
            "Policy stage started for job %s address=%s name=%s",
            job.id,
            job.address or "0x0",
            job.name or "Contract",
        )
        rpc_url = _rpc_url_for_job(job)
        chain_id = _chain_id_for_job(job)
        chain_name = _chain_name_for_job(job)
        durations_ms: dict[str, int] = {}

        # ``predicate_trees`` and ``effects`` are the semantic inputs to
        # ``build_effective_permissions``.
        predicate_trees = get_artifact(session, job.id, "predicate_trees")
        effects_artifact = get_artifact(session, job.id, "effects")
        missing_semantic_inputs = [
            name
            for name, artifact in (("predicate_trees", predicate_trees), ("effects", effects_artifact))
            if not isinstance(artifact, dict)
        ]
        if missing_semantic_inputs:
            exc = RuntimeError("missing semantic input artifact(s): " + ", ".join(sorted(missing_semantic_inputs)))
            record_degraded(
                phase="effective_permissions_semantic_inputs",
                exc=exc,
                context={"job_id": str(job.id), "missing_artifacts": sorted(missing_semantic_inputs)},
            )
            logger.warning(
                "Policy stage missing semantic inputs for job %s: %s",
                job.id,
                ", ".join(sorted(missing_semantic_inputs)),
                extra={"missing_artifacts": sorted(missing_semantic_inputs)},
            )
        # Optional: classify cache populated by the resolution stage. Lets the
        # refresh + labeling passes skip 6-10 RPCs per address.
        classify_cache_raw = get_artifact(session, job.id, "classified_addresses")
        classify_cache: dict[str, tuple[str, dict[str, object]]] = {}
        if isinstance(classify_cache_raw, dict):
            for addr, val in classify_cache_raw.items():
                if isinstance(val, list) and len(val) == 2:
                    classify_cache[addr] = (str(val[0]), dict(val[1]) if isinstance(val[1], dict) else {})

        try:
            assessment = load_assessment(get_artifact, session, job.id)
        except ArtifactSchemaError as exc:
            raise RuntimeError(f"{exc.artifact_name} artifact failed validation") from exc
        if assessment is None:
            raise RuntimeError("assessment artifact not found")

        from services.assessment import contract_subject, control_graph, controller_observations, observation_plan

        contract_analysis = contract_subject(assessment)
        control_snapshot = controller_observations(assessment)
        resolved_control_graph = control_graph(assessment)
        tracking_plan = observation_plan(assessment)

        nested_artifacts = _load_nested_artifacts(session, job.id, chain=chain_name)

        # Determine nested controller context for effective-permission enrichment.
        authority_snapshot: dict | None = None
        principal_resolution: PrincipalResolution = {
            "status": "no_authority",
            "reason": "No nested controller context resolved",
        }
        if isinstance(resolved_control_graph, dict):
            authority_result = self._resolve_authority(
                session,
                job,
                resolved_control_graph,
                control_snapshot,
                nested_artifacts,
            )
            authority_snapshot = authority_result.get("authority_snapshot")
            principal_resolution = authority_result.get("principal_resolution", principal_resolution)
            authority_status = principal_resolution.get("status", "unknown")
            record_stage_metric("authority_status", authority_status)
            logger.info(
                "Policy stage authority resolution complete for job %s",
                job.id,
                extra={
                    "address": (job.address or "0x0"),
                    "authority_status": authority_status,
                    "authority_reason": principal_resolution.get("reason"),
                },
            )

        # Build effective permissions
        self.update_detail(session, job, "Computing effective permissions")

        # Resolve per-function CapabilityExpr now so the artifact builder
        # and writer use the same semantic principal source.
        # Pass job.id — without it the resolver's default
        # ``Job.status==completed`` filter skips the in-progress job.
        capability_resolver_output: dict[str, dict[str, Any]] | None = None
        if isinstance(predicate_trees, dict) and job.address:
            job_chain = job.request.get("chain") if isinstance(job.request, dict) else None
            with log_timed_phase(logger, "semantic_capabilities", durations_ms=durations_ms) as ph:
                capability_resolver_output = _resolve_semantic_capabilities(
                    session,
                    contract_address=(job.address or "").lower(),
                    job_id=job.id,
                    chain=job_chain if isinstance(job_chain, str) else None,
                    chain_id=chain_id,
                )
                ph["function_count"] = len(capability_resolver_output or {})

        with log_timed_phase(logger, "effective_permissions", durations_ms=durations_ms) as ph:
            ep_data: EffectivePermissions = build_effective_permissions(
                contract_analysis,
                target_snapshot=control_snapshot,
                authority_snapshot=authority_snapshot,
                principal_resolution=principal_resolution,
                predicate_trees=predicate_trees if isinstance(predicate_trees, dict) else None,
                capability_resolver_output=capability_resolver_output,
                effects=effects_artifact if isinstance(effects_artifact, dict) else None,
            )
            ph["function_count"] = len(ep_data["functions"])

        # Cross-contract claims must land before row materialization so the DB
        # remains a projection of the canonical assessment rather than an older
        # pre-enrichment vocabulary.
        with log_timed_phase(logger, "cross_contract_enrichment", durations_ms=durations_ms):
            enriched = self._enrich_cross_contract(
                session,
                job,
                contract_analysis,
                control_snapshot,
                function_records=ep_data.get("functions"),
            )
            if enriched:
                self._apply_cross_contract_claims(ep_data, enriched)

        from services.assessment import add_policy, project_permission_index

        assessment = add_policy(assessment, ep_data, chain_id=chain_id)
        ep_data = cast(EffectivePermissions, project_permission_index(assessment, ep_data))
        store_artifact(session, job.id, "assessment", data=assessment)

        # Write to effective_functions and function_principals tables from
        # resolver-native semantic capability rows only.
        # An impl analyzed in proxy context resolves against the proxy's storage;
        # tag its rows with that deployment so a shared impl can hold N sets.
        deployment_address = normalize_deployment(
            (job.request if isinstance(job.request, dict) else {}).get("proxy_address")
        )
        contract_row = session.execute(select(Contract).where(Contract.job_id == job.id).limit(1)).scalar_one_or_none()
        # All three DB writes below (effective_functions, principal_history,
        # principal_labels) are gated on contract_row. A missing row means the
        # job completes green while writing zero rows — DB and artifacts then
        # disagree. Make that explicit and chartable rather than silent.
        record_stage_metric("rows_written", contract_row is not None)
        if contract_row is None:
            logger.warning(
                "Policy stage found no Contract row for job %s; wrote zero DB rows",
                job.id,
                extra={"address": (job.address or "0x0")},
            )
            record_degraded(
                phase="policy_db_write",
                exc=RuntimeError("no Contract row for job; zero policy rows written"),
                context={"job_id": str(job.id), "address": job.address or "0x0"},
            )
        # Cross-chain authority recognizer: None on mainnet and any
        # chain without bridge constants, so those paths stay byte-identical.
        # Uses the first-class job chain id (not the local ``chain_id``, which a
        # later block re-derives from request JSONB and can clobber to 1).
        cross_chain_recognizer = make_cross_chain_recognizer(
            _chain_id_for_job(job), _known_addresses_for_scope(resolved_control_graph, job.address)
        )
        if contract_row and isinstance(ep_data, dict):
            graph_nodes = resolved_control_graph.get("nodes") if isinstance(resolved_control_graph, dict) else None
            safe_lookup = _safe_address_lookup_from_graph(graph_nodes if isinstance(graph_nodes, list) else None)

            # The pre-image is captured before the rewrite: a principal this
            # run DROPS names no fact afterwards, and only the union of before
            # and after reaches the membership witnesses resting on it.
            principals_before = membership_gate.principal_addresses(session, [contract_row.id])
            with log_timed_phase(logger, "effective_function_rows", durations_ms=durations_ms) as ph:
                fp_added = write_effective_function_rows(
                    session,
                    contract_id=contract_row.id,
                    function_records=ep_data.get("functions", []),
                    capability_by_function=capability_resolver_output,
                    safe_address_lookup=safe_lookup or None,
                    resolve_principal_type=_make_principal_type_resolver(
                        classify_cache, rpc_url, cross_chain_recognizer, chain_id=_chain_id_for_job(job)
                    ),
                    deployment_address=deployment_address,
                )
                session.commit()
                ph["function_principals"] = fp_added
            record_stage_metric("function_principals", fp_added)
            membership_gate.evaluate_principal_change(
                session,
                contract_id=contract_row.id,
                addresses=principals_before | membership_gate.principal_addresses(session, [contract_row.id]),
                context=f"policy_function_principals:{job.id}",
            )

        record_stage_metric("effective_functions", len(ep_data.get("functions", [])))
        if contract_row and isinstance(predicate_trees, dict):
            job_chain = job.request.get("chain") if isinstance(job.request, dict) else None
            # Derive the int chain id from the registry. Non-mainnet
            # names now map to their real ids instead of collapsing to 1 (the
            # old hand map only knew ethereum/mainnet); an unknown chain still
            # tolerantly falls back to mainnet rather than raising.
            try:
                chain_id = chain_by_name(job_chain).chain_id if job_chain else 1
            except UnknownChainError:
                chain_id = 1
            with log_timed_phase(logger, "principal_history", durations_ms=durations_ms):
                try:
                    state_var_values = _load_state_var_values(
                        session,
                        contract_row.address,
                        job_id=job.id,
                        chain=job_chain if isinstance(job_chain, str) else None,
                    )
                    principal_history = build_principal_history(
                        contract_address=contract_row.address,
                        chain_id=chain_id,
                        predicate_trees=predicate_trees,
                        state_var_values=state_var_values,
                    )
                except Exception as exc:
                    record_degraded(
                        phase="principal_history",
                        exc=exc,
                        context={"job_id": str(job.id), "address": contract_row.address},
                    )
                    logger.warning(
                        "principal history skipped for job %s address=%s: %s",
                        job.id,
                        contract_row.address,
                        exc,
                        extra={"exc_type": type(exc).__name__},
                    )
                    principal_history = {
                        "schema_version": "principal_history.v1",
                        "contract_address": contract_row.address.lower(),
                        "chain_id": chain_id,
                        "status": "error",
                        "reason": str(exc),
                        "sources": [],
                        "role_membership": [],
                        "capability_roles": [],
                        "function_permissions": [],
                        "public_capabilities": [],
                    }
                store_artifact(session, job.id, "principal_history", data=principal_history)

        logger.info(
            "Policy stage effective permissions complete for job %s address=%s name=%s",
            job.id,
            job.address or "0x0",
            job.name or "Contract",
        )

        # Rebuild the resolved graph now that effective_permissions exists,
        # so semantic role/controller principals can be projected into the graph.
        # The refresh reuses the nested artifacts persisted during resolution.
        self.update_detail(session, job, "Refreshing resolved control graph")
        # Attach the target contract's updated effective_permissions to the
        # root bundle so role/controller principals can be projected when
        # re-traversing the graph.
        root_bundle = _root_artifacts(contract_analysis, tracking_plan, cast(ControlSnapshot, control_snapshot))
        root_bundle["effective_permissions"] = ep_data
        with log_timed_phase(logger, "graph_refresh", durations_ms=durations_ms) as ph:
            refreshed_graph, refreshed_nested = resolve_control_graph(
                root_artifacts=root_bundle,
                rpc_url=rpc_url,
                chain_id=chain_id,
                max_depth=RECURSION_MAX_DEPTH,
                workspace_prefix="recursive",
                nested_artifacts_override=nested_artifacts,
                # Reuse the resolution stage's classification results — every
                # entry here saves one classify_resolved_address call (6-10 RPCs).
                classify_cache=classify_cache,
                # Pre-seed with the resolution stage's graph: every nested
                # contract was already analyzed in the first walk and has
                # its effective_permissions baked in. The refresh's only job
                # is projecting the root's now-computed role principals onto
                # the existing graph, which the BFS handles by re-walking
                # ONLY the root and any newly-discovered downstream nodes.
                initial_graph=cast(Any, resolved_control_graph) if isinstance(resolved_control_graph, dict) else None,
            )
            if refreshed_graph:
                resolved_control_graph = refreshed_graph
                # Rewrite the CGN/CGE tables to the refreshed graph too — the
                # same scoped replace the resolution stage used. Rewriting only
                # the artifact left the table plane a strict subset: every
                # ``role_principal`` edge (projected here, because it needs the
                # effective_permissions computed this stage) and a set of
                # refresh-only ``controller_value`` edges were structurally
                # unreachable in ``control_graph_edges``, so the effects value
                # closure (both relations are in CONTROL_EDGE_RELATIONS — a
                # scorer input; the value movement rides the controller_value
                # edges, the role_principal rows carry authority structure),
                # Surface, chat, and enrollment all read a graph missing
                # authority the artifact plane asserted — while every row
                # still carried ``graph_max_depth`` as if the walk that
                # produced it were the complete one.
                if contract_row:
                    replace_control_graph_rows(
                        session,
                        contract_id=contract_row.id,
                        deployment_address=deployment_address,
                        resolved_graph=refreshed_graph,
                    )
                    session.commit()
                # Persist any newly materialized nested artifacts (rare — most come
                # from resolution stage already).
                new_addresses = set(refreshed_nested) - set(nested_artifacts)
                if new_addresses:
                    store_nested_artifacts(
                        session,
                        job.id,
                        {addr: refreshed_nested[addr] for addr in new_addresses},
                    )
            ph["graph_nodes"] = (
                len(resolved_control_graph.get("nodes", [])) if isinstance(resolved_control_graph, dict) else 0
            )
        # Materialize the ``function_principals`` rows that never reached the
        # graph at all. The walk's only principal ingresses are
        # ``authority_roles[].principals`` and ``controllers[].principals``; an
        # address in neither has no node, and with no node no spawn site can
        # ever see it — 73 addresses / 411 of 1,200 FP rows on the PR-161
        # corpus. This is the INSERT half ``reconcile_control_graph_types``
        # (UPDATE-only) never had.
        #
        # HERE, and not at the enrollment call site, for three reasons that are
        # all data-flow, not preference:
        #  1. It is strictly AFTER the ``replace_control_graph_rows`` above —
        #     the last wholesale delete+insert of this (contract, deployment)
        #     scope in the job's stage sequence — so the re-mint strategy the
        #     pass documents is guaranteed, not hoped for.
        #  2. It is strictly BEFORE the perimeter, so a minted node is a
        #     candidate in the SAME job rather than one run later.
        #  3. ``write_effective_function_rows`` committed this contract's FP
        #     rows earlier in this same stage, so the input plane is populated.
        #     Enrollment runs later still, is protocol-scoped, and only fires
        #     for protocol jobs.
        # Outside the ``if refreshed_graph:`` above for the same reason the
        # spawn is: a refresh that produced no graph must not silently skip the
        # mint, and an absent ledger must keep meaning "predates the ledger".
        fp_nodes: list[dict[str, Any]] = []
        if contract_row is not None:
            fp_ledger = new_fp_materialization_result(budget=FP_MATERIALIZE_LIMIT)
            try:
                _, fp_nodes = materialize_fp_principal_nodes(
                    session,
                    contract_id=contract_row.id,
                    deployment_address=deployment_address,
                    budget=FP_MATERIALIZE_LIMIT,
                    result=fp_ledger,
                )
                # No commit here: the pass commits each mint before recording
                # it, so the ledger written below can never name a row a
                # rollback removed.
            finally:
                _persist_spawn_summary(session, job, fp_ledger, artifact_name="fp_materialization_summary")

        # Bring the refresh's newly-discovered contracts inside the analysis
        # perimeter. Without this, a node FIRST seen here — every role principal,
        # since role principals need the effective_permissions computed this
        # stage — could never be analysed: the only other spawn site runs
        # earlier, in the resolution stage. Budgeted, because this path is
        # recursive (an analysed manager projects its own role principals and
        # spawns again), and every cut is recorded rather than dropped.
        #
        # Runs on EVERY policy job, outside the `if refreshed_graph:` above, and
        # the ledger is written in a `finally`. Both are deliberate. Writing it
        # only when the refresh produced a graph made an ABSENT artifact
        # ambiguous between "the refresh did not happen" and "the refresh
        # happened and omitted nothing" — the exact asymmetry the selection
        # ledger exists to avoid. And returning the ledger from the walker meant
        # a `create_job` raise part-way through left children committed with no
        # record of them at all.
        spawn_result = new_spawn_result(site="policy_refresh", budget=PERIMETER_SPAWN_LIMIT)
        try:
            if isinstance(resolved_control_graph, dict):
                # A LOCAL view, not the artifact. The minted nodes must reach
                # the walker (that is the whole point), but the persisted
                # ``resolved_control_graph`` is the WALK's output and must not
                # acquire nodes no walk produced — every artifact consumer would
                # then read a minted node as walk-witnessed. The nodes' own
                # plane is ``control_graph_nodes`` plus the
                # ``fp_materialization_summary`` ledger.
                perimeter_graph: Mapping[str, Any] = (
                    {**resolved_control_graph, "nodes": [*(resolved_control_graph.get("nodes") or []), *fp_nodes]}
                    if fp_nodes
                    else resolved_control_graph
                )
                queue_discovered_contracts(
                    session,
                    job,
                    perimeter_graph,
                    rpc_url,
                    site="policy_refresh",
                    chain_name=_chain_name_for_job(job),
                    budget=PERIMETER_SPAWN_LIMIT,
                    depth_cap=PERIMETER_SPAWN_DEPTH_CAP,
                    result=spawn_result,
                    # The set this stage actually minted, passed explicitly.
                    # The walker must not infer it from the node payload: a
                    # provenance marker inside ``details`` is forgeable, since
                    # the walk copies principal details through verbatim.
                    fp_materialized_addresses=[n["address"] for n in fp_nodes],
                )
        finally:
            _persist_spawn_summary(session, job, spawn_result)

        # Label principals
        self.update_detail(session, job, "Labeling principals")
        with log_timed_phase(logger, "principal_labels", durations_ms=durations_ms) as ph:
            pl_data = build_principal_labels(
                ep_data,
                resolved_control_graph=(
                    cast(dict, resolved_control_graph) if isinstance(resolved_control_graph, dict) else None
                ),
                rpc_url=rpc_url,
                chain_id=_chain_id_for_job(job),
                # Same cache the resolution stage populated. Without this, labeling
                # re-runs classify_resolved_address (6-10 RPCs each) for every
                # principal — the dominant cost on big protocols (etherfi LP impl
                # spent 14+ min here on shared-cpu-2x).
                classify_cache=classify_cache,
                # Rebuilt against the refreshed graph so the alias-of-known scope
                # reflects every node the refresh added.
                cross_chain_recognizer=make_cross_chain_recognizer(
                    _chain_id_for_job(job), _known_addresses_for_scope(resolved_control_graph, job.address)
                ),
                # Protocol-wide exact-owner Safe registry for signer-overlap.
                # Only populated for protocol-scoped jobs; a bare contract analysis
                # has no sibling Safes to compare against.
                protocol_safe_owner_sets=(
                    load_protocol_safe_owner_sets(session, job.protocol_id) if job.protocol_id else None
                ),
                # Shared-deployer groups (witnessed heuristic fact).
                protocol_deployer_groups=(
                    load_protocol_deployer_groups(session, job.protocol_id) if job.protocol_id else None
                ),
                # Contract-principal -> ultimate Safe/EOA terminal walk.
                resolve_controllers=_make_terminal_controller_resolver(rpc_url, chain_id=_chain_id_for_job(job)),
            )
            ph["principal_count"] = len(pl_data.get("principals", []))

        # Write to principal_labels table
        if contract_row:
            session.query(PrincipalLabel).filter(
                PrincipalLabel.contract_id == contract_row.id,
                deployment_scope(PrincipalLabel.deployment_address, deployment_address),
            ).delete(synchronize_session=False)
            for p in pl_data.get("principals", []):
                if p.get("address"):
                    session.add(
                        PrincipalLabel(
                            contract_id=contract_row.id,
                            deployment_address=deployment_address,
                            address=p["address"].lower(),
                            label=p.get("display_name"),
                            display_name=p.get("display_name"),
                            resolved_type=p.get("resolved_type"),
                            labels=p.get("labels"),
                            confidence=p.get("confidence"),
                            details=p.get("details"),
                            graph_context=p.get("graph_context"),
                        )
                    )
            session.commit()

        record_stage_metric("principals_labeled", len(pl_data.get("principals", [])))

        logger.info(
            "Policy stage principal labels complete for job %s address=%s name=%s",
            job.id,
            job.address or "0x0",
            job.name or "Contract",
        )

        # Canonical cutover: graph relations and effective permissions enrich
        # the same assessment rather than becoming new sources of truth.
        from services.assessment import add_resolution

        if isinstance(resolved_control_graph, dict):
            assessment = add_resolution(assessment, resolved_control_graph, chain_id=chain_id)
        store_artifact(session, job.id, "assessment", data=assessment)

        self.update_detail(
            session,
            job,
            f"Policy analysis complete: {len(ep_data.get('functions', []))} functions, "
            f"{len(pl_data.get('principals', []))} principals",
        )
        logger.info(
            "Policy stage complete for job %s address=%s name=%s",
            job.id,
            job.address or "0x0",
            job.name or "Contract",
        )

        # Auto-enroll protocol contracts into unified monitoring
        if job.protocol_id:
            with log_timed_phase(logger, "auto_enrollment", durations_ms=durations_ms):
                try:
                    from services.monitoring.enrollment import maybe_enroll_protocol

                    enrolled = maybe_enroll_protocol(
                        session,
                        job.protocol_id,
                        rpc_url,
                        chain=chain_name,
                        exclude_job_id=job.id,
                    )
                    record_stage_metric("enrolled", bool(enrolled))
                    if enrolled:
                        logger.info(
                            "Auto-enrolled protocol %s contracts into monitoring",
                            job.protocol_id,
                        )
                        # Fast path skipped the controller pass; enqueue a drain
                        # so the reconciler runs it (enroll_controllers=True).
                        # Commit now so the initial-TVL block's rollback-on-failure
                        # below can't discard the pending dirty row.
                        from services.monitoring.enrollment import mark_enrollment_dirty

                        mark_enrollment_dirty(session, job.protocol_id, "policy_complete")
                        session.commit()
                        # Fetch DeFiLlama TVL so the protocol has a number immediately.
                        # Per-contract tracked value is already in contract_balances
                        # from the resolution stage — the hourly loop will create
                        # a full snapshot combining both.
                        try:
                            from db.models import Protocol, TvlSnapshot
                            from services.monitoring.tvl import fetch_defillama_tvl

                            proto = session.get(Protocol, job.protocol_id)
                            dl = fetch_defillama_tvl(proto.name) if proto else None
                            if dl:
                                session.add(
                                    TvlSnapshot(
                                        protocol_id=job.protocol_id,
                                        defillama_tvl=round(dl["tvl"], 2) if dl["tvl"] else None,
                                        chain_breakdown=dl["chain_breakdown"],
                                        source="defillama",
                                    )
                                )
                                session.commit()
                        except Exception as exc:
                            # Failed TVL commit poisons the session; roll back
                            # before record_degraded reads job.protocol_id.
                            session.rollback()
                            record_degraded(
                                phase="initial_tvl_snapshot",
                                exc=exc,
                                context={"protocol_id": job.protocol_id},
                            )
                            logger.warning(
                                "Initial TVL snapshot failed for protocol %s: %s",
                                job.protocol_id,
                                exc,
                                extra={"exc_type": type(exc).__name__},
                            )
                except Exception as exc:
                    # A failed enroll (e.g. a benign concurrent (address, chain)
                    # race) leaves the session pending-rollback. Roll back BEFORE
                    # reading any job attribute below and before returning to the
                    # worker's success path, so the non-fatal hiccup degrades to a
                    # logged warning instead of escalating to a terminal job failure
                    # when the poisoned session next lazy-loads. A rollback that
                    # itself fails propagates to base.py's failure handler.
                    session.rollback()
                    record_degraded(
                        phase="auto_enrollment",
                        exc=exc,
                        context={"protocol_id": job.protocol_id},
                    )
                    logger.warning(
                        "Auto-enrollment failed for protocol %s: %s",
                        job.protocol_id,
                        exc,
                        extra={"exc_type": type(exc).__name__},
                    )

        # Send completion webhook for re-analysis jobs
        request = job.request if isinstance(job.request, dict) else {}
        if request.get("reanalysis_trigger"):
            try:
                from services.monitoring.notifier import notify_reanalysis_complete

                notify_reanalysis_complete(session, job)
            except Exception as exc:
                # Notifier failure is a side effect — the reanalysis itself completed.
                # No record_degraded: this doesn't change the job's stage output.
                logger.warning(
                    "Reanalysis completion notification failed for job %s: %s",
                    job.id,
                    exc,
                    extra={"exc_type": type(exc).__name__},
                )

        logger.info(
            "policy profile: %s total=%dms",
            job.name or "Contract",
            sum(durations_ms.values()),
            extra={
                "profile_kind": "policy_profile",
                "total_ms": sum(durations_ms.values()),
                "durations_ms": dict(durations_ms),
            },
        )

    def _apply_cross_contract_claims(self, payload: Mapping[str, Any], enriched: dict[str, list[EffectMatch]]) -> None:
        for fn in payload.get("functions", []):
            fn_sig = fn.get("function") or fn.get("abi_signature")
            additions = enriched.get(fn_sig) if fn_sig else None
            if not additions:
                continue
            existing = list(fn.get("claims") or [])
            fn["claims"] = resolve_claim_precedence([*existing, *additions])

    def _enrich_cross_contract(
        self,
        session,
        job: Job,
        contract_analysis: Mapping[str, Any],
        control_snapshot: Mapping[str, Any],
        function_records: Sequence[Mapping[str, Any]] | None = None,
    ) -> dict[str, list[EffectMatch]]:
        """Mint policy-derived claims from sibling facts.

        Replaces propagate-every-label with the four typed derivations in
        ``services.static.cross_contract``: value-flow propagation, transfer-policy
        configuration, beacon upgrade, and proxy-verified upgrade provenance. The
        returned claims merge onto each function's existing claim list.

        ``function_records`` is the effective-permissions payload the rows were
        just written from. The derivations key on the Slither full_name the
        effects artifact uses, while the row stores the canonical ABI signature,
        so the two only meet through a key both sides derive identically — the
        selector, taken from that same payload rather than re-derived here.
        """
        del contract_analysis
        from services.static.cross_contract import (
            build_callee_claim_map,
            derive_cross_contract_claims,
            proxy_provenance_from_classifications,
            sibling_transfer_hook_links,
        )

        # Find sibling jobs (same company / same parent)
        request = job.request if isinstance(job.request, dict) else {}
        parent_job_id = request.get("parent_job_id")
        company = job.company

        completed_jobs = (
            session.execute(select(Job).where(Job.status == JobStatus.completed, Job.address.isnot(None)))
            .scalars()
            .all()
        )

        # Filter siblings on the main thread, extracting only scalar values
        # so the parallel fetch can use fresh sessions without touching ORM
        # objects bound to this worker's session.
        sibling_targets: list[tuple[Any, str]] = []
        for sj in completed_jobs:
            if sj.id == job.id or not sj.address:
                continue
            sj_req = sj.request if isinstance(sj.request, dict) else {}
            is_sibling = (
                (company and sj.company == company)
                or (parent_job_id and sj_req.get("parent_job_id") == parent_job_id)
                or (parent_job_id and str(sj.id) == parent_job_id)
            )
            if is_sibling:
                sibling_targets.append((sj.id, sj.address.lower()))

        if not sibling_targets:
            return {}

        def _fetch_sibling_artifacts(
            target: tuple[Any, str],
        ) -> tuple[str, dict | None, dict | None]:
            sj_id, addr = target
            with SessionLocal() as s:
                effects_payload = get_artifact(s, sj_id, "effects")
                assessment_payload = get_artifact(s, sj_id, "assessment")
            snapshot_payload = None
            if isinstance(assessment_payload, dict):
                from services.assessment import controller_observations

                snapshot_payload = controller_observations(cast(Any, assessment_payload))
            return (
                addr,
                effects_payload if isinstance(effects_payload, dict) else None,
                snapshot_payload if isinstance(snapshot_payload, dict) else None,
            )

        sibling_effects: dict[str, dict] = {}
        sibling_snapshots: dict[str, dict] = {}
        for (_sj_id, addr), outcome in parallel_map(_fetch_sibling_artifacts, sibling_targets, max_workers=8):
            if isinstance(outcome, BaseException):
                record_degraded(
                    phase="cross_contract_enrichment",
                    exc=outcome,
                    context={"sibling_address": addr, "sibling_job_id": str(_sj_id)},
                )
                logger.warning("sibling artifact fetch failed for %s: %s", addr, outcome)
                continue
            _addr, effects_payload, snapshot_payload = outcome
            if effects_payload is not None:
                sibling_effects[_addr] = effects_payload
            if snapshot_payload is not None:
                sibling_snapshots[_addr] = snapshot_payload

        if not sibling_effects:
            return {}

        callee_claim_map = build_callee_claim_map(sibling_effects)
        controller_values = control_snapshot.get("controller_values", {})
        target_effects = get_artifact(session, job.id, "effects")
        target_effects = target_effects if isinstance(target_effects, dict) else None
        target_address = (job.address or "").lower()

        hook_links = sibling_transfer_hook_links(target_address, sibling_effects, sibling_snapshots)
        deployment_address = request.get("proxy_address") or job.address or ""
        proxy_provenance = proxy_provenance_from_classifications(
            deployment_address, get_artifact(session, job.id, "classifications")
        )

        enriched = derive_cross_contract_claims(
            target_effects,
            controller_values,
            callee_claim_map,
            sibling_transfer_hooks=hook_links,
            proxy_provenance=proxy_provenance,
        )
        if enriched:
            logger.info(
                "Job %s: cross-contract enrichment added policy claims: %s",
                job.id,
                {fn_sig: [c["claim_id"] for c in claims] for fn_sig, claims in enriched.items()},
            )
            contract_row = session.execute(
                select(Contract).where(Contract.job_id == job.id).limit(1)
            ).scalar_one_or_none()
            if contract_row:
                selector_for = _selector_by_function_key(function_records)
                # The same impl row can back N proxy deployments, each with its
                # own set of function rows. These claims were derived against
                # THIS job's control snapshot, so they belong to the deployment
                # the writer tagged — mirroring its scope derivation exactly,
                # not the local ``deployment_address`` below, which falls back to
                # the job's own address for a different purpose.
                row_deployment = normalize_deployment(request.get("proxy_address"))
                for fn_sig, new_claims in enriched.items():
                    stmt = select(EffectiveFunction).where(
                        EffectiveFunction.contract_id == contract_row.id,
                        deployment_scope(EffectiveFunction.deployment_address, row_deployment),
                    )
                    selector = selector_for.get(fn_sig)
                    if selector:
                        stmt = stmt.where(EffectiveFunction.selector == selector)
                    else:
                        stmt = stmt.where(EffectiveFunction.abi_signature == fn_sig)
                    # Exactly one row, or nothing. The scope above still ORs in
                    # legacy untagged rows by design, so a tagged row and a NULL
                    # one can both answer — and reading a single row from that
                    # raises inside a stage that does not catch it, losing the
                    # whole policy run over an enrichment detail. Ambiguity is
                    # not an answer: skip it, say so, and leave the row alone.
                    matches = session.execute(stmt).scalars().all()
                    if len(matches) == 1:
                        ef = matches[0]
                        ef.claims = resolve_claim_precedence([*(ef.claims or []), *new_claims])
                    else:
                        logger.warning(
                            "Job %s: cross-contract claims for %s matched %d effective_function rows; skipped",
                            job.id,
                            fn_sig,
                            len(matches),
                            extra={
                                "phase": "cross_contract_enrichment",
                                "function": fn_sig,
                                "matched_rows": len(matches),
                            },
                        )
                session.commit()
        return enriched

    def _resolve_authority(
        self,
        session: Session,
        job: Job,
        resolved_graph: Mapping[str, Any],
        snapshot: Mapping[str, Any],
        nested_artifacts: dict[str, LoadedArtifacts],
    ) -> dict:
        """Locate nested controller context from resolution-stage DB bundles.

        The resolution worker persists per-sub-contract artifacts as
        ``recursive:<address>:<kind>`` rows. This method fetches the
        first nested snapshot referenced by the target's controller values.
        Semantic capability resolution is responsible for function-level
        principals; this snapshot only enriches controller labels/details.
        """
        del session, job, resolved_graph

        authority_address = _semantic_controller_context_address(snapshot, nested_artifacts)

        if not authority_address or authority_address == "0x0000000000000000000000000000000000000000":
            return {"principal_resolution": {"status": "no_authority", "reason": "No non-zero authority found"}}

        authority_bundle = nested_artifacts.get(authority_address)
        if authority_bundle is None or "snapshot" not in authority_bundle:
            return {
                "principal_resolution": {
                    "status": "no_authority_snapshot",
                    "reason": "Authority contract found but snapshot artifact missing",
                }
            }

        authority_snapshot = cast(dict, authority_bundle["snapshot"])

        return {
            "authority_snapshot": authority_snapshot,
            "principal_resolution": {
                "status": "complete",
                "reason": "Nested controller snapshot joined into semantic permission view",
            },
        }


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        force=True,
    )
    PolicyWorker().run_loop()


if __name__ == "__main__":
    main()
