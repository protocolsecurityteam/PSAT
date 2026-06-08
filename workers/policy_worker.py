"""Policy worker — computes effective permissions and labels principals."""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.deployment import deployment_scope, normalize_deployment
from db.models import (
    EffectiveFunction,
    Job,
    JobStage,
    JobStatus,
    PrincipalLabel,
    SessionLocal,
)
from db.nested_artifacts import ARTIFACT_KINDS, KEY_PREFIX, parse_key
from db.nested_artifacts import store_bundle as store_nested_artifacts
from db.queue import get_artifact, require_contract_for_job, store_artifact
from schemas.control_tracking import ControlSnapshot
from services.artifacts import (
    POLICY_ARTIFACT,
    get_artifact_field,
    make_job_contract,
    make_job_stage_context,
    make_stage_artifact,
)
from services.policy import build_effective_permissions, build_principal_labels
from services.policy.effective_permissions_writer import write_effective_function_rows
from services.policy.principal_history import build_principal_history
from services.policy.types import PrincipalResolution
from services.resolution.capability_resolver import _load_state_var_values
from services.resolution.recursive import LoadedArtifacts, resolve_control_graph
from services.resolution.tracking import classify_resolved_address_with_status
from utils.concurrency import parallel_map
from utils.logging import record_degraded, record_stage_metric
from utils.rpc import default_rpc_url, require_configured_erpc_url, require_supported_chain_id
from workers.base import BaseWorker

logger = logging.getLogger("workers.policy_worker")

RECURSION_MAX_DEPTH = int(os.getenv("PSAT_RECURSION_MAX_DEPTH", "6"))


def _resolve_job_chain_id(job: Job) -> int:
    chain_id = require_supported_chain_id(
        chain_id=job.chain_id,
        context=f"policy job {job.id}",
    )
    return chain_id


def _log_policy_phase(phase: str, t0: float, durations_ms: dict[str, int], **fields: Any) -> None:
    """Emit one ``policy phase complete`` line + fold ``phase_ms_<phase>`` into the
    stage_timing artifact, mirroring the inline per-phase pattern in
    ``resolution_worker``/``static_worker``. ``process()`` had lifecycle markers but
    no sub-step timing, so a slow run (e.g. the 780s CumulativeMerkleDrop policy job)
    was an opaque single number; these lines attribute it to a named sub-step."""
    ms = int((time.monotonic() - t0) * 1000)
    durations_ms[phase] = ms
    record_stage_metric(f"phase_ms_{phase}", ms)
    logger.info(
        "policy phase complete: %s (%dms)",
        phase,
        ms,
        extra={"duration_ms": ms, "phase": phase, **fields},
    )


def _make_principal_type_resolver(
    classify_cache: dict[str, tuple[str, dict[str, object]]],
    rpc_url: str,
    chain_id: int,
) -> Callable[[str], tuple[str | None, dict[str, object] | None]]:
    """Build an ``address -> (resolved_type, details)`` classifier for the FP
    writer. Reuses the resolution stage's classify cache, falling back to a
    live (process-cached) ``classify_resolved_address`` probe for misses — the
    same path ``build_principal_labels`` uses, so FunctionPrincipal rows carry
    the same Safe/Timelock/EOA typing as principal labels."""
    effective_chain_id = require_supported_chain_id(chain_id=chain_id, context="policy principal type resolver")
    rpc_url = require_configured_erpc_url(
        rpc_url,
        context="policy principal type resolver",
        chain_id=effective_chain_id,
    )
    cache_lc = {k.lower(): v for k, v in classify_cache.items()}

    def _resolve(address: str) -> tuple[str | None, dict[str, object] | None]:
        cached = cache_lc.get((address or "").lower())
        if cached:
            return cached[0], cached[1]
        resolved_type, details, _cacheable = classify_resolved_address_with_status(
            rpc_url,
            address,
            chain_id=effective_chain_id,
        )
        return resolved_type, details

    return _resolve


def _rpc_url_for_job(job: Job) -> str:
    return default_rpc_url(chain_id=job.chain_id)


def _root_artifacts(
    contract_analysis: dict,
    tracking_plan: dict,
    snapshot: ControlSnapshot,
) -> LoadedArtifacts:
    return {
        "analysis": contract_analysis,
        "tracking_plan": tracking_plan,
        "snapshot": snapshot,
    }


def _load_nested_artifacts(session: Session, job_id, *, chain_id: int) -> dict[str, LoadedArtifacts]:
    """Hydrate ``recursive.*`` artifacts written by the resolution stage.

    Resolution writes only the runtime-state slices (snapshot,
    effective_permissions) to ``recursive.*`` rows. The static slices
    (analysis, tracking_plan) live in ``contract_materializations``
    (content-addressed by ``(chain_id, bytecode_keccak)``); we hydrate them
    here per-address so the rest of policy still sees a full
    ``LoadedArtifacts`` bundle. A bundle missing analysis or tracking data is a
    pipeline inconsistency and fails the policy stage; broken materialization
    rows should not be hidden by silently dropping nested contracts.
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
    for address, bundle in bundles.items():
        mrow = cm.find_by_address(session, chain_id=chain_id, address=address)
        if mrow is None:
            logger.error(
                "policy nested artifact hydration missing materialization for %s chain_id=%s",
                address,
                chain_id,
            )
            raise RuntimeError(f"missing contract materialization for nested address={address} chain_id={chain_id}")
        analysis = cm.hydrate_analysis(mrow)
        tracking_plan = cm.hydrate_tracking_plan(mrow)
        if not analysis or not tracking_plan:
            logger.error("policy nested artifact hydration incomplete for %s chain_id=%s", address, chain_id)
            raise RuntimeError(f"incomplete contract materialization for nested address={address} chain_id={chain_id}")
        bundle["analysis"] = copy.deepcopy(analysis)
        bundle["tracking_plan"] = copy.deepcopy(tracking_plan)

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
    chain_id: int,
) -> dict[str, dict[str, Any]]:
    """Run the semantic capability resolver for ``contract_address`` against
    the in-progress job. Returns ``{function_signature: capability_dict}``
    or fails the policy stage on miss / resolver failure.

    ``chain_id`` scopes the resolver's controller-value lookup to the
    same chain as the in-progress job."""
    from services.resolution.capability_resolver import resolve_contract_capabilities

    result = resolve_contract_capabilities(
        session,
        address=contract_address,
        job_id=job_id,
        chain_id=chain_id,
    )
    if result is None:
        logger.error(
            "semantic capability resolver produced no output for %s chain_id=%s job_id=%s",
            contract_address,
            chain_id,
            job_id,
        )
        raise RuntimeError(f"semantic capability resolver produced no output for {contract_address}")
    return result


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
    snapshot: dict,
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


class PolicyWorker(BaseWorker):
    stage = JobStage.policy
    next_stage = JobStage.coverage

    def process(self, session: Session, job: Job) -> None:
        job_address = job.address
        if not job_address:
            raise RuntimeError(f"policy job {job.id} requires address")
        job_address = job_address.lower()
        logger.info(
            "Policy stage started for job %s address=%s name=%s",
            job.id,
            job_address,
            job.name or "Contract",
        )
        chain_id = _resolve_job_chain_id(job)
        request = job.request if isinstance(job.request, dict) else {}
        if job.chain_id != chain_id:
            job.chain_id = chain_id
            session.commit()
            request = job.request if isinstance(job.request, dict) else {}
        rpc_url = _rpc_url_for_job(job)
        durations_ms: dict[str, int] = {}

        # Load required artifacts from DB
        contract_analysis = get_artifact_field(session, job.id, "contract_analysis")
        control_snapshot = get_artifact_field(session, job.id, "control_snapshot")
        resolved_control_graph = get_artifact_field(session, job.id, "resolved_control_graph")
        # ``predicate_trees`` and ``effects`` are the semantic inputs to
        # ``build_effective_permissions``.
        predicate_trees = get_artifact_field(session, job.id, "predicate_trees")
        effects_artifact = get_artifact_field(session, job.id, "effects")
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
            logger.error(
                "Policy stage missing semantic inputs for job %s: %s",
                job.id,
                ", ".join(sorted(missing_semantic_inputs)),
                extra={"missing_artifacts": sorted(missing_semantic_inputs)},
            )
            raise RuntimeError(f"policy stage missing semantic inputs for job {job.id}") from exc
        tracking_plan = get_artifact_field(session, job.id, "control_tracking_plan")
        # Optional: classify cache populated by the resolution stage. Lets the
        # refresh + labeling passes skip 6-10 RPCs per address.
        classify_cache_raw = get_artifact_field(session, job.id, "classified_addresses")
        classify_cache: dict[str, tuple[str, dict[str, object]]] = {}
        if isinstance(classify_cache_raw, dict):
            for addr, val in classify_cache_raw.items():
                if isinstance(val, list) and len(val) == 2:
                    classify_cache[addr] = (str(val[0]), dict(val[1]) if isinstance(val[1], dict) else {})

        if not isinstance(contract_analysis, dict):
            raise RuntimeError("static_analysis_artifact missing contract_analysis")
        if not isinstance(control_snapshot, dict):
            raise RuntimeError("resolution_artifact missing control_snapshot")

        nested_artifacts = _load_nested_artifacts(session, job.id, chain_id=chain_id)

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
            logger.info(
                "Policy stage authority resolution for job %s address=%s status=%s",
                job.id,
                job_address,
                principal_resolution.get("status", "unknown"),
            )

        # Build effective permissions
        self.update_detail(session, job, "Computing effective permissions")

        # Resolve per-function CapabilityExpr now so the artifact builder
        # and writer use the same semantic principal source.
        # Pass job.id — without it the resolver's default
        # ``Job.status==completed`` filter skips the in-progress job.
        capability_resolver_output: dict[str, dict[str, Any]] | None = None
        if isinstance(predicate_trees, dict) and job.address:
            cap_t0 = time.monotonic()
            capability_resolver_output = _resolve_semantic_capabilities(
                session,
                contract_address=job_address,
                job_id=job.id,
                chain_id=chain_id,
            )
            _log_policy_phase(
                "semantic_capabilities",
                cap_t0,
                durations_ms,
                function_count=len(capability_resolver_output or {}),
            )

        ep_t0 = time.monotonic()
        ep_data: dict = cast(
            dict,
            build_effective_permissions(
                contract_analysis,
                target_snapshot=control_snapshot,
                authority_snapshot=authority_snapshot,
                principal_resolution=principal_resolution,
                predicate_trees=predicate_trees if isinstance(predicate_trees, dict) else None,
                capability_resolver_output=capability_resolver_output,
                effects=effects_artifact if isinstance(effects_artifact, dict) else None,
            ),
        )
        _log_policy_phase(
            "effective_permissions",
            ep_t0,
            durations_ms,
            function_count=len(ep_data.get("functions", [])) if isinstance(ep_data, dict) else 0,
        )

        # Write to effective_functions and function_principals tables from
        # resolver-native semantic capability rows only.
        # An impl analyzed in proxy context resolves against the proxy's storage;
        # tag its rows with that deployment so a shared impl can hold N sets.
        deployment_address = normalize_deployment(
            (job.request if isinstance(job.request, dict) else {}).get("proxy_address")
        )
        contract_row = require_contract_for_job(session, job, context=f"policy effective function write for {job.id}")
        if isinstance(ep_data, dict):
            graph_nodes = resolved_control_graph.get("nodes") if isinstance(resolved_control_graph, dict) else None
            safe_lookup = _safe_address_lookup_from_graph(graph_nodes if isinstance(graph_nodes, list) else None)

            rows_t0 = time.monotonic()
            fp_added = write_effective_function_rows(
                session,
                contract_id=contract_row.id,
                function_records=ep_data.get("functions", []),
                capability_by_function=capability_resolver_output,
                safe_address_lookup=safe_lookup or None,
                resolve_principal_type=_make_principal_type_resolver(classify_cache, rpc_url, chain_id),
                deployment_address=deployment_address,
            )
            session.commit()
            _log_policy_phase("effective_function_rows", rows_t0, durations_ms, function_principals=fp_added)
            record_stage_metric("function_principals", fp_added)

        record_stage_metric("effective_functions", len(ep_data.get("functions", [])))
        principal_history: dict | None = None
        if contract_row and isinstance(predicate_trees, dict):
            ph_t0 = time.monotonic()
            state_var_values = _load_state_var_values(
                session,
                contract_row.address,
                job_id=job.id,
                chain_id=chain_id,
            )
            principal_history = build_principal_history(
                contract_address=contract_row.address,
                chain_id=chain_id,
                predicate_trees=predicate_trees,
                state_var_values=state_var_values,
            )
            _log_policy_phase("principal_history", ph_t0, durations_ms)

        logger.info(
            "Policy stage effective permissions complete for job %s address=%s name=%s",
            job.id,
            job_address,
            job.name or "Contract",
        )

        # Rebuild the resolved graph now that effective_permissions exists,
        # so semantic role/controller principals can be projected into the graph.
        # The refresh reuses the nested artifacts persisted during resolution.
        self.update_detail(session, job, "Refreshing resolved control graph")
        if not isinstance(tracking_plan, dict):
            tracking_plan = {}
        # Attach the target contract's updated effective_permissions to the
        # root bundle so role/controller principals can be projected when
        # re-traversing the graph.
        root_bundle = _root_artifacts(contract_analysis, tracking_plan, cast(ControlSnapshot, control_snapshot))
        root_bundle["effective_permissions"] = ep_data
        graph_t0 = time.monotonic()
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
            # Persist any newly materialized nested artifacts (rare — most come
            # from resolution stage already).
            new_addresses = set(refreshed_nested) - set(nested_artifacts)
            if new_addresses:
                store_nested_artifacts(
                    session,
                    job.id,
                    {addr: refreshed_nested[addr] for addr in new_addresses},
                )
        _log_policy_phase(
            "graph_refresh",
            graph_t0,
            durations_ms,
            graph_nodes=len(resolved_control_graph.get("nodes", [])) if isinstance(resolved_control_graph, dict) else 0,
        )

        # Label principals
        self.update_detail(session, job, "Labeling principals")
        labels_t0 = time.monotonic()
        pl_data = build_principal_labels(
            ep_data,
            resolved_control_graph=(
                cast(dict, resolved_control_graph) if isinstance(resolved_control_graph, dict) else None
            ),
            rpc_url=rpc_url,
            # Same cache the resolution stage populated. Without this, labeling
            # re-runs classify_resolved_address (6-10 RPCs each) for every
            # principal — the dominant cost on big protocols (etherfi LP impl
            # spent 14+ min here on shared-cpu-2x).
            classify_cache=classify_cache,
        )
        _log_policy_phase(
            "principal_labels",
            labels_t0,
            durations_ms,
            principal_count=len(pl_data.get("principals", [])),
        )

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
            job_address,
            job.name or "Contract",
        )

        # Cross-contract effect enrichment: propagate labels across contract boundaries
        enrich_t0 = time.monotonic()
        enriched = self._enrich_cross_contract(session, job, contract_analysis, control_snapshot)
        if enriched and ep_data is not None:
            self._apply_effect_label_updates(ep_data, enriched)
        _log_policy_phase("cross_contract_enrichment", enrich_t0, durations_ms)

        policy_payload = {
            "effective_permissions": ep_data,
            "principal_labels": pl_data,
            "resolved_control_graph": resolved_control_graph if isinstance(resolved_control_graph, dict) else None,
            "principal_history": principal_history,
        }
        policy_artifact = make_stage_artifact(
            kind=POLICY_ARTIFACT,
            stage="policy",
            schema_version="policy.v1",
            context=make_job_stage_context(
                job,
                stage="policy",
                schema_version="policy.v1",
                block_number=control_snapshot.get("block_number") if isinstance(control_snapshot, dict) else None,
            ),
            contract=make_job_contract(session, job, contract_row),
            data=policy_payload,
        )
        store_artifact(session, job.id, POLICY_ARTIFACT, data=policy_artifact)

        self.update_detail(
            session,
            job,
            f"Policy analysis complete: {len(ep_data.get('functions', []))} functions, "
            f"{len(pl_data.get('principals', []))} principals",
        )
        logger.info(
            "Policy stage complete for job %s address=%s name=%s",
            job.id,
            job_address,
            job.name or "Contract",
        )

        # Auto-enroll protocol contracts into unified monitoring
        if job.protocol_id:
            enroll_t0 = time.monotonic()
            try:
                from services.monitoring.enrollment import maybe_enroll_protocol

                enrolled = maybe_enroll_protocol(
                    session,
                    job.protocol_id,
                    rpc_url,
                    chain_id=chain_id,
                    exclude_job_id=job.id,
                )
                record_stage_metric("enrolled", bool(enrolled))
                if enrolled:
                    logger.info(
                        "Auto-enrolled protocol %s contracts into monitoring",
                        job.protocol_id,
                    )
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
                record_degraded(
                    phase="auto_enrollment",
                    exc=exc,
                    context={"protocol_id": job.protocol_id},
                )
                logger.error(
                    "Auto-enrollment failed for protocol %s: %s",
                    job.protocol_id,
                    exc,
                    extra={"exc_type": type(exc).__name__},
                )
                raise RuntimeError(f"auto-enrollment failed for protocol {job.protocol_id}") from exc
            _log_policy_phase("auto_enrollment", enroll_t0, durations_ms)

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

    def _apply_effect_label_updates(self, payload: dict, enriched: dict[str, list[str]]) -> None:
        for fn in payload.get("functions", []):
            fn_sig = fn.get("function") or fn.get("abi_signature")
            if not fn_sig:
                continue
            new_labels = enriched.get(fn_sig)
            if not new_labels:
                continue
            existing = set(fn.get("effect_labels") or [])
            fn["effect_labels"] = sorted(existing | set(new_labels))

    def _enrich_cross_contract(
        self, session, job: Job, contract_analysis: dict, control_snapshot: dict
    ) -> dict[str, list[str]]:
        """Propagate effect labels across contract boundaries.

        For each external call this contract makes, look up the callee's analysis
        and propagate its effect labels to the calling function.
        """
        from services.static.cross_contract import build_callee_effect_map, enrich_cross_contract_effects

        # Find sibling jobs (same company / same parent)
        request = job.request if isinstance(job.request, dict) else {}
        parent_job_id = request.get("parent_job_id")
        company = job.company
        chain_id = _resolve_job_chain_id(job)

        # Collect analyses of completed sibling contracts on the same chain.
        # The cross-contract helper is keyed by address because controller
        # values only carry addresses; constraining the sibling set keeps that
        # map from mixing same-address deployments across chains.
        completed_jobs = (
            session.execute(
                select(Job).where(
                    Job.status == JobStatus.completed,
                    Job.address.isnot(None),
                    Job.chain_id == chain_id,
                )
            )
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

        def _fetch_sibling_analysis(
            target: tuple[Any, str],
        ) -> tuple[str, dict | None, dict | None]:
            sj_id, addr = target
            with SessionLocal() as s:
                payload = get_artifact_field(s, sj_id, "contract_analysis")
                effects_payload = get_artifact_field(s, sj_id, "effects")
            return (
                addr,
                payload if isinstance(payload, dict) else None,
                effects_payload if isinstance(effects_payload, dict) else None,
            )

        sibling_analyses: dict[str, dict] = {}
        sibling_effects: dict[str, dict] = {}
        for (_sj_id, addr), outcome in parallel_map(_fetch_sibling_analysis, sibling_targets, max_workers=8):
            if isinstance(outcome, BaseException):
                record_degraded(
                    phase="cross_contract_enrichment",
                    exc=outcome,
                    context={"sibling_address": addr, "sibling_job_id": str(_sj_id)},
                )
                logger.warning("sibling artifact fetch failed for %s: %s", addr, outcome)
                continue
            _addr, payload, effects_payload = outcome
            if payload is not None:
                sibling_analyses[_addr] = payload
            if effects_payload is not None:
                sibling_effects[_addr] = effects_payload

        if not sibling_analyses:
            return {}

        callee_map = build_callee_effect_map(sibling_analyses, effects_by_address=sibling_effects)
        controller_values = control_snapshot.get("controller_values", {})
        target_effects = get_artifact_field(session, job.id, "effects")

        enriched = enrich_cross_contract_effects(
            contract_analysis,
            controller_values,
            callee_map,
            target_effects=target_effects if isinstance(target_effects, dict) else None,
        )
        if enriched:
            logger.info(
                "Job %s: cross-contract enrichment added labels: %s",
                job.id,
                enriched,
            )
            # Update the effective_functions table with new labels
            contract_row = require_contract_for_job(session, job, context=f"policy enrichment write for {job.id}")
            for fn_sig, new_labels in enriched.items():
                ef = session.execute(
                    select(EffectiveFunction).where(
                        EffectiveFunction.contract_id == contract_row.id,
                        EffectiveFunction.abi_signature == fn_sig,
                    )
                ).scalar_one_or_none()
                if ef:
                    existing = set(ef.effect_labels or [])
                    ef.effect_labels = sorted(existing | set(new_labels))
            session.commit()
        return enriched

    def _resolve_authority(
        self,
        session: Session,
        job: Job,
        resolved_graph: dict,
        snapshot: dict,
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
