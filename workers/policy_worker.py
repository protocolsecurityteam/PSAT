"""Policy worker — computes effective permissions and labels principals."""

from __future__ import annotations

import logging
import os
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import (
    Contract,
    EffectiveFunction,
    Job,
    JobStage,
    JobStatus,
    PrincipalLabel,
    SessionLocal,
)
from db.nested_artifacts import ARTIFACT_KINDS, KEY_PREFIX, parse_key
from db.nested_artifacts import store_bundle as store_nested_artifacts
from db.queue import get_artifact, store_artifact
from schemas.control_tracking import ControlSnapshot
from schemas.effective_permissions import PrincipalResolution
from services.policy import build_effective_permissions, build_principal_labels
from services.policy.effective_permissions_writer import write_effective_function_rows
from services.policy.principal_history import build_principal_history
from services.resolution.capability_resolver import _load_state_var_values
from services.resolution.recursive import LoadedArtifacts, resolve_control_graph
from utils.concurrency import parallel_map
from utils.logging import record_degraded
from utils.rpc import PUBLIC_ETH_RPC_URL, default_rpc_url
from workers.base import BaseWorker

logger = logging.getLogger("workers.policy_worker")

DEFAULT_RPC_URL = os.getenv("ETH_RPC", PUBLIC_ETH_RPC_URL)
RECURSION_MAX_DEPTH = int(os.getenv("PSAT_RECURSION_MAX_DEPTH", "6"))
CHAIN_IDS = {"ethereum": 1, "mainnet": 1}


def _rpc_url_for_job(job: Job) -> str:
    request = job.request if isinstance(job.request, dict) else {}
    explicit = request.get("rpc_url")
    chain = request.get("chain")
    return (
        default_rpc_url(
            explicit_rpc_url=explicit if isinstance(explicit, str) else None,
            chain_id=request.get("chain_id"),
            chain=chain if isinstance(chain, str) else None,
            fallback_url=os.getenv("ETH_RPC") or DEFAULT_RPC_URL,
        )
        or DEFAULT_RPC_URL
    )


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


def _load_nested_artifacts(session: Session, job_id) -> dict[str, LoadedArtifacts]:
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
    # Address-keyed lookup matches the chain default the resolution
    # writer uses; on a row miss we drop the bundle below since the
    # downstream consumers can't operate without analysis.
    chain = os.getenv("PSAT_DEFAULT_CHAIN", "ethereum")
    for address, bundle in bundles.items():
        try:
            mrow = cm.find_by_address(session, chain=chain, address=address)
        except Exception:
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
) -> dict[str, dict[str, Any]] | None:
    """Run the semantic capability resolver for ``contract_address`` against
    the in-progress job. Returns ``{function_signature: capability_dict}``
    or None on miss / failure.

    ``chain`` (e.g. ``"ethereum"``) plumbs through to the resolver's
    ``_load_state_var_values`` so the controller-value lookup is
    scoped by ``(job_id, chain)`` per Wave 4 C.1. The resolver also
    derives this from ``job.request['chain']`` when None is passed,
    so passing it here is belt-and-suspenders."""
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
        logger.info(
            "Policy stage started for job %s address=%s name=%s",
            job.id,
            job.address or "0x0",
            job.name or "Contract",
        )
        rpc_url = _rpc_url_for_job(job)

        # Load required artifacts from DB
        contract_analysis = get_artifact(session, job.id, "contract_analysis")
        control_snapshot = get_artifact(session, job.id, "control_snapshot")
        resolved_control_graph = get_artifact(session, job.id, "resolved_control_graph")
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
        tracking_plan = get_artifact(session, job.id, "control_tracking_plan")
        # Optional: classify cache populated by the resolution stage. Lets the
        # refresh + labeling passes skip 6-10 RPCs per address.
        classify_cache_raw = get_artifact(session, job.id, "classified_addresses")
        classify_cache: dict[str, tuple[str, dict[str, object]]] = {}
        if isinstance(classify_cache_raw, dict):
            for addr, val in classify_cache_raw.items():
                if isinstance(val, list) and len(val) == 2:
                    classify_cache[addr] = (str(val[0]), dict(val[1]) if isinstance(val[1], dict) else {})

        if not isinstance(contract_analysis, dict):
            raise RuntimeError("contract_analysis artifact not found")
        if not isinstance(control_snapshot, dict):
            raise RuntimeError("control_snapshot artifact not found")

        nested_artifacts = _load_nested_artifacts(session, job.id)

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
                job.address or "0x0",
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
            job_chain = job.request.get("chain") if isinstance(job.request, dict) else None
            capability_resolver_output = _resolve_semantic_capabilities(
                session,
                contract_address=(job.address or "").lower(),
                job_id=job.id,
                chain=job_chain if isinstance(job_chain, str) else None,
            )

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

        # Write to effective_functions and function_principals tables from
        # resolver-native semantic capability rows only.
        contract_row = session.execute(select(Contract).where(Contract.job_id == job.id).limit(1)).scalar_one_or_none()
        if contract_row and isinstance(ep_data, dict):
            graph_nodes = resolved_control_graph.get("nodes") if isinstance(resolved_control_graph, dict) else None
            safe_lookup = _safe_address_lookup_from_graph(graph_nodes if isinstance(graph_nodes, list) else None)

            write_effective_function_rows(
                session,
                contract_id=contract_row.id,
                function_records=ep_data.get("functions", []),
                capability_by_function=capability_resolver_output,
                safe_address_lookup=safe_lookup or None,
            )
            session.commit()

        store_artifact(session, job.id, "effective_permissions", data=ep_data)
        if contract_row and isinstance(predicate_trees, dict):
            job_chain = job.request.get("chain") if isinstance(job.request, dict) else None
            chain_id = CHAIN_IDS.get(str(job_chain or "ethereum").lower(), 1)
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
        if not isinstance(tracking_plan, dict):
            tracking_plan = {}
        # Attach the target contract's updated effective_permissions to the
        # root bundle so role/controller principals can be projected when
        # re-traversing the graph.
        root_bundle = _root_artifacts(contract_analysis, tracking_plan, cast(ControlSnapshot, control_snapshot))
        root_bundle["effective_permissions"] = ep_data
        refreshed_graph, refreshed_nested = resolve_control_graph(
            root_artifacts=root_bundle,
            rpc_url=rpc_url,
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
            store_artifact(session, job.id, "resolved_control_graph", data=refreshed_graph)
            # Persist any newly materialized nested artifacts (rare — most come
            # from resolution stage already).
            new_addresses = set(refreshed_nested) - set(nested_artifacts)
            if new_addresses:
                store_nested_artifacts(
                    session,
                    job.id,
                    {addr: refreshed_nested[addr] for addr in new_addresses},
                )

        # Label principals
        self.update_detail(session, job, "Labeling principals")
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

        # Write to principal_labels table
        if contract_row:
            session.query(PrincipalLabel).filter(PrincipalLabel.contract_id == contract_row.id).delete()
            for p in pl_data.get("principals", []):
                if p.get("address"):
                    session.add(
                        PrincipalLabel(
                            contract_id=contract_row.id,
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

        store_artifact(session, job.id, "principal_labels", data=pl_data)

        logger.info(
            "Policy stage principal labels complete for job %s address=%s name=%s",
            job.id,
            job.address or "0x0",
            job.name or "Contract",
        )

        # Cross-contract effect enrichment: propagate labels across contract boundaries
        enriched = self._enrich_cross_contract(session, job, contract_analysis, control_snapshot)
        if enriched and ep_data is not None:
            self._apply_effect_label_updates(ep_data, enriched)
            store_artifact(session, job.id, "effective_permissions", data=ep_data)

        self.update_detail(session, job, "Policy analysis complete")
        logger.info(
            "Policy stage complete for job %s address=%s name=%s",
            job.id,
            job.address or "0x0",
            job.name or "Contract",
        )

        # Auto-enroll protocol contracts into unified monitoring
        if job.protocol_id:
            try:
                from services.monitoring.enrollment import maybe_enroll_protocol

                enrolled = maybe_enroll_protocol(
                    session,
                    job.protocol_id,
                    rpc_url,
                    chain="ethereum",
                    exclude_job_id=job.id,
                )
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

        # Collect analyses of all completed sibling contracts
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

        def _fetch_sibling_analysis(
            target: tuple[Any, str],
        ) -> tuple[str, dict | None, dict | None]:
            sj_id, addr = target
            with SessionLocal() as s:
                payload = get_artifact(s, sj_id, "contract_analysis")
                effects_payload = get_artifact(s, sj_id, "effects")
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
        target_effects = get_artifact(session, job.id, "effects")

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
            contract_row = session.execute(
                select(Contract).where(Contract.job_id == job.id).limit(1)
            ).scalar_one_or_none()
            if contract_row:
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
