"""Policy worker: computes effective permissions and labels principals."""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Collection, Mapping
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.deployment import deployment_scope, normalize_deployment
from db.models import (
    Contract,
    Job,
    JobStage,
    PrincipalLabel,
    SessionLocal,
    derive_job_chain_id,
)
from db.nested_artifacts import ARTIFACT_KINDS, KEY_PREFIX, parse_key
from db.nested_artifacts import store_bundle as store_nested_artifacts
from db.queue import get_artifact, store_artifact, usable_semantic_artifact
from db.queue.artifacts import failed_semantic_artifact
from schemas.control_tracking import ControlSnapshot
from schemas.effective_permissions import PrincipalResolution
from services.clients.rpc import require_rpc_url
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
from services.policy.cross_contract_enrichment import (
    apply_claims_to_payload,
    call_address,
    describe_gaps,
    fetch_sibling_facts,
    proxy_coverage,
    related_jobs_with_facts,
    relevant_siblings,
    selector_by_function_key,
    write_claims_to_rows,
    write_gaps,
)
from services.policy.effective_permissions_writer import write_effective_function_rows
from services.policy.principal_enrichment import load_protocol_deployer_groups, load_protocol_safe_owner_sets
from services.policy.principal_history import build_principal_history
from services.policy.stale_policy import clear_policy_stale
from services.resolution.capability_resolver import _load_state_var_values
from services.resolution.cross_chain_authority import make_cross_chain_recognizer
from services.resolution.graph_tables import replace_control_graph_rows
from services.resolution.recursive import LoadedArtifacts, resolve_control_graph, unsettled_replay_addresses
from services.resolution.tracking import classify_resolved_address_with_status, read_contract_controllers
from services.static.claims import Claim
from utils.chains import UnknownChainError, chain_by_id, chain_by_name, require_chain
from utils.logging import log_timed_phase, record_degraded, record_stage_metric
from workers.base import BaseWorker
from workers.retry_policy import classify

logger = logging.getLogger("workers.policy_worker")

RECURSION_MAX_DEPTH = int(os.getenv("PSAT_RECURSION_MAX_DEPTH", "6"))

# Each sub-step in ``process()`` is wrapped in ``utils.logging.log_timed_phase`` so a slow job (e.g. a 780s policy run)
# can be attributed to a step; durations are recorded even when a step raises. ``durations_ms`` feeds the closing
# profile line.


def _make_principal_type_resolver(
    classify_cache: dict[str, tuple[str, dict[str, object]]],
    rpc_url: str | None,
    cross_chain_recognizer: Callable[[str], tuple[str, dict[str, object]] | None] | None = None,
    *,
    chain_id: int | None = None,
) -> Callable[[str], tuple[str | None, dict[str, object] | None]]:
    """An ``address -> (resolved_type, details)`` classifier for the FP writer: the resolution classify cache, else a
    live ``classify_resolved_address`` probe (the same path as ``build_principal_labels``, so typings match).
    ``cross_chain_recognizer`` runs first when given (``None`` on chains without bridge constants).
    """
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
    """The ``address -> [controller-step, ...] | None`` resolver for the contract-principal terminal walk: reads
    ``owner()``/``authority()``/``admin()`` and classifies each, so ``resolve_terminal_principal`` can chain to a
    Safe/EOA and fail closed on parallel planes (Solmate/Solady ``Auth``). ``None`` without an RPC URL (the walk
    is skipped).
    """
    if not rpc_url:
        return None

    def _resolve(address: str) -> list[dict[str, object]] | None:
        controllers = read_contract_controllers(rpc_url, address, chain_id=chain_id)
        if controllers is None:
            # A probe error: the plane set isn't known this round, reported as ``unknown_unfetched``.
            return None
        if not controllers:
            # Every getter answered and named nothing: reported as ``controllers_not_determined``. Distinct from
            # ``None``, but neither proves there's no controller.
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
    """Known addresses for cross-chain alias recognition (every resolved graph node plus the target); an aliased L1
    owner is only labelled when its implied L1 address is one of these.
    """
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
    """eRPC URL for the job's chain via ``jobs.chain_id`` (``_chain_id_for_job``); the request JSONB lacks the
    mainnet default for chainless submissions.
    """
    request = job.request if isinstance(job.request, dict) else {}
    explicit = request.get("rpc_url")
    return require_rpc_url(
        explicit_rpc_url=explicit if isinstance(explicit, str) else None,
        chain_id=_chain_id_for_job(job),
        context=f"policy rpc for job {job.id}",
    )


def _chain_id_for_job(job: Job) -> int:
    """The job's ``chain_id``: the column, else derived from ``request["chain"]``, else mainnet."""
    chain_id = getattr(job, "chain_id", None)
    if isinstance(chain_id, int):
        return chain_id
    request = job.request if isinstance(job.request, dict) else {}
    return derive_job_chain_id(request.get("chain"), job.address) or 1


def _chain_name_for_job(job: Job) -> str:
    """Canonical chain name (mainnet is ``"ethereum"``), matching what resolution materialized under, for the cache
    key and enrollment.
    """
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
    """Write the perimeter ledger, even after the walk raised.

    Best-effort and must never mask the original exception. After a mid-loop raise the session is usually poisoned, so
    retry on a fresh session (like ``BaseWorker._persist_stage_errors``). *artifact_name* selects the spawn summary or
    ``fp_materialization_summary``; both need this.
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
    # Same engine as the session it replaces; the global default can differ (tests, multi-DB).
    fresh = Session(bind=session.get_bind())
    try:
        store_artifact(fresh, job.id, artifact_name, data=spawn_result)
        fresh.commit()
    except Exception as exc:
        # An absent ledger means "predates the ledger", so a failed write would publish something false; record it.
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
    contract_analysis: dict,
    tracking_plan: dict,
    snapshot: ControlSnapshot,
    *,
    proxy_address: str | None = None,
) -> LoadedArtifacts:
    """The graph root's bundle. An impl job roots at its proxy, as resolution does: the proxy holds the state and emits
    the events the root's mapping replay reads.
    """
    if proxy_address:
        tracking_plan = {**tracking_plan, "contract_address": proxy_address}
        contract_analysis = {
            **contract_analysis,
            "subject": {**contract_analysis.get("subject", {}), "address": proxy_address},
        }
    return {
        "analysis": contract_analysis,
        "tracking_plan": tracking_plan,
        "snapshot": snapshot,
    }


def _materialization_by_bytecode(
    session: Session, address: str, *, chain: str, rpc_url: str, chain_id: int
) -> tuple[str, Any] | None:
    """``(analysed address, materialization)`` for *address*, found the way resolution's walk found it: a proxy is
    analysed as its implementation, and the row is looked up by that code's keccak, since a row stays bound to the first
    address that built it.
    """
    from db import contract_materializations as cm
    from services.clients.rpc import get_code_with_keccak
    from services.discovery.classifier import classify_single

    classification = classify_single(address, rpc_url, chain_id=chain_id)
    effective = address
    if classification.get("type") == "proxy":
        impl = classification.get("implementation")
        if not isinstance(impl, str) or not impl:
            return None
        effective = impl.lower()
    _code, keccak = get_code_with_keccak(rpc_url, effective, chain_id=chain_id)
    if not keccak:
        return None
    row = cm.find_by_keccak(session, chain=chain, bytecode_keccak=keccak)
    return (effective, row) if row is not None else None


def _load_nested_artifacts(
    session: Session,
    job_id,
    *,
    chain: str,
    replay_trees_for: Collection[str] = (),
    rpc_url: str | None = None,
    chain_id: int | None = None,
) -> dict[str, LoadedArtifacts]:
    """Hydrate the resolution stage's ``recursive.*`` artifacts.

    Those rows hold only runtime slices (snapshot, effective_permissions); analysis and tracking_plan come from
    ``contract_materializations`` per address. Bundles missing analysis or snapshot are dropped (``_resolve_authority``
    and the graph refresh need both). ``replay_trees_for`` names the addresses whose mapping-member replay the refresh
    re-runs, which also need their predicate trees; one with no row at its own address (a proxy, or code first built
    at another address) is hydrated by bytecode, given ``rpc_url`` and ``chain_id``.
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

    # Keyed on the job's chain name (as resolution materialized); a chainless call is a data bug and fails loud. A row
    # miss drops the bundle.
    require_chain(chain=chain, context="policy nested-artifact hydration")
    for address, bundle in bundles.items():
        lookup_failed = False
        try:
            mrow = cm.find_by_address(session, chain=chain, address=address)
        except Exception as exc:
            # Roll back so one DB error doesn't drop every remaining bundle. A row miss is expected (silent); a DB error
            # isn't.
            session.rollback()
            # ``bundle_*`` because ``address``/``chain`` are bound context fields and the formatter drops colliding
            # extras.
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
            lookup_failed = True
        analysed_address: str | None = None
        if mrow is None and not lookup_failed and address in replay_trees_for and rpc_url and chain_id is not None:
            try:
                found = _materialization_by_bytecode(session, address, chain=chain, rpc_url=rpc_url, chain_id=chain_id)
            except Exception as exc:
                session.rollback()
                record_degraded(
                    phase="nested_bytecode_hydration",
                    exc=exc,
                    context={"job_id": str(job_id), "bundle_address": address, "bundle_chain": chain},
                )
                logger.warning(
                    "Bytecode hydration failed for %s on %s; its mapping replay is not re-run",
                    address,
                    chain,
                    extra={"exc_type": type(exc).__name__, "bundle_address": address, "bundle_chain": chain},
                )
                found = None
            if found is not None:
                analysed_address, mrow = found
        if mrow is None:
            continue
        if mrow.analysis:
            bundle["analysis"] = copy.deepcopy(mrow.analysis)
        if mrow.tracking_plan:
            bundle["tracking_plan"] = copy.deepcopy(mrow.tracking_plan)
        if analysed_address is not None:
            # As resolution materialized it: the analysed code's subject, storage read at the node.
            if isinstance(bundle.get("analysis"), dict):
                bundle["analysis"]["subject"] = {**bundle["analysis"].get("subject", {}), "address": analysed_address}
            if isinstance(bundle.get("tracking_plan"), dict):
                bundle["tracking_plan"]["contract_address"] = address
        if address in replay_trees_for:
            try:
                trees = cm.hydrate_predicate_trees(mrow)
            except Exception as exc:
                # Without trees the walk keeps the node's stored status and skips its replay; the stage still runs.
                record_degraded(
                    phase="nested_replay_trees_hydration",
                    exc=exc,
                    context={"job_id": str(job_id), "bundle_address": address, "bundle_chain": chain},
                )
                logger.warning(
                    "Predicate-tree hydration failed for %s on %s; its mapping replay is not re-run",
                    address,
                    chain,
                    extra={"exc_type": type(exc).__name__, "bundle_address": address, "bundle_chain": chain},
                )
                trees = None
            if isinstance(trees, dict) and not failed_semantic_artifact("predicate_trees", trees):
                bundle["predicate_trees"] = {k: trees[k] for k in ("trees", "check_trees") if k in trees}

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
    """Run the semantic capability resolver for ``contract_address`` against the in-progress job;
    ``{function_signature: capability_dict}`` or None.

    ``chain`` scopes the controller-value lookup by ``(job_id, chain)``. ``chain_id`` is required so reads use the job's
    real chain rather than mainnet.
    """
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
    """``{function_signature: safe_address}`` from the resolved graph, for the threshold_group writer's synthetic
    Safe row. Falls back to ``{"default": first_safe}``; ``{}`` when there are no Safes (the writer uses the
    zero-address sentinel).
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

    # Nothing assigns ``self.next_stage``; a property avoids pyright's clash with the base's writable attribute.
    @property
    def next_stage(self) -> JobStage:  # pyright: ignore[reportIncompatibleVariableOverride]
        """Route into ``effects`` only when ``PSAT_EFFECTS_STAGE`` is set, else to ``coverage``.

        The flag gates the transition itself, since a job parked at an undrained stage would wait forever.
        """
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

        contract_analysis = get_artifact(session, job.id, "contract_analysis")
        control_snapshot = get_artifact(session, job.id, "control_snapshot")
        resolved_control_graph = get_artifact(session, job.id, "resolved_control_graph")
        # The semantic inputs to ``build_effective_permissions``.
        predicate_trees = usable_semantic_artifact("predicate_trees", get_artifact(session, job.id, "predicate_trees"))
        effects_artifact = usable_semantic_artifact("effects", get_artifact(session, job.id, "effects"))
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
        # The resolution stage's classify cache saves several RPCs per address.
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

        request = job.request if isinstance(job.request, dict) else {}
        root_address = str(request.get("proxy_address") or job.address or "").lower()
        nested_artifacts = _load_nested_artifacts(
            session,
            job.id,
            chain=chain_name,
            # The root replays from its own bundle.
            replay_trees_for=unsettled_replay_addresses(resolved_control_graph) - {root_address},
            rpc_url=rpc_url,
            chain_id=chain_id,
        )

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

        self.update_detail(session, job, "Computing effective permissions")

        # Resolve capabilities now so the artifact builder and writer share one source. Pass job.id so the resolver
        # doesn't skip the in-progress job.
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
            ph["function_count"] = len(ep_data.get("functions", [])) if isinstance(ep_data, dict) else 0

        # Rows come from resolver capabilities only. An impl in proxy context is tagged with that deployment so a shared
        # impl can hold several sets.
        deployment_address = normalize_deployment(
            (job.request if isinstance(job.request, dict) else {}).get("proxy_address")
        )
        contract_row = session.execute(
            select(Contract).where(Contract.job_id == job.id).order_by(Contract.id).limit(1)
        ).scalar_one_or_none()
        # Every DB write below needs contract_row; without one the job succeeds with zero rows, so make that visible.
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
        # ``None`` on chains without bridge constants. Uses the job's chain id, since the local one is later re-derived
        # and can become 1.
        cross_chain_recognizer = make_cross_chain_recognizer(
            _chain_id_for_job(job), _known_addresses_for_scope(resolved_control_graph, job.address)
        )
        if contract_row and isinstance(ep_data, dict):
            graph_nodes = resolved_control_graph.get("nodes") if isinstance(resolved_control_graph, dict) else None
            safe_lookup = _safe_address_lookup_from_graph(graph_nodes if isinstance(graph_nodes, list) else None)

            # Capture principals before the rewrite: dropped ones are only reachable through the pre-image.
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

        store_artifact(session, job.id, "effective_permissions", data=ep_data)
        record_stage_metric("effective_functions", len(ep_data.get("functions", [])))
        if contract_row and isinstance(predicate_trees, dict):
            job_chain = job.request.get("chain") if isinstance(job.request, dict) else None
            # Registry-derived chain id; unknown chains fall back to mainnet.
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

        # Rebuild the graph now that effective_permissions exists, so role/controller principals are projected, reusing
        # resolution's nested artifacts.
        self.update_detail(session, job, "Refreshing resolved control graph")
        if not isinstance(tracking_plan, dict):
            tracking_plan = {}
        # Attach the updated effective_permissions so role principals can be projected.
        root_bundle = _root_artifacts(
            contract_analysis,
            tracking_plan,
            cast(ControlSnapshot, control_snapshot),
            proxy_address=request.get("proxy_address"),
        )
        root_bundle["effective_permissions"] = ep_data
        # The root always re-walks; its trees let it re-run its mapping-member replay.
        root_bundle["predicate_trees"] = predicate_trees if isinstance(predicate_trees, dict) else None
        with log_timed_phase(logger, "graph_refresh", durations_ms=durations_ms) as ph:
            refreshed_graph, refreshed_nested = resolve_control_graph(
                root_artifacts=root_bundle,
                rpc_url=rpc_url,
                chain_id=chain_id,
                max_depth=RECURSION_MAX_DEPTH,
                workspace_prefix="recursive",
                nested_artifacts_override=nested_artifacts,
                # Each cached classification saves several RPCs.
                classify_cache=classify_cache,
                # Pre-seed with resolution's graph: nested contracts are already analysed, so the refresh only re-walks
                # the root and new nodes.
                initial_graph=cast(Any, resolved_control_graph) if isinstance(resolved_control_graph, dict) else None,
            )
            if refreshed_graph:
                resolved_control_graph = refreshed_graph
                store_artifact(session, job.id, "resolved_control_graph", data=refreshed_graph)
                # Rewrite the graph tables too, with the same scoped replace resolution used. Rewriting only the
                # artifact left ``role_principal`` and refresh-only ``controller_value`` edges missing from
                # ``control_graph_edges``, which the effects closure, Surface, chat and enrollment read.
                if contract_row:
                    replace_control_graph_rows(
                        session,
                        contract_id=contract_row.id,
                        deployment_address=deployment_address,
                        resolved_graph=refreshed_graph,
                    )
                    session.commit()
                # Rarely needed; most come from resolution.
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
        # Materialize ``function_principals`` rows that never reached the graph (the walk only reads
        # ``authority_roles[].principals`` and ``controllers[].principals``); without a node they can't be spawned.
        #
        # Here because: it's after the last ``replace_control_graph_rows`` for this scope; it's before the perimeter, so
        # minted nodes are candidates this job; and the FP rows were committed earlier this stage. Outside ``if
        # refreshed_graph:`` so an empty refresh doesn't skip it.
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
                # Each mint is committed before being recorded, so the ledger never names a rolled-back row.
            finally:
                _persist_spawn_summary(session, job, fp_ledger, artifact_name="fp_materialization_summary")

        # Bring newly discovered contracts (every role principal, since those need this stage's effective_permissions)
        # into the perimeter; the other spawn site runs earlier. Budgeted because the path recurses, and every cut is
        # recorded.
        #
        # Runs on every policy job with the ledger written in a ``finally``, so an absent artifact only means "predates
        # the ledger" and a partial spawn is still recorded.
        spawn_result = new_spawn_result(site="policy_refresh", budget=PERIMETER_SPAWN_LIMIT)
        try:
            if isinstance(resolved_control_graph, dict):
                # A local view: minted nodes must reach the walker, but the persisted ``resolved_control_graph`` must
                # stay the walk's output. Minted nodes live in ``control_graph_nodes`` and the
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
                    # Passed explicitly: a marker inside ``details`` could be forged.
                    fp_materialized_addresses=[n["address"] for n in fp_nodes],
                )
        finally:
            _persist_spawn_summary(session, job, spawn_result)

        # Mint policy-derived claims from sibling facts before labeling, which reads the claims.
        self._enrich_cross_contract(
            session,
            job,
            contract_analysis,
            control_snapshot,
            function_records=ep_data.get("functions") if isinstance(ep_data, dict) else None,
            ep_data=ep_data,
            target_effects=effects_artifact if isinstance(effects_artifact, dict) else None,
            durations_ms=durations_ms,
        )

        self.update_detail(session, job, "Labeling principals")
        with log_timed_phase(logger, "principal_labels", durations_ms=durations_ms) as ph:
            pl_data = build_principal_labels(
                ep_data,
                resolved_control_graph=(
                    cast(dict, resolved_control_graph) if isinstance(resolved_control_graph, dict) else None
                ),
                rpc_url=rpc_url,
                chain_id=_chain_id_for_job(job),
                # Without the cache, labeling reclassifies every principal (the dominant cost on big protocols).
                classify_cache=classify_cache,
                # Rebuilt against the refreshed graph so the known-address scope includes new nodes.
                cross_chain_recognizer=make_cross_chain_recognizer(
                    _chain_id_for_job(job), _known_addresses_for_scope(resolved_control_graph, job.address)
                ),
                # Protocol-wide Safe owner registry for signer overlap; protocol-scoped jobs only.
                protocol_safe_owner_sets=(
                    load_protocol_safe_owner_sets(session, job.protocol_id) if job.protocol_id else None
                ),
                # Shared-deployer groups (a witnessed heuristic fact).
                protocol_deployer_groups=(
                    load_protocol_deployer_groups(session, job.protocol_id) if job.protocol_id else None
                ),
                # Contract principal to terminal Safe/EOA walk.
                resolve_controllers=_make_terminal_controller_resolver(rpc_url, chain_id=_chain_id_for_job(job)),
            )
            ph["principal_count"] = len(pl_data.get("principals", []))

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

        store_artifact(session, job.id, "principal_labels", data=pl_data)
        record_stage_metric("principals_labeled", len(pl_data.get("principals", [])))

        logger.info(
            "Policy stage principal labels complete for job %s address=%s name=%s",
            job.id,
            job.address or "0x0",
            job.name or "Contract",
        )

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
                        # The fast path skipped controllers, so enqueue a drain for the reconciler. Commit now so the
                        # TVL block's rollback can't drop it.
                        from services.monitoring.enrollment import mark_enrollment_dirty

                        mark_enrollment_dirty(session, job.protocol_id, "policy_complete")
                        session.commit()
                        # DeFiLlama TVL so the protocol has a number immediately; the hourly loop combines it with
                        # contract_balances.
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
                            # A failed commit poisons the session; roll back before reading job.protocol_id.
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
                    # A failed enroll (e.g. a benign concurrent race) poisons the session; roll back before touching the
                    # job so it degrades to a warning rather than a terminal failure.
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

        # Completion webhook for re-analysis jobs.
        request = job.request if isinstance(job.request, dict) else {}
        if request.get("reanalysis_trigger"):
            try:
                from services.monitoring.notifier import notify_reanalysis_complete

                notify_reanalysis_complete(session, job)
            except Exception as exc:
                # A side effect; the job's output is unchanged, so no record_degraded.
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

    def _enrich_cross_contract(
        self,
        session,
        job: Job,
        contract_analysis: dict,
        control_snapshot: dict,
        function_records: list[dict] | None = None,
        *,
        ep_data: dict | None = None,
        target_effects: dict | None = None,
        durations_ms: dict[str, int] | None = None,
    ) -> dict[str, list[Claim]]:
        """Mint policy-derived claims from sibling facts via ``services.static.cross_contract``'s derivations
        (value-flow propagation, transfer-policy configuration, beacon upgrade, proxy-verified upgrade provenance),
        merged onto each function's claims.

        Derivations key on Slither full_name while rows store the ABI signature, so they're joined by the selector from
        ``function_records``.
        """
        del contract_analysis
        from services.static.cross_contract import (
            build_callee_claim_map,
            derive_cross_contract_claims,
            proxy_provenance_from_classifications,
            sibling_transfer_hook_links,
            unresolved_callees,
        )

        request = job.request if isinstance(job.request, dict) else {}
        chain_id = _chain_id_for_job(job)
        target_address = call_address(session, job, chain_id=chain_id)
        if target_effects is None:
            target_effects = usable_semantic_artifact("effects", get_artifact(session, job.id, "effects"))

        with log_timed_phase(logger, "cross_contract_enrichment", durations_ms=durations_ms) as ph:
            # Committed before the fact read: a sibling whose facts land after it marks this job stale again.
            clear_policy_stale(session, job.id)
            session.commit()
            facts = fetch_sibling_facts(
                relevant_siblings(
                    session,
                    job,
                    related_jobs_with_facts(session, job, chain_id=chain_id),
                    snapshot=control_snapshot,
                    chain_id=chain_id,
                ),
                session_factory=SessionLocal,
            )
            for exc in facts.unreadable.values():
                # Not found out yet: retry rather than publish without the sibling. A proven-absent body joins the
                # siblings that never stored facts.
                if exc is not None and classify(exc) == "transient":
                    raise exc

            deployment_address = request.get("proxy_address") or job.address or ""
            enriched = derive_cross_contract_claims(
                target_effects,
                control_snapshot.get("controller_values", {}),
                build_callee_claim_map(facts.effects),
                sibling_transfer_hooks=sibling_transfer_hook_links(target_address, facts.effects, facts.snapshots),
                proxy_provenance=proxy_provenance_from_classifications(
                    deployment_address, get_artifact(session, job.id, "classifications")
                ),
                callee_implementations=facts.implementations,
            )
            gaps = describe_gaps(
                session,
                unresolved_callees(
                    target_effects,
                    control_snapshot.get("controller_values", {}),
                    set(facts.effects),
                    target_address=target_address,
                    proxy_coverage=proxy_coverage(session, facts, chain_id=chain_id),
                ),
                chain_id=chain_id,
                facts=facts,
            )
            ph["siblings"] = len(facts.effects)
            ph["functions_enriched"] = len(enriched)
            ph["functions_with_gaps"] = len(gaps)
            if enriched:
                logger.info(
                    "Job %s: cross-contract enrichment added policy claims: %s",
                    job.id,
                    {fn_sig: [c["claim_id"] for c in claims] for fn_sig, claims in enriched.items()},
                )
            if gaps:
                logger.info(
                    "Job %s: cross-contract claims not determined for callees without facts: %s",
                    job.id,
                    {fn_sig: sorted({(g["callee"], g["reason"]) for g in fn_gaps}) for fn_sig, fn_gaps in gaps.items()},
                )
            contract_row = session.execute(
                select(Contract).where(Contract.job_id == job.id).order_by(Contract.id).limit(1)
            ).scalar_one_or_none()
            # An impl row can back several deployments; these belong to the deployment the writer tagged, derived the
            # same way.
            row_deployment = normalize_deployment(request.get("proxy_address"))
            if contract_row is not None and enriched:
                write_claims_to_rows(
                    session,
                    contract_id=contract_row.id,
                    deployment_address=row_deployment,
                    selector_for=selector_by_function_key(function_records),
                    enriched=enriched,
                    job_id=job.id,
                )
            if ep_data is not None:
                apply_claims_to_payload(ep_data, enriched)
            # Without its own facts the job has no calls to judge: its gaps stay NULL (not evaluated).
            if contract_row is not None and target_effects is not None:
                write_gaps(
                    session,
                    contract_id=contract_row.id,
                    deployment_address=row_deployment,
                    function_records=function_records,
                    gaps=gaps,
                    payload=ep_data,
                )
            if ep_data is not None:
                store_artifact(session, job.id, "effective_permissions", data=ep_data)
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
        """Find nested controller context from resolution's ``recursive:<address>:<kind>`` artifacts: the first
        nested snapshot the target's controller values reference. Only enriches controller labels; function
        principals come from capability resolution.
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
