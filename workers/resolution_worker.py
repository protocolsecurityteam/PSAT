"""Resolution worker: builds the control snapshot and resolves the control graph."""

from __future__ import annotations

import logging
import os
import re
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.deployment import deployment_scope, normalize_deployment
from db.models import (
    Contract,
    ControllerValue,
    Job,
    JobStage,
    derive_job_chain_id,
)
from db.nested_artifacts import store_bundle as store_nested_artifacts
from db.queue import create_job, get_artifact, store_artifact
from schemas.control_tracking import ControlSnapshot, ControlTrackingPlan
from services.clients.rpc import require_rpc_url
from services.discovery.perimeter import queue_discovered_contracts
from services.monitoring.balance_observation import (
    observation_contract,
)
from services.monitoring.balance_reads import ObservationSubject
from services.monitoring.role_holder_cycle import (
    OUTCOME_GATE_CLOSED,
    OUTCOME_NO_REGISTRY,
    OUTCOME_NO_ROWS,
    OUTCOME_ROWS_WRITTEN,
    access_control_gate_open,
)
from services.resolution.capability_resolver import (
    find_analysis_job_for_address,
    find_dependency_provider_job_for_address,
)
from services.resolution.flow_asset_plane import (
    collect_asset_receivers,
    count_resolved,
    resolve_flow_asset_addresses,
)
from services.resolution.graph_tables import replace_control_graph_rows
from services.resolution.recursive import LoadedArtifacts, resolve_control_graph
from services.resolution.role_holder_plane import (
    persist_role_holder_planes,
    pin_probe_block,
    resolve_role_holder_planes,
)
from services.resolution.tracking import build_control_snapshot
from utils.balance_status import BALANCE_WRITER_RESOLUTION
from utils.chains import UnknownChainError, chain_by_id, chain_enabled
from utils.logging import record_degraded, record_stage_metric
from workers.base import BaseWorker

logger = logging.getLogger("workers.resolution_worker")

RECURSION_MAX_DEPTH = int(os.getenv("PSAT_RECURSION_MAX_DEPTH", "6"))


def _rpc_url_for_job(job: Job) -> str:
    """eRPC URL for the job's chain via ``jobs.chain_id`` (``_chain_id_for_job``); the request lacks the mainnet
    default for chainless submissions.
    """
    request = job.request if isinstance(job.request, dict) else {}
    explicit = request.get("rpc_url")
    return require_rpc_url(
        explicit_rpc_url=explicit if isinstance(explicit, str) else None,
        chain_id=_chain_id_for_job(job),
        context=f"resolution rpc for job {job.id}",
    )


def _chain_id_for_job(job: Job) -> int:
    """The job's ``chain_id`` (invariant 1): the column, else derived from ``request["chain"]``, else mainnet."""
    chain_id = getattr(job, "chain_id", None)
    if isinstance(chain_id, int):
        return chain_id
    request = job.request if isinstance(job.request, dict) else {}
    return derive_job_chain_id(request.get("chain"), job.address) or 1


def _chain_name_for_job(job: Job) -> str:
    """Canonical chain name for the job, stamped on spawned jobs so chain never cascades as ``None``.

    Mainnet is ``"ethereum"``.
    """
    try:
        return chain_by_id(_chain_id_for_job(job)).name
    except UnknownChainError:
        return "ethereum"


def _build_root_artifacts(
    contract_analysis: dict,
    tracking_plan: dict,
    snapshot: ControlSnapshot,
    predicate_trees: dict | None = None,
) -> LoadedArtifacts:
    return {
        "analysis": contract_analysis,
        "tracking_plan": tracking_plan,
        "snapshot": snapshot,
        "predicate_trees": predicate_trees,
    }


_HEX_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_ZERO_ADDRESS = "0x" + "0" * 40


def _membership_gate_controller_hook(
    session: Session,
    contract_row: Contract,
    controller_values: dict,
    *,
    removed_values: set[str] | frozenset[str] = frozenset(),
) -> None:
    """Membership-gate event-2 hook for the ControllerValue commit (spec §3.4 event 2b); best-effort.

    ``removed_values`` (F5) are controller addresses the rewrite dropped; Class-A rows anchored on them are re-checked
    in the same evaluate (as changed deployers and edge names).
    """
    from services.discovery.membership_gate import FactsDelta, evaluate_committed

    values: set[str] = set()
    for cv in controller_values.values():
        value = cv.get("value") if isinstance(cv, dict) else None
        if isinstance(value, str) and _HEX_ADDRESS_RE.match(value) and value.lower() != _ZERO_ADDRESS:
            values.add(value.lower())
    removed = {v for v in removed_values if v not in values}
    evaluate_committed(
        session,
        FactsDelta(
            new_edge_addresses=tuple(sorted(values | removed)),
            changed_deployer_addresses=tuple(sorted(removed)),
            recheck_contract_ids=(contract_row.id,),
        ),
        context=f"resolution_controller_values:{contract_row.id}",
    )


class ResolutionWorker(BaseWorker):
    stage = JobStage.resolution
    next_stage = JobStage.policy

    def process(self, session: Session, job: Job) -> None:
        logger.info(
            "Resolution stage started for job %s address=%s name=%s",
            job.id,
            job.address or "0x0",
            job.name or "Contract",
        )
        rpc_url = _rpc_url_for_job(job)
        chain_id = _chain_id_for_job(job)

        tracking_plan = get_artifact(session, job.id, "control_tracking_plan")
        if not isinstance(tracking_plan, dict):
            raise RuntimeError("control_tracking_plan artifact not found")

        contract_analysis = get_artifact(session, job.id, "contract_analysis")
        if not isinstance(contract_analysis, dict):
            raise RuntimeError("contract_analysis artifact not found")
        predicate_trees = get_artifact(session, job.id, "predicate_trees")
        if not isinstance(predicate_trees, dict):
            predicate_trees = None

        # Impl jobs read storage from the proxy.
        request = job.request if isinstance(job.request, dict) else {}
        proxy_address = request.get("proxy_address")
        # An UpgradeableBeacon's owner() is this instance's upgrade authority, read live below.
        beacon_address = proxy_address if request.get("proxy_type") == "beacon" else None
        # The proxy for an impl in proxy context, else NULL, so a shared impl holds per-proxy sets.
        deployment_address = normalize_deployment(proxy_address)
        getter_fallback_address: str | None = None
        if proxy_address:
            # Immutable authority addresses live in impl bytecode and revert through beacon/per-instance proxies (e.g.
            # EtherFiNode), so keep the impl as a getter fallback.
            getter_fallback_address = tracking_plan.get("contract_address")
            tracking_plan = {**tracking_plan, "contract_address": proxy_address}
            contract_analysis = {
                **contract_analysis,
                "subject": {**contract_analysis.get("subject", {}), "address": proxy_address},
            }
            logger.info(
                "Job %s: impl contract — reading state from proxy %s",
                job.id,
                proxy_address,
            )

        self.update_detail(session, job, "Reading current controller state")
        t0 = time.monotonic()
        snapshot = build_control_snapshot(
            cast(ControlTrackingPlan, tracking_plan),
            rpc_url,
            heartbeat=lambda: self._heartbeat(session, job),
            getter_fallback_address=getter_fallback_address,
            beacon_address=beacon_address,
            chain_id=chain_id,
        )
        logger.info(
            "resolution phase complete: control snapshot",
            extra={"duration_ms": int((time.monotonic() - t0) * 1000), "phase": "control_snapshot"},
        )
        # The policy stage reads this artifact.
        store_artifact(session, job.id, "control_snapshot", data=snapshot)
        # Reverting reads are NULL ``eth_call_error`` entries; count them separately so the resolved metric is honest.
        _controller_values = snapshot.get("controller_values", {})
        _controllers_errored = sum(
            1 for cv in _controller_values.values() if cv.get("observed_via") == "eth_call_error"
        )
        record_stage_metric("controllers_resolved", len(_controller_values) - _controllers_errored)
        if _controllers_errored:
            record_stage_metric("controllers_read_error", _controllers_errored)
        if snapshot.get("block_number") is not None:
            record_stage_metric("block_number", snapshot.get("block_number"))

        contract_row = session.execute(select(Contract).where(Contract.job_id == job.id).limit(1)).scalar_one_or_none()
        if contract_row:
            # F5: values about to be dropped, re-checked by the same gate pass.
            pre_rewrite_values = {
                v.lower()
                for (v,) in session.execute(
                    select(ControllerValue.value).where(
                        ControllerValue.contract_id == contract_row.id,
                        deployment_scope(ControllerValue.deployment_address, deployment_address),
                    )
                )
                if isinstance(v, str) and _HEX_ADDRESS_RE.match(v) and v.lower() != _ZERO_ADDRESS
            }
            session.query(ControllerValue).filter(
                ControllerValue.contract_id == contract_row.id,
                deployment_scope(ControllerValue.deployment_address, deployment_address),
            ).delete(synchronize_session=False)
            for cid, cv in snapshot.get("controller_values", {}).items():
                session.add(
                    ControllerValue(
                        contract_id=contract_row.id,
                        deployment_address=deployment_address,
                        controller_id=cid,
                        value=cv.get("value"),
                        resolved_type=cv.get("resolved_type"),
                        source=cv.get("source"),
                        block_number=snapshot.get("block_number"),
                        details=cv.get("details"),
                        observed_via=cv.get("observed_via"),
                        # Absent means NULL, not a guess.
                        authority_provenance=cv.get("authority_provenance"),
                    )
                )
            session.commit()
            # §3.4 event 2b: committed controllers are the gate's W3 fuel (plus the subject itself).
            _membership_gate_controller_hook(
                session, contract_row, snapshot.get("controller_values", {}), removed_values=pre_rewrite_values
            )

        logger.info(
            "Resolution stage control snapshot complete for job %s address=%s name=%s",
            job.id,
            job.address or "0x0",
            job.name or "Contract",
        )

        self._fetch_balances(
            session, job, contract_row, chain_id=chain_id, heartbeat=lambda: self._heartbeat(session, job)
        )

        root_artifacts = _build_root_artifacts(contract_analysis, tracking_plan, snapshot, predicate_trees)

        self.update_detail(session, job, "Resolving recursive control graph")
        t0 = time.monotonic()
        # Cached classifications let the policy stage skip its most expensive passes.
        classify_cache: dict[str, tuple[str, dict[str, object]]] = {}
        resolved_graph, nested_artifacts = resolve_control_graph(
            root_artifacts=root_artifacts,
            rpc_url=rpc_url,
            chain_id=chain_id,
            max_depth=RECURSION_MAX_DEPTH,
            workspace_prefix="recursive",
            classify_cache=classify_cache,
            heartbeat=lambda: self._heartbeat(session, job),
        )

        logger.info(
            "resolution phase complete: recursive graph",
            extra={"duration_ms": int((time.monotonic() - t0) * 1000), "phase": "recursive_graph"},
        )
        record_stage_metric("phase_ms_recursive_graph", int((time.monotonic() - t0) * 1000))

        graph_nodes = len(resolved_graph.get("nodes", [])) if resolved_graph else 0
        graph_edges = len(resolved_graph.get("edges", [])) if resolved_graph else 0
        record_stage_metric("graph_nodes", graph_nodes)
        record_stage_metric("graph_edges", graph_edges)
        if resolved_graph:
            # Per-address nested artifacts for the policy stage.
            store_nested_artifacts(session, job.id, nested_artifacts)
            store_artifact(session, job.id, "resolved_control_graph", data=resolved_graph)
            # Saves several RPCs per address in the policy stage.
            if classify_cache:
                store_artifact(
                    session,
                    job.id,
                    "classified_addresses",
                    data={addr: list(v) for addr, v in classify_cache.items()},
                )
            logger.info(
                "Resolution stage graph complete for job %s address=%s name=%s",
                job.id,
                job.address or "0x0",
                job.name or "Contract",
            )

            # Same replace the policy refresh uses, so tables match the latest graph artifact.
            if contract_row:
                replace_control_graph_rows(
                    session,
                    contract_id=contract_row.id,
                    deployment_address=deployment_address,
                    resolved_graph=resolved_graph,
                )
                session.commit()

            self._queue_discovered_contracts(session, job, cast(dict, resolved_graph), rpc_url)

        # Dependency edges so policy waits for external authority contracts in the predicate trees (e.g. a roleRegistry
        # call). Failure only loses cross-contract inlining.
        try:
            self._emit_dependency_edges_from_predicate_trees(session, job, snapshot, rpc_url)
        except Exception as exc:
            record_degraded(
                phase="resolution_dependency_emission",
                exc=exc,
                context={"address": job.address or "0x0"},
            )
            logger.warning(
                "Job %s: dependency-edge emission failed: %s",
                job.id,
                exc,
                extra={"exc_type": type(exc).__name__},
            )

        # Isolated: this plane publishes only lower bounds and must not fail the stage.
        try:
            self._resolve_role_holder_plane(
                session,
                job,
                chain_id=chain_id,
                rpc_url=rpc_url,
                registry_address=proxy_address or job.address,
            )
        except Exception as exc:
            session.rollback()
            record_degraded(
                phase="resolution_role_holder_plane",
                exc=exc,
                context={"address": job.address or "0x0"},
            )
            logger.warning(
                "Job %s: role-holder plane resolution failed: %s",
                job.id,
                exc,
                extra={"exc_type": type(exc).__name__},
            )

        # Isolated: it only adds addresses, so failure costs pricing coverage and proves nothing false.
        try:
            self._resolve_flow_asset_addresses(
                session,
                job,
                chain_id=chain_id,
                rpc_url=rpc_url,
                deployment_address=proxy_address or job.address,
                proven_proxied=bool(proxy_address),
            )
        except Exception as exc:
            session.rollback()
            record_degraded(
                phase="resolution_flow_asset_plane",
                exc=exc,
                context={"address": job.address or "0x0"},
            )
            logger.warning(
                "Job %s: flow asset address resolution failed: %s",
                job.id,
                exc,
                extra={"exc_type": type(exc).__name__},
            )

        self.update_detail(
            session,
            job,
            f"Resolution complete: {graph_nodes} graph nodes, {graph_edges} edges",
        )
        logger.info(
            "Resolution stage complete for job %s address=%s name=%s",
            job.id,
            job.address or "0x0",
            job.name or "Contract",
        )

    def _resolve_role_holder_plane(
        self,
        session: Session,
        job: Job,
        *,
        chain_id: int,
        rpc_url: str,
        registry_address: str | None,
    ) -> int:
        """Publish this registry's role floors; returns rows written.

        An opportunistic fast path; ``services.monitoring.role_holder_cycle`` guarantees coverage on its own clock.
        Gated on the two AccessControl cursors existing, not being warm: a cold cursor still writes a withheld row,
        distinguishing "no roles" from "not read". Every outcome is recorded (closed gate, nothing resolved, N rows).
        The registry is the runtime (proxy) address.
        """
        if not registry_address:
            self._record_role_plane_outcome(job, None, OUTCOME_NO_REGISTRY, 0)
            return 0
        if not access_control_gate_open(session, chain_id=chain_id, registry_address=registry_address):
            self._record_role_plane_outcome(job, registry_address, OUTCOME_GATE_CLOSED, 0)
            return 0

        rows = resolve_role_holder_planes(
            session,
            chain_id=chain_id,
            registry_address=registry_address,
            rpc_url=rpc_url,
        )
        if not rows:
            self._record_role_plane_outcome(job, registry_address, OUTCOME_NO_ROWS, 0)
            return 0
        written = persist_role_holder_planes(session, rows)
        session.commit()
        # §3.4 event 2: role holders are anchor-chain links, so a grant/revoke can make or break a W3-D1 witness.
        from services.discovery.membership_gate import evaluate_role_plane_change

        evaluate_role_plane_change(
            session,
            registry_address=registry_address,
            rows=rows,
            context=f"role_holder_plane:{registry_address}",
        )
        self._record_role_plane_outcome(job, registry_address, OUTCOME_ROWS_WRITTEN, written)
        return written

    @staticmethod
    def _record_role_plane_outcome(job: Job, registry_address: str | None, outcome: str, written: int) -> None:
        record_stage_metric("role_holder_planes", written)
        record_stage_metric("role_holder_plane_outcome", outcome)
        logger.info(
            "Job %s: role-holder plane %s for registry %s (%d row(s))",
            job.id,
            outcome,
            registry_address or "0x0",
            written,
            extra={
                "registry_address": registry_address,
                "outcome": outcome,
                "role_holder_planes": written,
            },
        )

    def _resolve_flow_asset_addresses(
        self,
        session: Session,
        job: Job,
        *,
        chain_id: int,
        rpc_url: str,
        deployment_address: str | None,
        proven_proxied: bool,
    ) -> int:
        """Dereference this job's flow-sink asset getters; returns rows published.

        Read at the runtime address (the proxy in proxy context), which is also the only basis for ``proven_proxied``;
        no proxy in the request doesn't prove unproxied. The height comes from ``pin_probe_block``; without one nothing
        is read.
        """
        if not deployment_address:
            return 0
        effects = get_artifact(session, job.id, "effects")
        if not isinstance(effects, dict):
            return 0
        receivers = collect_asset_receivers(effects)
        if not receivers:
            return 0
        probe_block = pin_probe_block(rpc_url, chain_id=chain_id)
        if probe_block is None:
            logger.warning(
                "Job %s: could not pin a probe block; flow asset addresses withheld",
                job.id,
            )
            return 0
        payload = resolve_flow_asset_addresses(
            receivers,
            rpc_url=rpc_url,
            chain_id=chain_id,
            deployment_address=deployment_address,
            proven_proxied=proven_proxied,
            probe_block=probe_block,
        )
        # Replaced wholesale at a new height, so stale and fresh addresses never mix.
        store_artifact(session, job.id, "flow_asset_addresses", data=payload)
        session.commit()
        resolved = count_resolved(payload)
        record_stage_metric("flow_asset_addresses", resolved)
        logger.info(
            "Job %s: flow asset plane resolved %d/%d receiver(s) at block %d",
            job.id,
            resolved,
            len(receivers),
            probe_block.number,
            extra={
                "deployment_address": deployment_address,
                "flow_asset_receivers": len(receivers),
                "flow_asset_addresses": resolved,
                "probe_block": probe_block.number,
            },
        )
        return len(receivers)

    def _fetch_balances(
        self,
        session: Session,
        job: Job,
        contract_row: Contract | None,
        *,
        chain_id: int,
        heartbeat: Callable[[], None] | None = None,
    ) -> None:
        """Bounded current holdings only (before effects); no history scans."""
        from sqlalchemy.orm import sessionmaker

        from services.monitoring.balance_collection import CollectionSubject, collect_balances

        if not job.address or contract_row is None:
            return
        request = job.request if isinstance(job.request, dict) else {}
        contract = observation_contract(
            session,
            fallback=contract_row,
            chain_id=chain_id,
            requested_address=request.get("proxy_address") or job.address,
        )
        target = CollectionSubject(ObservationSubject.of_contract(contract), chain_id)
        factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False)
        self.update_detail(session, job, "Refreshing current balances")
        # Release the connection before provider calls; collection commits its own small transactions.
        session.commit()
        report = collect_balances(
            [target], writer=BALANCE_WRITER_RESOLUTION, session_factory=factory, heartbeat=heartbeat
        )
        for name in ("attempted", "reused", "deferred", "committed", "failed", "partial"):
            record_stage_metric("balance_" + name, getattr(report, name))
        if report.failed or report.deferred or report.partial:
            record_degraded(
                phase="balance_fetch",
                exc=RuntimeError("balance inputs incomplete; durable retry scheduled"),
                context={"failed": report.failed, "deferred": report.deferred, "partial": report.partial},
            )
        session.expire_all()

    def _queue_discovered_contracts(self, session: Session, job: Job, resolved_graph: dict, rpc_url: str) -> None:
        """Queue jobs for contracts found during resolution without one.

        No budget (``max_depth`` bounds it); the recursive policy refresh passes one.
        """
        queue_discovered_contracts(
            session,
            job,
            resolved_graph,
            rpc_url,
            site="resolution",
            chain_name=_chain_name_for_job(job),
        )

    def _emit_dependency_edges_from_predicate_trees(
        self,
        session: Session,
        job: Job,
        snapshot: ControlSnapshot,
        rpc_url: str,
    ) -> None:
        """Insert ``JobDependency`` rows for external contracts A's predicate trees use as authority.

        Finds leaves whose ``authority_contract.address_source`` is a state variable, resolves it via the
        controller_values snapshot, and inserts ``(A, provider, required_stage=policy)``; ``_satisfy_dependencies``
        flips it later. For proxies the provider is the impl job when known.

        Missing provider jobs are created under a ``(chain, address)`` advisory lock. Idempotent (ON CONFLICT DO
        NOTHING) and safe before B exists; the claim gate does the waiting.
        """
        from sqlalchemy import text as _sa_text
        from sqlalchemy.dialects.postgresql import insert as _pg_insert

        from db.models import JobDependency

        predicate_trees = get_artifact(session, job.id, "predicate_trees")
        if not isinstance(predicate_trees, dict):
            return
        tree_maps = [
            tree_map
            for tree_map in (predicate_trees.get("trees"), predicate_trees.get("check_trees"))
            if isinstance(tree_map, dict) and tree_map
        ]
        if not tree_maps:
            return

        controller_values = (snapshot or {}).get("controller_values") or {}
        # ``state_variable:<name>`` rows to ``{name: address}``.
        state_var_addresses: dict[str, str] = {}
        for cid, payload in controller_values.items():
            if not isinstance(cid, str) or not isinstance(payload, dict):
                continue
            value = payload.get("value")
            if not isinstance(value, str) or not value.startswith("0x") or len(value) != 42:
                continue
            name = cid.split(":", 1)[1] if ":" in cid else cid
            state_var_addresses.setdefault(name, value.lower())

        referenced: set[str] = set()
        for tree_map in tree_maps:
            for tree in tree_map.values():
                _collect_authority_contract_state_vars(tree, referenced)
        if not referenced:
            return

        # Missing values are skipped (not captured yet, private var, RPC failure).
        target_addresses = sorted({state_var_addresses[name] for name in referenced if name in state_var_addresses})
        if not target_addresses:
            return

        # Same chain as A (chain-as-island), stamped even when the request has none.
        chain = _chain_name_for_job(job)
        # Defence in depth: a disabled chain spawns no provider jobs.
        if not chain_enabled(chain):
            logger.info(
                "Skipping dependency-edge emission: chain not enabled for this deployment",
                extra={
                    "job_id": str(job.id),
                    "chain": chain,
                    "reason": "chain_not_enabled",
                    "site": "resolution_dependency",
                },
            )
            return
        parent_company = job.company

        edges_inserted = 0
        n_satisfied = 0
        n_pending = 0
        n_cycle = 0
        for target_addr in target_addresses:
            # Self-references aren't dependencies.
            if target_addr == (job.address or "").lower():
                continue
            # Serializes concurrent A jobs spawning the same B.
            lock_key = _stable_lock_key(chain, target_addr)
            session.execute(_sa_text("SELECT pg_advisory_xact_lock(:k)"), {"k": lock_key})

            provider_lookup = find_dependency_provider_job_for_address(session, target_addr, chain=chain)
            provider_job = provider_lookup.analysis_job if provider_lookup is not None else None
            dependency_provider_addr = (
                (provider_job.address or target_addr).lower() if provider_job is not None else target_addr
            )
            if provider_job is None:
                provider_request = {
                    "address": target_addr,
                    "name": target_addr,
                    "rpc_url": rpc_url,
                    "parent_job_id": str(job.id),
                    "discovered_by": "resolution_dependency",
                    "chain": chain,
                }
                provider_job = create_job(session, provider_request, initial_stage=JobStage.discovery)
                if parent_company:
                    provider_job.company = parent_company
                if job.protocol_id:
                    provider_job.protocol_id = job.protocol_id
                session.commit()
                dependency_provider_addr = target_addr

            if provider_job.id == job.id:
                continue

            satisfied_lookup = find_analysis_job_for_address(
                session,
                target_addr,
                required_artifact="effective_permissions",
                chain=chain,
                completed_only=False,
            )
            already_satisfied = False
            if satisfied_lookup is not None:
                provider_job = satisfied_lookup.analysis_job
                dependency_provider_addr = (provider_job.address or dependency_provider_addr).lower()
                already_satisfied = True

            # An edge closing a cycle would deadlock the claim gate; insert it as ``cycle_degraded`` so it doesn't block
            # and the leaf resolves to external_check_only.
            cycle_path = None
            if not already_satisfied:
                cycle_path = _detect_dep_cycle(
                    session,
                    proposed_depender_id=job.id,
                    proposed_provider_id=provider_job.id,
                )
            edge_status = "satisfied" if already_satisfied else ("cycle_degraded" if cycle_path else "pending")
            values = {
                "depender_job_id": job.id,
                "provider_chain": chain,
                "provider_address": dependency_provider_addr,
                "required_stage": JobStage.policy,
                "status": edge_status,
                "cycle_path": cycle_path,
            }
            if already_satisfied:
                values["satisfied_at"] = datetime.now(timezone.utc)
            stmt = (
                _pg_insert(JobDependency)
                .values(**values)
                .on_conflict_do_nothing(
                    index_elements=[
                        "depender_job_id",
                        "provider_chain",
                        "provider_address",
                        "required_stage",
                    ],
                )
            )
            result = session.execute(stmt)
            # ``rowcount`` isn't on the generic Result type pyright sees.
            if (getattr(result, "rowcount", 0) or 0) > 0:
                edges_inserted += 1
                if edge_status == "satisfied":
                    n_satisfied += 1
                elif edge_status == "cycle_degraded":
                    n_cycle += 1
                    # A cycle is a degraded outcome; surface it.
                    logger.warning(
                        "Job %s: dependency cycle on provider %s — edge inserted as cycle_degraded (path=%s)",
                        job.id,
                        dependency_provider_addr,
                        cycle_path,
                        extra={"provider_address": dependency_provider_addr, "cycle_path": cycle_path},
                    )
                else:
                    n_pending += 1

        if edges_inserted:
            session.commit()
            logger.info(
                "Job %s: emitted %d dependency edge(s) on external authority contracts "
                "(satisfied=%d pending=%d cycle_degraded=%d)",
                job.id,
                edges_inserted,
                n_satisfied,
                n_pending,
                n_cycle,
                extra={
                    "dep_edges_inserted": edges_inserted,
                    "dep_satisfied": n_satisfied,
                    "dep_pending": n_pending,
                    "dep_cycle_degraded": n_cycle,
                },
            )
            record_stage_metric("dep_edges_inserted", edges_inserted)
            record_stage_metric("dep_edges_pending", n_pending)
            record_stage_metric("dep_edges_cycle_degraded", n_cycle)


def _collect_authority_contract_state_vars(node: dict, out: set[str]) -> None:
    """Add every state-variable name used as an ``authority_contract.address_source`` in a predicate tree to ``out``."""
    if not isinstance(node, dict):
        return
    if node.get("op") == "LEAF":
        leaf = node.get("leaf") or {}
        descriptor = leaf.get("set_descriptor") or {}
        authority = descriptor.get("authority_contract") or {}
        address_source = authority.get("address_source") or {}
        if address_source.get("source") == "state_variable":
            sv = address_source.get("state_variable_name")
            if isinstance(sv, str) and sv:
                out.add(sv)
        return
    for child in node.get("children") or []:
        _collect_authority_contract_state_vars(child, out)


def _detect_dep_cycle(
    session: Session,
    *,
    proposed_depender_id,
    proposed_provider_id,
) -> list[str] | None:
    """If edge ``(depender → provider)`` would close a cycle, return the path of job ids for debugging, else
    ``None``.

    A recursive CTE walks forward from the provider, joining via ``Job.address`` (dependency rows store only
    chain+address for the provider), with path-based cycle elimination.
    """
    from sqlalchemy import text as _sa_text

    sql = _sa_text(
        """
        WITH RECURSIVE chain AS (
            -- Base: edges leaving the proposed provider.
            SELECT
                jd.id AS edge_id,
                jd.depender_job_id AS from_job,
                provider_job.id AS to_job,
                ARRAY[jd.depender_job_id::text] AS path
            FROM job_dependencies jd
            JOIN jobs provider_job
              ON LOWER(provider_job.address) = LOWER(jd.provider_address)
             AND COALESCE(provider_job.request->>'chain', '') = COALESCE(jd.provider_chain, '')
            WHERE jd.depender_job_id = :start_provider
              AND jd.status IN ('pending', 'satisfied')

            UNION

            -- Recurse: follow the next hop's depender forward.
            SELECT
                jd.id,
                jd.depender_job_id,
                provider_job.id,
                chain.path || jd.depender_job_id::text
            FROM job_dependencies jd
            JOIN jobs provider_job
              ON LOWER(provider_job.address) = LOWER(jd.provider_address)
             AND COALESCE(provider_job.request->>'chain', '') = COALESCE(jd.provider_chain, '')
            JOIN chain ON jd.depender_job_id = chain.to_job
            WHERE jd.status IN ('pending', 'satisfied')
              AND NOT (jd.depender_job_id::text = ANY(chain.path))
        )
        SELECT path FROM chain WHERE to_job = :target_depender LIMIT 1
        """
    )
    row = session.execute(
        sql,
        {
            "start_provider": str(proposed_provider_id),
            "target_depender": str(proposed_depender_id),
        },
    ).first()
    if row is None:
        return None
    path = list(row[0]) if row[0] is not None else []
    # Close the path: B → ... → A → B.
    path.append(str(proposed_provider_id))
    return path


def _stable_lock_key(chain: str | None, address: str) -> int:
    """Hash ``(chain, address)`` to a stable 63-bit ``pg_advisory_xact_lock`` key."""
    import hashlib

    h = hashlib.sha256(f"{chain or 'ethereum'}:{address.lower()}".encode()).digest()
    return int.from_bytes(h[:8], "big") & ((1 << 63) - 1)


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        force=True,
    )
    ResolutionWorker().run_loop()


if __name__ == "__main__":
    main()
