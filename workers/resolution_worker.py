"""Resolution worker — builds control snapshot and resolves control graph."""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.deployment import deployment_scope, normalize_deployment
from db.models import (
    Contract,
    ContractBalance,
    ControlGraphEdge,
    ControlGraphNode,
    ControllerValue,
    Job,
    JobStage,
)
from db.nested_artifacts import store_bundle as store_nested_artifacts
from db.queue import create_job, require_contract_for_job, store_artifact
from schemas.control_tracking import ControlSnapshot, ControlTrackingPlan
from services.artifacts import (
    RESOLUTION_ARTIFACT,
    get_artifact_field,
    make_job_contract,
    make_job_stage_context,
    make_stage_artifact,
)
from services.resolution.capability_resolver import (
    find_analysis_job_for_address,
    find_dependency_provider_job_for_address,
)
from services.resolution.recursive import LoadedArtifacts, resolve_control_graph
from services.resolution.tracking import build_control_snapshot
from utils.logging import record_degraded, record_stage_metric
from utils.rpc import default_rpc_url, require_supported_chain_id
from workers.base import BaseWorker

logger = logging.getLogger("workers.resolution_worker")

RECURSION_MAX_DEPTH = int(os.getenv("PSAT_RECURSION_MAX_DEPTH", "6"))


def _resolve_job_chain_id(job: Job) -> int:
    chain_id = require_supported_chain_id(
        chain_id=job.chain_id,
        context=f"resolution job {job.id}",
    )
    return chain_id


def _rpc_url_for_job(job: Job) -> str:
    return default_rpc_url(chain_id=job.chain_id)


def _build_root_artifacts(
    contract_analysis: dict,
    tracking_plan: dict,
    snapshot: ControlSnapshot,
    predicate_trees: dict | None = None,
) -> LoadedArtifacts:
    """Package the root job's in-memory artifacts for the recursive resolver."""
    return {
        "analysis": contract_analysis,
        "tracking_plan": tracking_plan,
        "snapshot": snapshot,
        "predicate_trees": predicate_trees,
    }


class ResolutionWorker(BaseWorker):
    stage = JobStage.resolution
    next_stage = JobStage.policy

    def process(self, session: Session, job: Job) -> None:
        job_address = job.address
        if not job_address:
            raise RuntimeError(f"resolution job {job.id} requires address")
        job_address = job_address.lower()
        logger.info(
            "Resolution stage started for job %s address=%s name=%s",
            job.id,
            job_address,
            job.name or "Contract",
        )
        chain_id = _resolve_job_chain_id(job)
        raw_request = job.request
        request: dict[str, Any] = cast(dict[str, Any], raw_request) if isinstance(raw_request, dict) else {}
        if job.chain_id != chain_id:
            job.chain_id = chain_id
            session.commit()
            raw_request = job.request
            request = cast(dict[str, Any], raw_request) if isinstance(raw_request, dict) else {}
        rpc_url = _rpc_url_for_job(job)

        # Read control_tracking_plan from DB
        tracking_plan = get_artifact_field(session, job.id, "control_tracking_plan")
        if not isinstance(tracking_plan, dict):
            raise RuntimeError("static_analysis_artifact missing control_tracking_plan")

        # Read contract_analysis from DB (needed for recursive resolution)
        contract_analysis = get_artifact_field(session, job.id, "contract_analysis")
        if not isinstance(contract_analysis, dict):
            raise RuntimeError("static_analysis_artifact missing contract_analysis")
        predicate_trees = get_artifact_field(session, job.id, "predicate_trees")
        if not isinstance(predicate_trees, dict):
            predicate_trees = None

        # For impl jobs, read storage from the proxy address (where state lives)
        proxy_address = request.get("proxy_address")
        # Deployment this resolution is attributed to (proxy for an impl in proxy
        # context, else NULL) so a shared impl can hold per-proxy result sets.
        deployment_address = normalize_deployment(proxy_address)
        if isinstance(proxy_address, str) and proxy_address:
            normalized_proxy_address = proxy_address.lower()
            plan_contract = tracking_plan.get("contract")
            if isinstance(plan_contract, dict):
                implementation_addresses: list[str] = []
                current_contract_address = plan_contract.get("address")
                raw_implementations = plan_contract.get("implementation_addresses")
                for candidate in [
                    current_contract_address,
                    *(raw_implementations if isinstance(raw_implementations, list) else []),
                ]:
                    if not isinstance(candidate, str):
                        continue
                    normalized = candidate.lower()
                    if normalized == normalized_proxy_address or normalized in implementation_addresses:
                        continue
                    implementation_addresses.append(normalized)
                plan_contract = {
                    **plan_contract,
                    "address": normalized_proxy_address,
                    "is_proxy": True,
                    "proxy_address": normalized_proxy_address,
                    "implementation_addresses": implementation_addresses,
                }
            tracking_plan = {
                **tracking_plan,
                "contract_address": normalized_proxy_address,
                **({"contract": plan_contract} if isinstance(plan_contract, dict) else {}),
            }
            subject = contract_analysis.get("subject", {})
            if isinstance(subject, dict):
                implementation_addresses: list[str] = []
                current_subject_address = subject.get("address")
                raw_implementations = subject.get("implementation_addresses")
                for candidate in [
                    current_subject_address,
                    *(raw_implementations if isinstance(raw_implementations, list) else []),
                ]:
                    if not isinstance(candidate, str):
                        continue
                    normalized = candidate.lower()
                    if normalized == normalized_proxy_address or normalized in implementation_addresses:
                        continue
                    implementation_addresses.append(normalized)
                subject = {
                    **subject,
                    "address": normalized_proxy_address,
                    "is_proxy": True,
                    "proxy_address": normalized_proxy_address,
                    "implementation_addresses": implementation_addresses,
                }
            contract_analysis = {
                **contract_analysis,
                "subject": subject,
            }
            logger.info(
                "Job %s: impl contract — reading state from proxy %s",
                job.id,
                proxy_address,
            )

        # Build control snapshot via RPC calls
        self.update_detail(session, job, "Reading current controller state")
        t0 = time.monotonic()
        snapshot = build_control_snapshot(
            cast(ControlTrackingPlan, tracking_plan),
            rpc_url,
            heartbeat=lambda: self._heartbeat(session, job),
        )
        logger.info(
            "resolution phase complete: control snapshot",
            extra={"duration_ms": int((time.monotonic() - t0) * 1000), "phase": "control_snapshot"},
        )
        record_stage_metric("controllers_resolved", len(snapshot.get("controller_values", {})))
        if snapshot.get("block_number") is not None:
            record_stage_metric("block_number", snapshot.get("block_number"))

        # Write to controller_values table
        contract_row = require_contract_for_job(session, job, context=f"resolution controller write for {job.id}")
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
                )
            )
        session.commit()

        logger.info(
            "Resolution stage control snapshot complete for job %s address=%s name=%s",
            job.id,
            job_address,
            job.name or "Contract",
        )

        # Fetch token balances
        self._fetch_balances(
            session,
            job,
            contract_row,
            chain_id=chain_id,
            heartbeat=lambda: self._heartbeat(session, job),
        )

        root_artifacts = _build_root_artifacts(contract_analysis, tracking_plan, snapshot, predicate_trees)

        self.update_detail(session, job, "Resolving recursive control graph")
        t0 = time.monotonic()
        # Cache classify_resolved_address results so the policy stage can
        # short-circuit its refresh + labeling passes (the dominant cost
        # on cascade workloads — see PSAT_BENCH_NOTES in
        # services/resolution/recursive.py).
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

        graph_nodes = len(resolved_graph.get("nodes", [])) if resolved_graph else 0
        graph_edges = len(resolved_graph.get("edges", [])) if resolved_graph else 0
        record_stage_metric("graph_nodes", graph_nodes)
        record_stage_metric("graph_edges", graph_edges)
        classified_addresses = {addr: list(v) for addr, v in classify_cache.items()} if classify_cache else {}
        if resolved_graph:
            # Persist each nested contract's artifacts so the policy stage can
            # read them back by address (no local filesystem).
            store_nested_artifacts(session, job.id, nested_artifacts)
            # Persist the classify cache so the policy stage skips re-running
            # the 6-10 RPC fan-out per address. dict[str, tuple] → JSON-friendly
            # dict[str, list] for storage.
            logger.info(
                "Resolution stage graph complete for job %s address=%s name=%s",
                job.id,
                job_address,
                job.name or "Contract",
            )

            # Write to control_graph_nodes and control_graph_edges tables
            if contract_row:
                session.query(ControlGraphNode).filter(
                    ControlGraphNode.contract_id == contract_row.id,
                    deployment_scope(ControlGraphNode.deployment_address, deployment_address),
                ).delete(synchronize_session=False)
                session.query(ControlGraphEdge).filter(
                    ControlGraphEdge.contract_id == contract_row.id,
                    deployment_scope(ControlGraphEdge.deployment_address, deployment_address),
                ).delete(synchronize_session=False)
                for node in resolved_graph.get("nodes", []):
                    session.add(
                        ControlGraphNode(
                            contract_id=contract_row.id,
                            deployment_address=deployment_address,
                            address=(node.get("address") or "").lower(),
                            node_type=node.get("node_type"),
                            resolved_type=node.get("resolved_type"),
                            label=node.get("label"),
                            contract_name=node.get("contract_name"),
                            depth=node.get("depth"),
                            analyzed=node.get("analyzed", False),
                            details=node.get("details"),
                        )
                    )
                for edge in resolved_graph.get("edges", []):
                    session.add(
                        ControlGraphEdge(
                            contract_id=contract_row.id,
                            deployment_address=deployment_address,
                            from_node_id=edge.get("from_id", ""),
                            to_node_id=edge.get("to_id", ""),
                            relation=edge.get("relation"),
                            label=edge.get("label"),
                            source_controller_id=edge.get("source_controller_id"),
                            notes=edge.get("notes"),
                        )
                    )
                session.commit()

            # Queue analysis jobs for contracts discovered during resolution
                self._queue_discovered_contracts(
                    session,
                    job,
                    cast(dict, resolved_graph),
                    chain_id=chain_id,
                )

        resolution_payload = {
            "control_snapshot": snapshot,
            "resolved_control_graph": resolved_graph or {"nodes": [], "edges": []},
            "nested_artifacts": nested_artifacts,
            "classified_addresses": classified_addresses,
        }
        resolution_artifact = make_stage_artifact(
            kind=RESOLUTION_ARTIFACT,
            stage="resolution",
            schema_version="resolution.v1",
            context=make_job_stage_context(
                job,
                stage="resolution",
                schema_version="resolution.v1",
                block_number=snapshot.get("block_number") if isinstance(snapshot, dict) else None,
            ),
            contract=make_job_contract(session, job, contract_row),
            data=resolution_payload,
        )
        store_artifact(session, job.id, RESOLUTION_ARTIFACT, data=resolution_artifact)

        # Emit JobDependency edges so the policy stage waits for any
        # external authority contract referenced by this job's predicate
        # trees (e.g. EtherFiAdmin.upgradeTo's roleRegistry call).
        try:
            self._emit_dependency_edges_from_predicate_trees(session, job, snapshot, rpc_url)
        except Exception as exc:
            record_degraded(
                phase="resolution_dependency_emission",
                exc=exc,
                context={"address": job_address},
            )
            logger.error(
                "Job %s: dependency-edge emission failed: %s",
                job.id,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
            raise RuntimeError(f"dependency-edge emission failed for job {job.id}") from exc

        self.update_detail(
            session,
            job,
            f"Resolution complete: {graph_nodes} graph nodes, {graph_edges} edges",
        )
        logger.info(
            "Resolution stage complete for job %s address=%s name=%s",
            job.id,
            job_address,
            job.name or "Contract",
        )

    def _fetch_balances(
        self,
        session: Session,
        job: Job,
        contract_row: Contract | None,
        *,
        chain_id: int,
        heartbeat: Callable[[], None] | None = None,
    ) -> None:
        """Fetch ETH + token balances and store in contract_balances table."""
        from utils.concurrency import parallel_map
        from utils.onchain import get_eth_balance, get_eth_price, get_token_balances

        address = job.address
        if not address or not contract_row:
            return

        request = job.request if isinstance(job.request, dict) else {}
        target_address = request.get("proxy_address") or address

        self.update_detail(session, job, "Fetching token balances")
        # Native balance is eRPC-backed. Token enumeration requires an indexed
        # token universe; without one the helper raises so this stage does not
        # persist partial/empty balances.
        calls: dict[str, Callable[[], object]] = {
            "eth_wei": (lambda: get_eth_balance(target_address, chain_id=chain_id)),
            "tokens": (lambda: get_token_balances(target_address, chain_id=chain_id)),
            "eth_price": (lambda: get_eth_price(chain_id=chain_id)),
        }

        def _run_call(item: tuple[str, Callable[[], object]]) -> tuple[str, object]:
            call_id, fn = item
            return call_id, fn()

        results: dict[str, object | BaseException] = {}
        for (call_id, _fn), outcome in parallel_map(
            _run_call,
            list(calls.items()),
            max_workers=len(calls),
            heartbeat=heartbeat,
        ):
            if isinstance(outcome, BaseException):
                results[call_id] = outcome
                continue
            result_call_id, value = outcome
            results[result_call_id] = value

        eth_wei_raw = results.get("eth_wei")
        tokens_raw = results.get("tokens")
        if isinstance(eth_wei_raw, BaseException) or isinstance(tokens_raw, BaseException):
            primary_exc = eth_wei_raw if isinstance(eth_wei_raw, BaseException) else tokens_raw
            assert isinstance(primary_exc, BaseException)
            record_degraded(
                phase="balance_fetch",
                exc=primary_exc,
                context={
                    "address": target_address,
                    "eth_failed": isinstance(eth_wei_raw, BaseException),
                    "tokens_failed": isinstance(tokens_raw, BaseException),
                },
            )
            logger.error(
                "Job %s: balance fetch failed: eth=%r tokens=%r",
                job.id,
                eth_wei_raw,
                tokens_raw,
            )
            raise RuntimeError(f"balance fetch failed for {target_address}") from primary_exc
        eth_wei = cast(int, eth_wei_raw)
        tokens = cast(list, tokens_raw)

        # Clear old balances
        session.query(ContractBalance).filter(ContractBalance.contract_id == contract_row.id).delete()

        # Native ETH balance
        if eth_wei > 0:
            eth_price_raw = results.get("eth_price")
            eth_price: float | None
            eth_usd: float | None = None
            if isinstance(eth_price_raw, BaseException):
                record_degraded(
                    phase="eth_price_fetch",
                    exc=eth_price_raw,
                    context={"address": target_address},
                )
                logger.error("Job %s: ETH price fetch failed: %s", job.id, eth_price_raw)
                raise RuntimeError(f"ETH price fetch failed for {target_address}") from eth_price_raw
            else:
                eth_price = cast(float, eth_price_raw)
                eth_usd = (eth_wei / 1e18) * eth_price
            session.add(
                ContractBalance(
                    contract_id=contract_row.id,
                    token_address=None,
                    token_name="Ether",
                    token_symbol="ETH",
                    decimals=18,
                    raw_balance=str(eth_wei),
                    price_usd=eth_price,
                    usd_value=round(eth_usd, 2) if eth_usd else None,
                )
            )

        # ERC-20 token balances
        for tok in tokens:
            session.add(
                ContractBalance(
                    contract_id=contract_row.id,
                    token_address=tok["token_address"],
                    token_name=tok["token_name"],
                    token_symbol=tok["token_symbol"],
                    decimals=tok["decimals"],
                    raw_balance=str(tok["balance"]),
                    price_usd=tok.get("price_usd"),
                    usd_value=tok.get("usd_value"),
                )
            )

        session.commit()
        total = len(tokens) + (1 if eth_wei > 0 else 0)
        logger.info("Job %s: stored %d balance(s) for %s", job.id, total, target_address)

    def _queue_discovered_contracts(
        self,
        session: Session,
        job: Job,
        resolved_graph: dict,
        *,
        chain_id: int,
    ) -> None:
        """Queue analysis jobs for contracts found during resolution that have no existing job."""
        from db.models import Contract, ContractDependency
        from services.discovery.source_confidence import asserts_ownership

        request = job.request if isinstance(job.request, dict) else {}
        parent_company = job.company

        # Walk up parent chain to find company if not set on this job
        if not parent_company:
            seen: set[str] = set()
            current_req = request
            while not parent_company:
                parent_id = current_req.get("parent_job_id")
                if not isinstance(parent_id, str) or parent_id in seen:
                    break
                seen.add(parent_id)
                parent_job = session.get(Job, parent_id)
                if parent_job is None:
                    break
                if parent_job.company:
                    parent_company = parent_job.company
                    break
                current_req = parent_job.request if isinstance(parent_job.request, dict) else {}

        # Structural-ownership lookup. The resolved control graph spawns
        # children for any analyzed node, but the discovery gate only
        # wants to grant ownership to children that are *structural*
        # same-protocol components (impl / proxy / beacon) of the parent.
        #
        # ``cd.relationship_type`` alone isn't sufficient — it's the
        # classifier's verdict on what kind of contract the dep IS, not
        # the edge semantics. A HIGH ether.fi contract calling Lido
        # stETH has ``relationship_type='proxy'`` because stETH is a
        # proxy — that doesn't make stETH ether.fi's structural proxy.
        # We require the proxy/impl/beacon fields on the Contract row
        # to actually link the two:
        #   * impl edge   → parent.implementation == dep.address
        #   * proxy edge  → dep.implementation == parent.address
        #   * beacon edge → parent.beacon == dep.address
        #
        parent_owns_high = False
        structural_rel_by_addr: dict[str, str] = {}
        parent_contract = require_contract_for_job(
            session,
            job,
            context=f"resolution structural propagation parent lookup for {job.id}",
        )
        parent_sources = getattr(parent_contract, "discovery_sources", None)
        parent_owns_high = asserts_ownership(list(parent_sources) if parent_sources else None)
        parent_id = getattr(parent_contract, "id", None)
        parent_impl = (getattr(parent_contract, "implementation", None) or "").lower() or None
        parent_beacon = (getattr(parent_contract, "beacon", None) or "").lower() or None
        parent_addr_lower = (getattr(parent_contract, "address", None) or "").lower() or None
        if parent_id is not None:
            dep_rows = list(
                session.execute(select(ContractDependency).where(ContractDependency.contract_id == parent_id)).scalars()
            )
            # For proxy-direction edges we need to verify the dep's
            # Contract.implementation back-links to the parent.
            # Batch the lookup so the loop stays O(deps) not O(deps×SELECTs).
            proxy_edge_addrs = [row.dependency_address.lower() for row in dep_rows if row.relationship_type == "proxy"]
            dep_impl_by_addr: dict[str, str | None] = {}
            if proxy_edge_addrs:
                dep_contract_rows = session.execute(
                    select(Contract).where(
                        Contract.address.in_(proxy_edge_addrs),
                        Contract.chain_id == chain_id,
                    )
                ).scalars()
                for dc in dep_contract_rows:
                    dep_impl_by_addr[dc.address.lower()] = (dc.implementation or "").lower() or None

            for row in dep_rows:
                rel = row.relationship_type
                if rel not in ("implementation", "proxy", "beacon"):
                    continue
                dep_addr = (row.dependency_address or "").lower()
                if not dep_addr:
                    continue
                structurally_linked = False
                if rel == "implementation":
                    structurally_linked = parent_impl is not None and parent_impl == dep_addr
                elif rel == "proxy":
                    dep_impl = dep_impl_by_addr.get(dep_addr)
                    structurally_linked = (
                        dep_impl is not None and parent_addr_lower is not None and dep_impl == parent_addr_lower
                    )
                else:  # rel == "beacon"
                    structurally_linked = parent_beacon is not None and parent_beacon == dep_addr
                if structurally_linked:
                    structural_rel_by_addr[dep_addr] = rel

        nodes = resolved_graph.get("nodes", [])
        root_address = resolved_graph.get("root_contract_address", "").lower()
        queued_count = 0

        for node in nodes:
            addr = (node.get("address") or "").lower()
            if not addr or not addr.startswith("0x") or len(addr) != 42:
                continue
            if addr == "0x0000000000000000000000000000000000000000":
                # An unset controller/dependency resolves to the zero address;
                # queuing it spawns a discovery job that can only fail with
                # "No verified source code for 0x000…000".
                continue
            if addr == root_address:
                continue
            # Only queue contracts that were analyzed during resolution
            if not node.get("analyzed"):
                continue
            if node.get("node_type") != "contract":
                continue

            # Skip if a job already exists for this address on this chain.
            existing = session.execute(
                select(Job)
                .where(
                    Job.address == addr,
                    Job.chain_id == chain_id,
                )
                .limit(1)
            ).scalar_one_or_none()
            if existing:
                continue

            contract_name = node.get("contract_name") or node.get("label") or addr
            child_request = {
                "address": addr,
                "name": contract_name,
                "chain_id": chain_id,
                "parent_job_id": str(job.id),
                "discovered_by": "resolution",
            }
            structural_rel = structural_rel_by_addr.get(addr)
            if structural_rel is not None:
                child_request["discovery_relationship"] = structural_rel
                child_request["parent_owns_high"] = parent_owns_high

            child_job = create_job(session, child_request, initial_stage=JobStage.discovery)
            if parent_company:
                child_job.company = parent_company
            if job.protocol_id:
                child_job.protocol_id = job.protocol_id
            session.commit()

            queued_count += 1
            logger.info(
                "Job %s: queued discovered contract %s (%s) as job %s",
                job.id,
                contract_name,
                addr,
                child_job.id,
            )

        if queued_count:
            logger.info(
                "Job %s: queued %d contracts discovered during resolution",
                job.id,
                queued_count,
            )

    def _emit_dependency_edges_from_predicate_trees(
        self,
        session: Session,
        job: Job,
        snapshot: ControlSnapshot,
        rpc_url: str,
    ) -> None:
        """Insert ``JobDependency`` rows for every external contract A's
        predicate trees reference as an authority source.

        Walks the static stage's ``predicate_trees`` artifact, finds
        leaves whose ``set_descriptor.authority_contract.address_source``
        traces to a state variable, resolves that variable's value via
        the just-written ``controller_values`` snapshot, then inserts an
        edge ``(A, provider_address, required_stage=policy)`` so A's
        policy stage waits until B's policy stage completes (whereupon
        ``BaseWorker._satisfy_dependencies`` flips the row). For proxies,
        ``provider_address`` is the implementation child job when known,
        because that is where semantic policy artifacts are produced.

        Provider B jobs that don't yet exist are spawned via
        ``create_job`` under a ``(chain_id, address)`` advisory lock so
        concurrent A workers can't race-create duplicate B jobs. This
        mirrors the existing ``_queue_discovered_contracts`` pattern but
        keys on the predicate-tree-referenced address rather than the
        resolved-graph node list.

        Idempotent: re-running resolution on the same A is a no-op
        because ``ON CONFLICT DO NOTHING`` deduplicates on the unique
        edge key. Safe to call before B exists, before B has predicate
        trees, before B has reached any particular stage — the gate
        itself blocks A from advancing until B is ready.
        """
        from sqlalchemy import text as _sa_text
        from sqlalchemy.dialects.postgresql import insert as _pg_insert

        from db.models import JobDependency

        predicate_trees = get_artifact_field(session, job.id, "predicate_trees")
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
        # Build a {state-variable-name: address} map from controller_values.
        # Rows look like ``"state_variable:_owner": {"value": "0xabc..."}``;
        # strip the ``state_variable:`` prefix so the predicate-tree
        # operand-name lookup matches.
        state_var_addresses: dict[str, str] = {}
        for cid, payload in controller_values.items():
            if not isinstance(cid, str) or not isinstance(payload, dict):
                continue
            value = payload.get("value")
            if not isinstance(value, str) or not value.startswith("0x") or len(value) != 42:
                continue
            name = cid.split(":", 1)[1] if ":" in cid else cid
            state_var_addresses.setdefault(name, value.lower())

        # Walk every predicate tree and collect referenced authority
        # contract state-vars. Worth doing once — the same registry can
        # be referenced from many functions on A.
        referenced: set[str] = set()
        for tree_map in tree_maps:
            for tree in tree_map.values():
                _collect_authority_contract_state_vars(tree, referenced)
        if not referenced:
            return

        # Resolve each referenced state-variable name to a concrete
        # address. Missing values are hard failures: otherwise policy may
        # run without the authority job it needs for cross-contract inlining.
        missing_references = sorted(name for name in referenced if name not in state_var_addresses)
        if missing_references:
            logger.error(
                "Job %s: dependency-edge emission missing authority address values: %s",
                job.id,
                missing_references,
            )
            raise RuntimeError(
                f"dependency-edge emission missing authority address values for job {job.id}: {missing_references}"
            )
        target_addresses = sorted({state_var_addresses[name] for name in referenced if name in state_var_addresses})
        if not target_addresses:
            return

        chain_id = require_supported_chain_id(
            chain_id=job.chain_id,
            context=f"resolution dependency edges for job {job.id}",
        )
        parent_company = job.company
        job_address = job.address
        if not job_address:
            raise RuntimeError(f"resolution dependency edges for job {job.id} require address")
        job_address = job_address.lower()

        edges_inserted = 0
        n_satisfied = 0
        n_pending = 0
        for target_addr in target_addresses:
            # Self-references — A's own state-var resolves to A's address
            # — never form a useful dependency. Skip.
            if target_addr == job_address:
                continue
            if target_addr == "0x0000000000000000000000000000000000000000":
                continue
            # Advisory xact-lock keyed on (chain_id, address) so two
            # concurrent A jobs spawning the same B don't double-insert.
            # Mirrors the generic event indexer's insert pattern.
            lock_key = _stable_lock_key(chain_id, target_addr)
            session.execute(_sa_text("SELECT pg_advisory_xact_lock(:k)"), {"k": lock_key})

            provider_lookup = find_dependency_provider_job_for_address(session, target_addr, chain_id=chain_id)
            provider_job = provider_lookup.analysis_job if provider_lookup is not None else None
            dependency_provider_addr = (
                (provider_job.address or target_addr).lower() if provider_job is not None else target_addr
            )
            if provider_job is None:
                provider_request = {
                    "address": target_addr,
                    "name": target_addr,
                    "chain_id": chain_id,
                    "parent_job_id": str(job.id),
                    "discovered_by": "resolution_dependency",
                }
                provider_job = create_job(session, provider_request, initial_stage=JobStage.discovery)
                if parent_company:
                    provider_job.company = parent_company
                if job.protocol_id:
                    provider_job.protocol_id = job.protocol_id
                session.commit()
                dependency_provider_addr = target_addr

            # Don't depend on yourself.
            if provider_job.id == job.id:
                continue

            satisfied_lookup = find_analysis_job_for_address(
                session,
                target_addr,
                required_artifact="effective_permissions",
                chain_id=chain_id,
                completed_only=False,
            )
            already_satisfied = False
            if satisfied_lookup is not None:
                provider_job = satisfied_lookup.analysis_job
                dependency_provider_addr = (provider_job.address or dependency_provider_addr).lower()
                already_satisfied = True

            # Cycle detection: would inserting (A -> B) close a path
            # that's already (B -> ... -> A)? If so, fail the stage instead
            # of inserting a non-blocking degraded edge.
            cycle_path = None
            if not already_satisfied:
                cycle_path = _detect_dep_cycle(
                    session,
                    proposed_depender_id=job.id,
                    proposed_provider_id=provider_job.id,
                )
            if cycle_path:
                logger.error(
                    "Job %s: dependency cycle on provider %s path=%s",
                    job.id,
                    dependency_provider_addr,
                    cycle_path,
                    extra={"provider_address": dependency_provider_addr, "cycle_path": cycle_path},
                )
                raise RuntimeError(f"dependency cycle detected for job {job.id}: {cycle_path}")
            edge_status = "satisfied" if already_satisfied else "pending"
            values = {
                "depender_job_id": job.id,
                "provider_chain_id": chain_id,
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
                        "provider_chain_id",
                        "provider_address",
                        "required_stage",
                    ],
                )
            )
            result = session.execute(stmt)
            # ``Result.rowcount`` is on the concrete ``CursorResult``
            # but the generic ``Result[Any]`` Protocol pyright sees
            # doesn't expose it. Same ``getattr`` pattern as
            # ``workers.event_log_indexer._bulk_insert_logs``.
            if (getattr(result, "rowcount", 0) or 0) > 0:
                edges_inserted += 1
                if edge_status == "satisfied":
                    n_satisfied += 1
                else:
                    n_pending += 1

        if edges_inserted:
            session.commit()
            logger.info(
                "Job %s: emitted %d dependency edge(s) on external authority contracts "
                "(satisfied=%d pending=%d)",
                job.id,
                edges_inserted,
                n_satisfied,
                n_pending,
                extra={
                    "dep_edges_inserted": edges_inserted,
                    "dep_satisfied": n_satisfied,
                    "dep_pending": n_pending,
                },
            )
            record_stage_metric("dep_edges_inserted", edges_inserted)
            record_stage_metric("dep_edges_pending", n_pending)


def _collect_authority_contract_state_vars(node: dict, out: set[str]) -> None:
    """Walk a predicate-tree node and add every state-variable name that
    appears as an ``authority_contract.address_source`` to ``out``. The
    address source is what the semantic builder writes when a leaf's external
    call's destination traced back to a state variable (e.g.
    ``authority.check(...)`` — the ``authority`` storage var)."""
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
    """If adding edge ``(depender → provider)`` would close a cycle,
    return the dep-chain path through job IDs (most-recent-first) for
    ops debugging. Otherwise return ``None`` and the edge is safe.

    Uses a recursive CTE walking forward from ``proposed_provider_id``:
    each hop joins ``job_dependencies.depender_job_id`` to the previous
    row's provider via ``Job.address`` (we don't carry job-id pointers
    on the dep row's provider side — only chain_id+address — so the join
    goes through the ``jobs`` table). Bounded by ``ARRAY[…]`` cycle
    elimination on ``path``. The CTE answer is "is the proposed
    depender reachable from the proposed provider?"
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
             AND provider_job.chain_id = jd.provider_chain_id
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
             AND provider_job.chain_id = jd.provider_chain_id
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
    # Append the closing edge so the path reads "B → ... → A → B".
    path.append(str(proposed_provider_id))
    return path


def _stable_lock_key(chain_id: int, address: str) -> int:
    """Hash ``(chain_id, address)`` to a 63-bit int for ``pg_advisory_xact_lock``.

    Postgres advisory-lock keys are bigint; collapsing to 63 bits keeps
    us inside the signed range. Stable across processes — two workers
    racing to spawn the same provider job acquire the same lock."""
    import hashlib

    effective_chain_id = require_supported_chain_id(
        chain_id=chain_id,
        context=f"resolution dependency lock for {address}",
    )
    h = hashlib.sha256(f"{effective_chain_id}:{address.lower()}".encode()).digest()
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
