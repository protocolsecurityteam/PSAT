"""Resolution worker — builds control snapshot and resolves control graph."""

from __future__ import annotations

import logging
import os
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
from services.discovery.perimeter import queue_discovered_contracts
from services.monitoring.asset_sweep import SweepOutcome
from services.monitoring.balance_observation import (
    NativeReading,
    SweepRequest,
    escalation_reason,
    fetch_asset_page,
    known_swept_assets,
    known_typed_assets,
    observation_contract,
    record_observation,
    run_sweeps,
    scanned_from_block,
    sweep_from_block,
)
from services.monitoring.balance_reads import pinned_native_balances
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
from utils.balance_status import ASSET_SET_STATUS_FETCH_FAILED, BALANCE_WRITER_RESOLUTION
from utils.chains import UnknownChainError, chain_by_id, chain_enabled
from utils.logging import record_degraded, record_stage_metric
from utils.rpc import require_rpc_url
from workers.base import BaseWorker

logger = logging.getLogger("workers.resolution_worker")

RECURSION_MAX_DEPTH = int(os.getenv("PSAT_RECURSION_MAX_DEPTH", "6"))


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
        context=f"resolution rpc for job {job.id}",
    )


def _chain_id_for_job(job: Job) -> int:
    """The job's first-class ``chain_id`` (invariant 1). Prefers the populated
    ``jobs.chain_id`` column and falls back to deriving it from
    ``request["chain"]`` via the canonical registry; mainnet (1) is the last
    resort for a chain-less row so behaviour is unchanged there."""
    chain_id = getattr(job, "chain_id", None)
    if isinstance(chain_id, int):
        return chain_id
    request = job.request if isinstance(job.request, dict) else {}
    return derive_job_chain_id(request.get("chain"), job.address) or 1


def _chain_name_for_job(job: Job) -> str:
    """Canonical chain name for the job's first-class ``chain_id``.

    Stamped onto spawned child/dependency-provider jobs so a discovered
    contract inherits the parent's chain instead of cascading as ``None`` when
    the request payload lacks a chain (a chainless ``/api/analyze`` submission).
    Mainnet resolves to ``"ethereum"`` so mainnet spawns are unchanged."""
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
        logger.info(
            "Resolution stage started for job %s address=%s name=%s",
            job.id,
            job.address or "0x0",
            job.name or "Contract",
        )
        rpc_url = _rpc_url_for_job(job)
        chain_id = _chain_id_for_job(job)

        # Read control_tracking_plan from DB
        tracking_plan = get_artifact(session, job.id, "control_tracking_plan")
        if not isinstance(tracking_plan, dict):
            raise RuntimeError("control_tracking_plan artifact not found")

        # Read contract_analysis from DB (needed for recursive resolution)
        contract_analysis = get_artifact(session, job.id, "contract_analysis")
        if not isinstance(contract_analysis, dict):
            raise RuntimeError("contract_analysis artifact not found")
        predicate_trees = get_artifact(session, job.id, "predicate_trees")
        if not isinstance(predicate_trees, dict):
            predicate_trees = None

        # For impl jobs, read storage from the proxy address (where state lives)
        request = job.request if isinstance(job.request, dict) else {}
        proxy_address = request.get("proxy_address")
        # An UpgradeableBeacon governs this instance: its owner() is the
        # instance's upgrade authority and is read live from the beacon below.
        beacon_address = proxy_address if request.get("proxy_type") == "beacon" else None
        # Deployment this resolution is attributed to (proxy for an impl in proxy
        # context, else NULL) so a shared impl can hold per-proxy result sets.
        deployment_address = normalize_deployment(proxy_address)
        getter_fallback_address: str | None = None
        if proxy_address:
            # Reading impl state via the proxy is correct for storage-backed
            # vars, but immutable authority addresses live in the impl bytecode
            # and revert when the proxy doesn't delegatecall to this impl
            # (beacon / per-instance patterns, e.g. EtherFiNode). Keep the impl
            # address as a getter fallback so those reverting reads recover.
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

        # Build control snapshot via RPC calls
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
        # Keep as artifact — policy stage reads it as JSON
        store_artifact(session, job.id, "control_snapshot", data=snapshot)
        # A reverting controller read is recorded as an ``eth_call_error`` NULL
        # entry (see build_control_snapshot); counting those as resolved hid the
        # etherfi NULL-controller incident. Split the count so the resolved metric
        # reflects only real values and the read errors chart on their own.
        _controller_values = snapshot.get("controller_values", {})
        _controllers_errored = sum(
            1 for cv in _controller_values.values() if cv.get("observed_via") == "eth_call_error"
        )
        record_stage_metric("controllers_resolved", len(_controller_values) - _controllers_errored)
        if _controllers_errored:
            record_stage_metric("controllers_read_error", _controllers_errored)
        if snapshot.get("block_number") is not None:
            record_stage_metric("block_number", snapshot.get("block_number"))

        # Write to controller_values table
        contract_row = session.execute(select(Contract).where(Contract.job_id == job.id).limit(1)).scalar_one_or_none()
        if contract_row:
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
                        # Absent in the snapshot => NULL, not a guessed value.
                        authority_provenance=cv.get("authority_provenance"),
                    )
                )
            session.commit()

        logger.info(
            "Resolution stage control snapshot complete for job %s address=%s name=%s",
            job.id,
            job.address or "0x0",
            job.name or "Contract",
        )

        # Fetch token balances
        self._fetch_balances(
            session, job, contract_row, chain_id=chain_id, heartbeat=lambda: self._heartbeat(session, job)
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
        if resolved_graph:
            # Persist each nested contract's artifacts so the policy stage can
            # read them back by address (no local filesystem).
            store_nested_artifacts(session, job.id, nested_artifacts)
            # Keep as artifact — policy stage reads it as JSON
            store_artifact(session, job.id, "resolved_control_graph", data=resolved_graph)
            # Persist the classify cache so the policy stage skips re-running
            # the 6-10 RPC fan-out per address. dict[str, tuple] → JSON-friendly
            # dict[str, list] for storage.
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

            # Write to control_graph_nodes and control_graph_edges tables.
            # Shared with the policy stage's graph-refresh rewrite: the same
            # replace keeps the table plane equal to whichever graph artifact
            # was stored last, instead of freezing it at the pre-refresh walk.
            if contract_row:
                replace_control_graph_rows(
                    session,
                    contract_id=contract_row.id,
                    deployment_address=deployment_address,
                    resolved_graph=resolved_graph,
                )
                session.commit()

            # Queue analysis jobs for contracts discovered during resolution
            self._queue_discovered_contracts(session, job, cast(dict, resolved_graph), rpc_url)

        # Emit JobDependency edges so the policy stage waits for any
        # external authority contract referenced by this job's predicate
        # trees (e.g. EtherFiAdmin.upgradeTo's roleRegistry call).
        # Defensive: a failure to enumerate deps must not block the
        # resolution stage from completing — the depender just won't
        # benefit from cross-contract inlining at policy time.
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

        # Isolated for the same reason as the dependency edges above: this plane
        # publishes only lower bounds, so it must never be able to fail a stage
        # that proved something else.
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

        # Isolated on the same terms as the two steps above, and for the same
        # reason: this plane can only ADD addresses to sinks that had none, so a
        # failure here costs pricing coverage and proves nothing false. It must
        # never fail a stage that already resolved a control graph.
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
        """Publish this registry's role floors. Returns the rows written.

        The opportunistic fast path: it refreshes whatever this job's own
        registry can prove while the stage is already here. The periodic
        refresher (``services.monitoring.role_holder_cycle``) is what guarantees
        a registry is reached at all, on a clock that does not depend on a job
        arriving for it.

        The gate is cursor EXISTENCE on both AccessControl topics, not warmth. A
        cold cursor still mints a row whose floor is withheld (``holders`` NULL,
        ``coverage`` partial); skipping it instead would erase the distinction
        between a registry with no roles and a registry nothing was read from.
        Everything past that precondition is the module's to refuse.

        Every outcome is recorded — a closed gate, an open gate that resolved
        nothing, and N rows written. They are three different facts, and a metric
        that fires only on the third makes the first two indistinguishable from
        the stage never running.

        The registry is the RUNTIME address — the proxy an impl job's logs are
        actually emitted at, never the implementation its ``contracts`` row is
        keyed to.
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
        self._record_role_plane_outcome(job, registry_address, OUTCOME_ROWS_WRITTEN, written)
        return written

    @staticmethod
    def _record_role_plane_outcome(job: Job, registry_address: str | None, outcome: str, written: int) -> None:
        """One metric and one log line per pass, whatever the pass concluded."""
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
        """Dereference this job's flow-sink asset getters. Returns rows published.

        The address read at is the RUNTIME one — the proxy for an implementation
        in proxy context, else the job's own address. That is also the sole basis
        for ``proven_proxied``: an implementation job carries its proxy in the
        request, and that is an earned fact about where this code executes. A job
        with no proxy in its request is NOT thereby proven unproxied, which is
        exactly why the invariant's other value is ``not_determined``.

        The height comes from ``pin_probe_block`` — confirmation-depth-deep and
        hash-witnessed. When it cannot be pinned nothing is read: falling back to
        ``"latest"`` would publish an address at an unrecorded, unrepeatable
        height, and every row here is a now-fact that lives or dies by its block.
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
        # Upsert on (job_id, name): a re-run replaces the payload wholesale at a
        # new pinned height rather than accumulating, so no stale address ever
        # sits beside a fresh one pretending to share its block.
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
        """Fetch ETH + token balances and store in contract_balances table.

        ``chain_id`` is required: it scopes every Etherscan v2 read to
        the job's chain so an L2 job records L2 balances/prices, not mainnet
        ones. A chainless balance fetch can no longer default to mainnet."""
        from utils.etherscan import TokenBalancePage, get_eth_balance, get_native_price, parallel_get
        from utils.rpc import rpc_url_for_chain_id

        address = job.address
        if not address or not contract_row:
            return

        request = job.request if isinstance(job.request, dict) else {}
        # The address to READ. Which contract row the answer is FILED against is
        # then decided by that address, not by the job — a proxy's holdings
        # belong to the proxy's row. Filing them against the implementation's row
        # is what let a later read at the implementation's own address win the
        # native class and evict a real 19.06 ETH balance.
        target_address = request.get("proxy_address") or address
        contract = observation_contract(
            session,
            fallback=contract_row,
            chain_id=chain_id,
            requested_address=target_address,
        )
        observed_address = contract.address or target_address

        self.update_detail(session, job, "Fetching token balances")
        # One pinned native read first. A zero is only ever publishable as a
        # PROVEN zero from here: Etherscan's ``account/balance`` is ``tag=latest``
        # and its answer carries no height. Failure drops through to the unpinned
        # path below, where the same zero is not_determined.
        pinned_block, pinned_wei = pinned_native_balances([observed_address], chain_id=chain_id)

        # Fan out the three Etherscan calls (eth balance, token balances, eth
        # price). All three serialise on the global rate lock, so threading
        # only stacks RTTs — the limiter is preserved.
        results = parallel_get(
            {
                "eth_wei": (lambda: get_eth_balance(observed_address, chain_id=chain_id)),
                "tokens": (lambda: fetch_asset_page(observed_address, chain_id=chain_id)),
                "native_price": (lambda: get_native_price(chain_id)),
            },
            heartbeat=heartbeat,
        )

        eth_wei_raw = results.get("eth_wei")
        tokens_raw = results.get("tokens")
        native_failed = isinstance(eth_wei_raw, BaseException)
        tokens_failed = isinstance(tokens_raw, BaseException)
        if native_failed or tokens_failed:
            primary_exc = eth_wei_raw if native_failed else tokens_raw
            assert isinstance(primary_exc, BaseException)
            record_degraded(
                phase="balance_fetch",
                exc=primary_exc,
                context={
                    "address": observed_address,
                    "eth_failed": native_failed,
                    "tokens_failed": tokens_failed,
                },
            )
            logger.warning(
                "Job %s: balance fetch failed: eth=%r tokens=%r",
                job.id,
                eth_wei_raw,
                tokens_raw,
            )
        page = (
            TokenBalancePage(
                rows=[],
                page_length=None,
                status=ASSET_SET_STATUS_FETCH_FAILED,
                pages_read=0,
                basis="etherscan addresstokenbalance raised inside the parallel fan-out",
            )
            if tokens_failed
            else cast(TokenBalancePage, tokens_raw)
        )

        # The pinned word wins when there is one; otherwise the unpinned answer,
        # or nothing at all when the read failed. ``eth_wei is None`` is the
        # not-known state and never becomes a zero.
        eth_wei: int | None
        native_block: int | None
        if pinned_block is not None and observed_address.lower() in pinned_wei:
            eth_wei = pinned_wei[observed_address.lower()]
            native_block = pinned_block
        else:
            native_block = None
            eth_wei = None if native_failed else cast(int, eth_wei_raw)

        # Native gas balance, valued in this chain's OWN native coin: the
        # symbol/name are the registry's native_asset, and the USD quote is that
        # coin's price — an L2/alt-L1 balance is never labeled or priced as
        # mainnet ETH.
        native_asset = chain_by_id(chain_id).native_asset
        if native_asset == "ETH":
            native_symbol, native_name = "ETH", "Ether"
        else:
            native_symbol, native_name = native_asset, native_asset
        native_price_raw = results.get("native_price")
        native_price: float | None
        if isinstance(native_price_raw, BaseException):
            record_degraded(
                phase="native_price_fetch",
                exc=native_price_raw,
                context={"address": observed_address, "chain_id": chain_id},
            )
            logger.warning("Job %s: native price fetch failed: %s", job.id, native_price_raw)
            native_price = None
        else:
            native_price = cast(float, native_price_raw)

        # THE HALVES FAIL INDEPENDENTLY, SO EACH IS PERSISTED INDEPENDENTLY.
        # There is no early return here, and reinstating one would be a
        # correctness bug rather than a shortcut: the fetch row's two statuses
        # are per class, so returning on ``native_failed or tokens_failed``
        # writes a row saying ``returned_assets`` (or ``proven_nonzero``) for the
        # half that SUCCEEDED while persisting none of its rows. That row-less
        # non-failed class then wins ``contract_balances_latest`` and withdraws
        # every prior holding of it — an absence manufactured by the writer, and
        # invisible to ``contracts_missing_current_rows``, which reads the status.
        #
        # The invariant every reader depends on: A NON-FAILED CLASS STATUS IS A
        # PROMISE THAT THAT CLASS'S ROW SET WAS WRITTEN — possibly empty, when
        # empty is what was observed (``proven_zero``, ``returned_empty``, or a
        # page whose every entry was zero-balance), but never merely skipped.
        # It is enforced in ``balance_observation.record_observation``, the one
        # write point both producers go through.
        escalation = escalation_reason(session, contract_id=contract.id, page=page)
        sweeps: dict[int, SweepOutcome] = {}
        sweep_cost = None
        if escalation is not None and contract.address:
            sweeps, sweep_cost = run_sweeps(
                [
                    SweepRequest(
                        contract_id=contract.id,
                        address=contract.address,
                        chain_id=chain_id,
                        from_block=sweep_from_block(session, contract_id=contract.id),
                        reason=escalation,
                        known_assets=known_swept_assets(session, contract_id=contract.id),
                        known_typed=known_typed_assets(session, contract_id=contract.id),
                        union_from_block=scanned_from_block(session, contract_id=contract.id),
                    )
                ],
                rpc_url_for=lambda cid: rpc_url_for_chain_id(cid),
            )
        recorded = record_observation(
            session,
            contract=contract,
            chain_id=chain_id,
            native=NativeReading(
                wei=eth_wei,
                block_number=native_block,
                failed=native_failed and native_block is None,
                price_usd=native_price,
                symbol=native_symbol,
                name=native_name,
            ),
            page=page,
            writer=BALANCE_WRITER_RESOLUTION,
            sweep=cast(SweepOutcome | None, sweeps.get(contract.id)),
            escalation=escalation,
            cost_note=(
                f"cycle scan cost {sweep_cost.get_logs} getLogs + {sweep_cost.multicall} multicall + "
                f"{sweep_cost.head_reads} head over 1 escalated contract"
                if sweep_cost is not None
                else None
            ),
        )
        session.commit()
        logger.info(
            "Job %s: stored %d balance(s) for %s",
            job.id,
            len(recorded.rows),
            observed_address,
        )

    def _queue_discovered_contracts(self, session: Session, job: Job, resolved_graph: dict, rpc_url: str) -> None:
        """Queue analysis jobs for contracts found during resolution that have no existing job.

        No budget: the walk's own ``max_depth`` already bounds this graph. The
        policy-stage refresh, which is recursive, passes one.
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
        ``create_job`` under a ``(chain, address)`` advisory lock so
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
        # address. Missing values are skipped — the snapshot may not
        # have populated the row yet (e.g. private state-var without a
        # public getter, or RPC failure during the snapshot pass).
        target_addresses = sorted({state_var_addresses[name] for name in referenced if name in state_var_addresses})
        if not target_addresses:
            return

        # Dependency provider B is on the same chain as A (v1 is chain-as-island).
        # Derive from the job's first-class chain so the edge's
        # provider_chain and any spawned provider job are chain-stamped even when
        # the request payload carries no chain.
        chain = _chain_name_for_job(job)
        # Defense in depth: A's chain equals every provider B's chain, so
        # a gated parent implies gated providers — but a disabled chain must spawn
        # no provider jobs, so gate the whole emission here. In practice A is always
        # enabled (it is running), so this never fires on mainnet-only.
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
            # Self-references — A's own state-var resolves to A's address
            # — never form a useful dependency. Skip.
            if target_addr == (job.address or "").lower():
                continue
            # Advisory xact-lock keyed on (chain, address) so two
            # concurrent A jobs spawning the same B don't double-insert.
            # Mirrors the generic event indexer's insert pattern.
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

            # Don't depend on yourself.
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

            # Cycle detection: would inserting (A → B) close a path
            # that's already (B → ... → A)? If so we'd have A waiting on
            # B which is (transitively) waiting on A — deadlock under
            # the claim gate. Insert with status='cycle_degraded'
            # instead so the gate doesn't block A and the resolver
            # short-circuits the leaf to external_check_only at
            # evaluation time.
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
            # ``Result.rowcount`` is on the concrete ``CursorResult``
            # but the generic ``Result[Any]`` Protocol pyright sees
            # doesn't expose it. Same ``getattr`` pattern as
            # ``workers.event_log_indexer._bulk_insert_logs``.
            if (getattr(result, "rowcount", 0) or 0) > 0:
                edges_inserted += 1
                if edge_status == "satisfied":
                    n_satisfied += 1
                elif edge_status == "cycle_degraded":
                    n_cycle += 1
                    # A dependency cycle is a degraded outcome — the edge is
                    # inserted non-blocking so the depender doesn't deadlock under
                    # the claim gate. Surface it instead of letting a real stall
                    # condition land silently.
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
    on the dep row's provider side — only chain+address — so the join
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
    # Append the closing edge so the path reads "B → ... → A → B".
    path.append(str(proposed_provider_id))
    return path


def _stable_lock_key(chain: str | None, address: str) -> int:
    """Hash ``(chain, address)`` to a 63-bit int for ``pg_advisory_xact_lock``.

    Postgres advisory-lock keys are bigint; collapsing to 63 bits keeps
    us inside the signed range. Stable across processes — two workers
    racing to spawn the same provider job acquire the same lock."""
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
