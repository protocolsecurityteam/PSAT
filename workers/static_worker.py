"""Static analysis worker — runs Slither and contract analysis in a temp directory."""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import tempfile
import textwrap
from pathlib import Path
from typing import Any, cast

from sqlalchemy import select

from db.models import Contract, ContractSummary, Job, JobDependency, JobStage, RoleDefinition, derive_job_chain_id
from db.queue import (
    _MUTABLE_CONTRACT_FIELDS,
    create_job,
    get_artifact,
    get_source_files,
    reconcile_impl_job_for_proxy,
    store_artifact,
)
from schemas.contract_analysis import ContractAnalysis
from services.clients.rpc import default_rpc_url, normalize_hex  # used for address comparison
from services.discovery import (
    build_dependency_visualization,
    build_unified_dependencies,
    classify_contracts,
    enrich_dependency_metadata,
    find_dependencies,
    find_dynamic_dependencies,
)
from services.discovery.dynamic_dependencies import NoNewTransactionsError
from services.discovery.fetch import _confine, sanitize_evm_version
from services.monitoring.proxy_watcher import resolve_current_implementation
from services.resolution.tracking_plan import build_control_tracking_plan
from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts
from utils.chains import UnknownChainError, chain_by_id, chain_enabled, require_chain
from utils.logging import log_timed_phase, record_degraded, record_stage_metric
from workers.base import BaseWorker, JobHandledDirectly
from workers.static_support.dynamic_deps import _merge_dynamic_deps, _start_block_from_prev_dyn
from workers.static_support.source_prep import (
    _detect_solc_version,
    _detect_src_dir,
    _prune_remappings,
    _relax_pragmas,
)
from workers.static_support.upgrade_history import (
    _apply_known_names_to_uh,
    _from_block_for_upgrade_history,
    _merge_upgrade_history,
)

logger = logging.getLogger("workers.static_worker")

# ---------------------------------------------------------------------------
# Error logging template
# ---------------------------------------------------------------------------
_ERROR_TEMPLATE = """
================== STATIC WORKER ERROR ==================
Job:      {job_id}
Address:  {address}
Contract: {contract_name}
Phase:    {phase}
----------------------------------------------------------
{error}
==========================================================
""".strip()


# WARNING (not ERROR): callers swallow the underlying exception and continue with a
# stub artifact, so the job-level outcome is degraded — not failed. Pair every call
# site with ``record_degraded`` so the swallow shows up in the stage_errors artifact.
def _log_phase_error(job_id: str, address: str, contract_name: str, phase: str, error: str) -> None:
    logger.warning(
        _ERROR_TEMPLATE.format(
            job_id=job_id,
            address=address,
            contract_name=contract_name,
            phase=phase,
            error=error,
        )
    )


def _request_rpc_url(job: Job) -> str | None:
    """eRPC URL for the job's own chain, resolved via the first-class
    ``jobs.chain_id`` column (``_parent_chain_name``), not the request JSONB —
    a chainless ``/api/analyze`` submission carries the mainnet edge default
    only in the column, so a request-only read comes back None and silently
    skips classification/deps. The request's local-node override still wins."""
    request = job.request if isinstance(job.request, dict) else {}
    explicit = request.get("rpc_url")
    return default_rpc_url(
        explicit_rpc_url=explicit if isinstance(explicit, str) else None,
        chain=_parent_chain_name(job),
    )


def _parent_chain_id(job: Job) -> int:
    """The parent job's first-class ``chain_id`` (inv. 6): the populated
    ``jobs.chain_id`` column, else derived from ``request["chain"]`` via the
    registry, else mainnet. Threaded into RPC reads so the inv-7 URL↔chain_id
    guard is armed."""
    chain_id = getattr(job, "chain_id", None)
    if isinstance(chain_id, int):
        return chain_id
    request = job.request if isinstance(job.request, dict) else {}
    return derive_job_chain_id(request.get("chain"), job.address) or 1


def _parent_chain_name(job: Job) -> str:
    """Canonical chain name of the parent job, for stamping onto a spawned impl
    child so chain never cascades as ``None`` (inv. 6). Uses the first-class
    ``jobs.chain_id`` column, else derives from ``request["chain"]`` via the
    registry; mainnet resolves to ``"ethereum"`` so mainnet spawns are unchanged."""
    chain_id = _parent_chain_id(job)
    try:
        return chain_by_id(chain_id).name
    except UnknownChainError as exc:
        # The fallback keeps the spawn path alive, but stamping "ethereum" onto a
        # child whose parent lives on an unregistered chain is a wrong answer, not
        # a missing one — surface it rather than let the default pass for a lookup.
        # ``process()`` calls this ~10× per job, so report each unknown chain_id
        # once: one data bug is one line, not ten. The seen-set hangs off the job
        # row (same trick as ``_heartbeat_job_id`` in ``base.py``) rather than a
        # ContextVar — the K=1 loop runs every job on the worker's own context,
        # where a ContextVar set would silence every job after the first.
        seen = getattr(job, "_unknown_chains_reported", None)
        if seen is None:
            seen = set()
            setattr(job, "_unknown_chains_reported", seen)
        if chain_id not in seen:
            seen.add(chain_id)
            record_degraded(
                phase="parent_chain_name",
                exc=exc,
                context={"job_id": str(getattr(job, "id", "")), "chain_id": chain_id},
            )
            logger.warning(
                "Unknown chain_id %s on job %s; falling back to ethereum for the spawned child",
                chain_id,
                getattr(job, "id", None),
                extra={"exc_type": type(exc).__name__, "chain_id": chain_id},
            )
        return "ethereum"


def _redirect_proxy_policy_dependencies(
    session,
    *,
    chain: str | None,
    proxy_addr: str,
    impl_addr: str,
) -> int:
    """Move pending policy dependency edges from a proxy to its impl job.

    Resolution can discover an authority proxy before static has created the
    proxy's implementation child. At that point the only durable provider
    address is the proxy. Once static resolves the implementation, the edge
    must wait on the impl job because policy artifacts are produced there.
    """
    from datetime import datetime, timezone

    proxy_addr = proxy_addr.lower()
    impl_addr = impl_addr.lower()
    if proxy_addr == impl_addr:
        return 0

    stmt = select(JobDependency).where(
        JobDependency.provider_address == proxy_addr,
        JobDependency.required_stage == JobStage.policy,
        JobDependency.status == "pending",
    )
    if chain is None:
        stmt = stmt.where(JobDependency.provider_chain.is_(None))
    else:
        stmt = stmt.where(JobDependency.provider_chain == chain)
    rows = session.execute(stmt).scalars().all()

    changed = 0
    now = datetime.now(timezone.utc)
    for row in rows:
        duplicate = session.execute(
            select(JobDependency)
            .where(
                JobDependency.depender_job_id == row.depender_job_id,
                JobDependency.provider_chain == row.provider_chain,
                JobDependency.provider_address == impl_addr,
                JobDependency.required_stage == row.required_stage,
                JobDependency.id != row.id,
            )
            .limit(1)
        ).scalar_one_or_none()
        if duplicate is not None:
            row.status = "satisfied"
            row.satisfied_at = now
        else:
            row.provider_address = impl_addr
        changed += 1

    if changed:
        session.commit()
        logger.info(
            "Redirected %d pending policy dependency edge(s) from proxy %s to implementation %s",
            changed,
            proxy_addr,
            impl_addr,
        )
    return changed


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------


_GENERIC_PROXY_NAMES = {
    "uupsproxy",
    "erc1967proxy",
    "transparentupgradeableproxy",
    "proxy",
    "beaconproxy",
    "ossifiableproxy",
    "upgradeablebeacon",
}


def _contract_label_from_meta(project_dir: Path) -> str:
    """Derive the human-readable contract label for the dependency graph.

    Reads ``contract_meta.json`` written by scaffold/static_worker; falls
    back to the workspace directory name. Generic proxy contract names are
    swapped for the job's ``display_name`` when available.
    """
    meta_path = project_dir / "contract_meta.json"
    if not meta_path.exists():
        return project_dir.name
    try:
        meta = json.loads(meta_path.read_text())
    except Exception:
        return project_dir.name
    name = meta.get("contract_name", "")
    if name.lower().replace("_", "") in _GENERIC_PROXY_NAMES and meta.get("display_name"):
        return meta["display_name"]
    return name or project_dir.name


# ---------------------------------------------------------------------------
# Dynamic dependency merge helper
# ---------------------------------------------------------------------------


def _load_prev_dynamic_deps(session, job, tx_hashes: list[str] | None) -> dict | None:
    """Read the persisted dynamic_dependencies artifact, if any. Tx-hash overrides skip the cache."""
    if tx_hashes:
        return None
    raw = get_artifact(session, job.id, "dynamic_dependencies")
    return raw if isinstance(raw, dict) else None


# ---------------------------------------------------------------------------
# Upgrade history merge helper
# ---------------------------------------------------------------------------


def _finalize_upgrade_history(
    session,
    job,
    address: str,
    uh_pre: dict | None,
    prev_uh: dict | None,
    unified: dict,
    contract_row: Contract | None = None,
) -> dict | None:
    """Apply known-name backfill, merge with prior cached upgrade history,
    persist, and project to relational rows.

    ``uh_pre`` is the freshly-computed upgrade history from the parallel
    section. After persistence, the upgrade events are projected into
    ``UpgradeEvent`` rows (for company-overview aggregates) and historical
    impl addresses are backfilled into ``Contract`` rows (so the
    audit-coverage matcher can link audits whose scope names a past impl).
    The projection step is best-effort — the artifact is already stored
    when it runs, so a failure leaves the data recoverable via re-running.
    """
    if uh_pre is None:
        return None

    _apply_known_names_to_uh(uh_pre, unified)

    if prev_uh and prev_uh.get("proxies"):
        if uh_pre.get("proxies"):
            uh = _merge_upgrade_history(prev_uh, uh_pre)
        else:
            uh = prev_uh
    else:
        uh = uh_pre

    if not uh.get("proxies"):
        return None

    store_artifact(session, job.id, "upgrade_history", data=uh)

    # Project the artifact's "upgraded" events into UpgradeEvent rows and
    # backfill historical impl Contract rows. Both operate on the in-memory
    # dict — no re-read of storage. Errors here are non-fatal: the artifact
    # is already stored, so a failure leaves the data still recoverable
    # via re-running this stage.
    stats_proxy_ids: set[int] = set()
    if contract_row is not None:
        try:
            from services.discovery.upgrade_history import (
                backfill_historical_impl_contracts,
                project_to_events,
            )

            stats = project_to_events(
                session,
                subject_contract_id=contract_row.id,
                subject_chain=contract_row.chain,
                artifact_data=uh,
            )
            session.commit()
            stats_proxy_ids = set(stats.get("proxy_contract_ids") or ())
            logger.info(
                "Static stage upgrade events projected for job %s (proxies %d/%d, events %d, skipped %d)",
                job.id,
                stats["proxies_projected"],
                stats["proxies_seen"],
                stats["events_written"],
                stats["proxies_skipped_no_contract"],
            )
            if contract_row.protocol_id is not None and stats["impl_addrs"]:
                # parent_proxy_sources gates ownership: when the subject
                # proxy only has low-confidence sources (e.g. dapp_crawl),
                # the impls land as orphans so a foreign proxy doesn't
                # multiply itself into N "owned" rows. See
                # services/discovery/source_confidence.py.
                #
                # parent_proxy_current_impl_address lets the gate consult
                # the current impl when the proxy is itself LOW-sourced
                # (e.g. ``structural_adoption`` post-3a8f4d1c9b07). The
                # impl is the authoritative HIGH anchor in the LRTSquare*
                # shape — same one-hop discipline as 4d72e9b1f035 branch B.
                backfill_historical_impl_contracts(
                    session,
                    protocol_id=contract_row.protocol_id,
                    chain=contract_row.chain,
                    impl_addrs=stats["impl_addrs"],
                    parent_proxy_sources=contract_row.discovery_sources,
                    parent_proxy_current_impl_address=contract_row.implementation,
                )
        except Exception as exc:
            record_degraded(
                phase="static_upgrade_history_projection",
                exc=exc,
                context={"job_id": job.id, "address": job.address or "0x0"},
            )
            logger.warning(
                "Upgrade event projection failed for job %s: %s",
                job.id,
                exc,
            )

    # The executor fold is a SEPARATE failure domain from the projection: it is
    # the only part of this stage that touches the wire twice more (receipts,
    # creation witnesses), and a wire failure must cost the receipt facts only,
    # never the event rows that were just written.
    if contract_row is not None and stats_proxy_ids:
        try:
            from services.clients.rpc import chain_id_for_chain_name
            from services.discovery.upgrade_history import fold_upgrade_transactions

            chain_id = chain_id_for_chain_name(contract_row.chain or "ethereum")
            if chain_id is not None:
                fold_stats = fold_upgrade_transactions(
                    session,
                    chain_id=chain_id,
                    contract_ids=sorted(stats_proxy_ids),
                )
                session.commit()
                logger.info(
                    "Static stage upgrade executor fold for job %s (tx %d/%d, kinds %s)",
                    job.id,
                    fold_stats["tx_folded"],
                    fold_stats["tx_in_scope"],
                    fold_stats["kinds"],
                )
        except Exception as exc:
            # A DB-layer failure leaves the session in a failed transaction, and
            # every later statement in this stage would raise
            # PendingRollbackError instead of doing its work. Roll back first so
            # the fold's failure costs the fold only.
            session.rollback()
            record_degraded(
                phase="static_upgrade_executor_fold",
                exc=exc,
                context={"job_id": job.id, "address": job.address or "0x0"},
            )
            logger.warning(
                "Upgrade executor fold failed for job %s: %s",
                job.id,
                exc,
            )

    return uh


# Proxy types where the implementation is baked into bytecode (immutable) —
# safe to reuse from cache without an RPC slot check.
_IMMUTABLE_PROXY_TYPES = frozenset({"eip1167"})

# Proxy types with multiple facets that can't be verified with a single slot check.
_MULTI_FACET_PROXY_TYPES = frozenset({"eip2535"})

_PROXY_FIELDS = _MUTABLE_CONTRACT_FIELDS


def _validate_cached_dep_classifications(
    prev_cls: dict,
    rpc_url: str,
    *,
    chain_id: int | None = None,
) -> dict[str, dict]:
    """Validate cached dependency proxy classifications against live on-chain state.

    For each cached proxy classification that has a known implementation
    address, makes a single RPC call to verify the implementation hasn't
    changed.  Returns a dict of ``{address: classification}`` entries that
    are still valid.

    Stale entries (where the on-chain implementation differs) are dropped
    so ``classify_contracts`` will re-classify them from scratch.

    Non-proxy entries and immutable proxy types (e.g. EIP-1167) are kept
    unconditionally.
    """
    valid: dict[str, dict] = {}

    for addr, cls_info in prev_cls.get("classifications", {}).items():
        if not isinstance(cls_info, dict):
            continue

        # Non-proxy classifications are immutable — keep as-is
        if cls_info.get("type") != "proxy":
            valid[addr] = cls_info
            continue

        proxy_type = cls_info.get("proxy_type")
        cached_impl = cls_info.get("implementation")

        # Immutable proxy types: implementation baked into bytecode
        if proxy_type in _IMMUTABLE_PROXY_TYPES:
            valid[addr] = cls_info
            continue

        # Diamond proxies: can't verify with a single call
        if proxy_type in _MULTI_FACET_PROXY_TYPES:
            continue

        # No cached implementation to compare — keep as-is (e.g. beacon
        # proxies that only have a beacon address, or partial classifications).
        if not cached_impl:
            valid[addr] = cls_info
            continue

        # Single RPC call to check current implementation
        try:
            current_impl = resolve_current_implementation(addr, rpc_url, proxy_type=proxy_type, chain_id=chain_id)
            if not current_impl:
                continue  # can't verify — re-classify to be safe
            if normalize_hex(current_impl) != normalize_hex(cached_impl):
                logger.info(
                    "Cached dep %s proxy upgraded: cached=%s current=%s — will re-classify",
                    addr,
                    cached_impl,
                    current_impl,
                )
                continue  # upgraded — drop from cache
        except Exception as exc:
            logger.debug("Cached dep %s proxy check failed: %s — will re-classify", addr, exc)
            continue

        valid[addr] = cls_info

    return valid


def _apply_proxy_cache(session, src_contract, contract_row, proxy_state: dict | None = None) -> dict:
    """Copy proxy fields from *src_contract* (or *proxy_state* dict) to
    *contract_row* and return a ``classify_single``-style dict for downstream
    consumers.

    When *proxy_state* is provided (e.g. from a ``cached_proxy_state``
    artifact), its values take precedence over the ``src_contract`` attributes
    — this handles the case where the unique-constraint reuse in
    ``copy_static_cache`` reset the proxy fields on the shared Contract row.
    """
    for field in _PROXY_FIELDS:
        if proxy_state is not None:
            setattr(contract_row, field, proxy_state.get(field))
        else:
            setattr(contract_row, field, getattr(src_contract, field))
    session.commit()

    is_proxy = proxy_state["is_proxy"] if proxy_state else src_contract.is_proxy
    if not is_proxy:
        return {"type": "regular"}
    return {
        "type": "proxy",
        **{
            f: (proxy_state.get(f) if proxy_state else getattr(src_contract, f))
            for f in _PROXY_FIELDS
            if f != "is_proxy"
        },
    }


def _check_proxy_cache(session, job, contract_row) -> dict | None:
    """Check whether proxy classification can be reused from a cached source job.

    Returns a ``classify_single``-style dict if the cached proxy state is still
    valid, or ``None`` when full ``_resolve_proxy`` must run.
    """
    request = job.request if isinstance(job.request, dict) else {}
    if not request.get("static_cached"):
        return None

    source_job_id = request.get("cache_source_job_id")
    if not source_job_id:
        return None

    try:
        src_contract = session.execute(
            select(Contract).where(Contract.job_id == source_job_id).limit(1)
        ).scalar_one_or_none()
    except Exception as exc:
        logger.debug("Cache source contract lookup failed for job %s: %s", job.id, exc)
        src_contract = None

    # With the (address, chain) unique constraint, copy_static_cache may have
    # reused the same Contract row (updating its job_id to the target and
    # resetting proxy fields).  Read the saved proxy state from artifact.
    cached_proxy_state: dict | None = None
    if src_contract is None:
        _raw_proxy = get_artifact(session, job.id, "cached_proxy_state")
        if not isinstance(_raw_proxy, dict):
            return None
        cached_proxy_state = _raw_proxy
        # Use contract_row as the base but check proxy state from artifact
        src_contract = contract_row

    # Determine proxy state: prefer artifact (accurate pre-reset snapshot)
    src_is_proxy = cached_proxy_state["is_proxy"] if cached_proxy_state else src_contract.is_proxy
    src_proxy_type = cached_proxy_state.get("proxy_type") if cached_proxy_state else src_contract.proxy_type
    src_implementation = cached_proxy_state.get("implementation") if cached_proxy_state else src_contract.implementation

    # Non-proxy source: non-proxies don't become proxies.
    if not src_is_proxy:
        return _apply_proxy_cache(session, src_contract, contract_row, proxy_state=cached_proxy_state)

    proxy_type = src_proxy_type

    # Diamond proxies have multiple facets — can't verify with a single call.
    if proxy_type in _MULTI_FACET_PROXY_TYPES:
        return None

    # Immutable proxy types (e.g. EIP-1167): impl is baked into bytecode.
    if proxy_type in _IMMUTABLE_PROXY_TYPES:
        return _apply_proxy_cache(session, src_contract, contract_row, proxy_state=cached_proxy_state)

    cached_impl = src_implementation
    if not cached_impl:
        return None

    rpc_url = _request_rpc_url(job)
    if not rpc_url:
        return None

    # Single RPC call — resolve_current_implementation handles all proxy types
    # (slot reads, getter calls, fallback discovery).
    try:
        current_impl = resolve_current_implementation(
            contract_row.address, rpc_url, proxy_type=proxy_type, chain_id=_parent_chain_id(job)
        )
        if not current_impl:
            return None
        current_impl = normalize_hex(current_impl)
    except Exception as exc:
        logger.debug("Proxy implementation check failed for job %s: %s", job.id, exc)
        return None

    if current_impl != normalize_hex(cached_impl):
        return None  # upgraded — need full re-classification

    return _apply_proxy_cache(session, src_contract, contract_row, proxy_state=cached_proxy_state)


class StaticWorker(BaseWorker):
    stage = JobStage.static
    next_stage = JobStage.resolution

    @staticmethod
    def _load_contract_row(session, job):
        """Resolve the Contract row for ``job``, tolerating job_id rebinds.

        Two jobs targeting the same ``(address, chain)`` (e.g. USDC discovered
        concurrently across protocols) collide on ``uq_contract_address_chain``;
        ``workers/discovery.py:402`` rebinds the existing row's ``job_id`` to
        whichever job wrote it last, orphaning the earlier job. A job_id-keyed
        lookup then returns ``None`` and the worker terminates with "Contract
        row not found for this job". Match the address+chain fallback already
        used by ``services.aggregations.company_overview.prefetch_contracts``.
        """
        from sqlalchemy import func
        from sqlalchemy import select as sa_select

        row = session.execute(sa_select(Contract).where(Contract.job_id == job.id).limit(1)).scalar_one_or_none()
        if row is not None or not job.address:
            return row
        # Chain comes from the first-class ``jobs.chain_id`` column, not the
        # request JSONB: a chainless submission has ``request["chain"]=None`` but
        # a real mainnet ``chain_id``, so a request-only read would drop the
        # filter and match any chain's row at this address. Coalesce so a mainnet
        # lookup also finds legacy NULL-chain rows (invariants 1/6/12).
        chain_name = _parent_chain_name(job)
        stmt = (
            sa_select(Contract)
            .where(
                Contract.address == job.address.lower(),
                func.lower(func.coalesce(Contract.chain, "ethereum")) == chain_name,
            )
            .limit(1)
        )
        return session.execute(stmt).scalar_one_or_none()

    def process(self, session, job):
        sources = get_source_files(session, job.id)
        if not sources:
            raise RuntimeError("No source files found in DB for this job")

        # Read from contracts table instead of artifacts
        contract_row = self._load_contract_row(session, job)
        if not contract_row:
            raise RuntimeError("Contract row not found for this job")

        contract_name = contract_row.contract_name or "Contract"
        address = contract_row.address or job.address or "0x0"
        job_id_str = str(job.id)

        # Build meta dict for downstream tools that still expect it
        meta = {
            "address": address,
            "contract_name": contract_name,
            "compiler_version": contract_row.compiler_version or "",
            "language": contract_row.language or "solidity",
            "evm_version": contract_row.evm_version or "shanghai",
            "source_format": contract_row.source_format or "flat",
            "source_file_count": contract_row.source_file_count or len(sources),
            "remappings": list(contract_row.remappings or []),
            # Carried, not defaulted: the discovery fetch already answered this and
            # the column keeps all three answers (TRUE 230 / FALSE 1 / NULL 410 on the
            # 2026-07-28 corpus). ``or``-ing a default here would erase the NULL, which
            # is the state that says the fetch fact never reached this row. Consumed by
            # ``core._source_verified`` and published as
            # ``contract_summaries.source_verified``.
            "source_verified": contract_row.source_verified,
        }
        build_settings = {
            "evm_version": contract_row.evm_version or "shanghai",
            "optimization_used": contract_row.optimization or False,
            "runs": contract_row.optimization_runs or 200,
        }
        remappings = meta.get("remappings", [])

        # Attach the job's display name so downstream tools (e.g. graph builder)
        # can use it instead of the Etherscan contract name for proxy contracts.
        if job.name:
            meta["display_name"] = job.name

        request = job.request if isinstance(job.request, dict) else {}

        logger.info(
            "Static stage started for job %s address=%s contract=%s",
            job_id_str,
            address,
            contract_name,
        )

        # Attempt to reuse proxy classification from a cached source job.
        # This avoids 3-8 RPC calls when the proxy hasn't been upgraded.
        cached_proxy = _check_proxy_cache(session, job, contract_row)
        if cached_proxy is not None:
            target_classification = cached_proxy
            # Store contract_flags artifact to match what _resolve_proxy would produce
            cached_type = cached_proxy.get("type", "regular")
            flags = {
                "is_proxy": cached_type == "proxy",
                "classification_type": cached_type,
                "cached_from_job": str(request.get("cache_source_job_id", "")),
                **{f: cached_proxy.get(f) for f in _PROXY_FIELDS if f != "is_proxy"},
            }
            store_artifact(session, job.id, "contract_flags", data=flags)
            logger.info(
                "Job %s: proxy classification reused from cache (type=%s)",
                job.id,
                cached_type,
            )
        else:
            # Always attempt semantic proxy classification when RPC is available.
            # Hidden proxies often won't match cheap static classifiers, so we run
            # this unconditionally.  The result is reused by classify_contracts()
            # in the dependency phase to avoid duplicate RPC calls.
            target_classification = self._resolve_proxy(session, job, address, contract_name)

        # Check if proxy classification marked this as a proxy — if so,
        # skip Slither/analysis on the proxy source (it's just a thin wrapper).
        # Dependency discovery still runs because proxy-address deps are useful.
        session.refresh(contract_row)
        is_proxy = contract_row.is_proxy
        record_stage_metric("is_proxy", bool(is_proxy))

        # Check if the discovery worker flagged this job as using cached static
        # data.  When set, we skip the expensive Slither / contract-analysis /
        # tracking-plan phases but still run the dependency phase (resolution
        # needs it).
        has_cached_static = bool(request.get("static_cached"))

        # Create temp directory and write source files
        tmp_dir = tempfile.mkdtemp(prefix="psat_static_")
        project_dir = Path(tmp_dir)
        try:
            self._scaffold_project(project_dir, sources, meta, build_settings, remappings)

            # Phase 0: Dependency artifacts (always runs — proxy deps are useful)
            with log_timed_phase(logger, "dependency_discovery"):
                self._run_dependency_phase(session, job, project_dir, contract_name, address, target_classification)

            secondary_analysis: Any = None
            if is_proxy:
                self.update_detail(session, job, "Proxy detected — impl job handles analysis")
                logger.info(
                    "Static stage skipping analysis for proxy job %s (%s) — impl child job will analyze",
                    job_id_str,
                    contract_name,
                )
                # Proxy jobs skip resolution/policy — complete directly
                from db.queue import complete_job

                complete_job(session, job.id, f"Proxy {contract_name} — impl child job queued for full analysis")
                raise JobHandledDirectly()
            elif has_cached_static:
                # Static artifacts already present from cache — skip analysis phases.
                logger.info(
                    "Static stage cache hit for job %s (%s) — skipping Slither/analysis/tracking plan",
                    job_id_str,
                    contract_name,
                )
                self.update_detail(session, job, "Static analysis complete (cached)")
                # The cached contract_analysis still carries secondary_impl_pointers
                # (copy_static_cache copies it), so secondaries get resolved on the
                # cache path too — not only on a fresh (Slither) analysis.
                cached_analysis = get_artifact(session, job.id, "contract_analysis")
                secondary_analysis = cached_analysis if isinstance(cached_analysis, dict) else None
            else:
                # Phase 1: Contract analysis (uses Slither's Python IR — the
                # CLI subprocess that produced detector findings was removed;
                # vulnerability triage is now an out-of-band concern, not part
                # of the cascade pipeline).
                with log_timed_phase(logger, "contract_analysis"):
                    analysis_data = self._run_analysis_phase(session, job, project_dir, contract_name, address)

                if analysis_data is None:
                    raise RuntimeError(f"Contract analysis failed for {contract_name} ({address}).")

                # Phase 2: Control tracking plan
                with log_timed_phase(logger, "tracking_plan"):
                    self._run_tracking_plan_phase(session, job, analysis_data, contract_name, address)
                secondary_analysis = analysis_data if isinstance(analysis_data, dict) else None

            # 1A: queue split-proxy secondary implementations (best-effort). SINGLE
            # call site reached by BOTH the fresh-analysis and cache-hit paths, so
            # an impl re-seen in proxy context never silently skips secondary-impl
            # linkage just because its static artifacts were cached.
            if secondary_analysis is not None:
                self._resolve_secondary_impls(session, job, address, secondary_analysis)

            # Both paths above leave the same three artifacts behind (the cache
            # path copies them), so supply is published from one call site.
            self._publish_materialization(session, job, address, contract_name)

            self.update_detail(session, job, "Static analysis complete")
            logger.info("Static analysis complete for job %s (%s)", job_id_str, contract_name)

        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _resolve_proxy(self, session, job, address: str, contract_name: str) -> dict | None:
        """Use on-chain classification to detect proxy type and resolve implementation.

        If an implementation is found, creates a linked child job for it so the
        real business logic gets analyzed.

        Returns the raw ``classify_single`` result dict so callers can pass it
        to ``classify_contracts(pre_classified=...)`` and avoid duplicate RPC calls.
        Returns ``None`` when classification was skipped or failed.
        """
        from services.discovery.classifier import ClassificationIncompleteError, classify_single

        request = job.request if isinstance(job.request, dict) else {}
        rpc_url = _request_rpc_url(job)
        if not rpc_url:
            logger.info("Job %s: no RPC available for proxy classification", job.id)
            store_artifact(
                session,
                job.id,
                "contract_flags",
                data={"is_proxy": False, "classification_type": "unknown", "classification_skipped": "no_rpc"},
            )
            return None

        try:
            classification = classify_single(address, rpc_url, chain_id=_parent_chain_id(job))
        except ClassificationIncompleteError as exc:
            # #121: the proxy-detection slots could not be read (transient RPC).
            # Storing is_proxy=False here and analyzing the address as-is would
            # silently erase a real implementation's access-control surface.
            # Record the degradation and re-raise so the static stage fails
            # closed into the worker retry path (registered transient) rather
            # than completing a confident clean model of a proxy shell.
            from utils.secrets import sanitize_string

            record_degraded(
                phase="proxy_classification",
                exc=exc,
                context={"address": address},
            )
            logger.warning(
                "Job %s: proxy classification incomplete (proxy-slot read failed); retrying: %s",
                job.id,
                sanitize_string(str(exc)),
            )
            raise
        except Exception as exc:
            from utils.secrets import sanitize_string

            record_degraded(
                phase="proxy_classification",
                exc=exc,
                context={"address": address},
            )
            logger.warning("Job %s: proxy classification failed: %s", job.id, sanitize_string(str(exc)))
            store_artifact(
                session,
                job.id,
                "contract_flags",
                data={
                    "is_proxy": False,
                    "classification_type": "unknown",
                    "classification_error": sanitize_string(str(exc)),
                },
            )
            return None

        classification_type = classification.get("type", "regular")
        # An UpgradeableBeacon is analysed as itself (is_proxy stays False so the
        # static worker runs Slither/tracking and discovers its owner()) yet still
        # spawns its implementation as a beacon-context child, so each governed
        # instance resolves against the beacon. Every other non-proxy type returns.
        is_beacon = classification_type == "beacon"
        if classification_type != "proxy" and not is_beacon:
            store_artifact(
                session,
                job.id,
                "contract_flags",
                data={"is_proxy": False, "classification_type": classification_type},
            )
            logger.info(
                "Job %s: semantic proxy classification result=%s for %s",
                job.id,
                classification_type,
                contract_name,
            )
            return classification

        proxy_type = "beacon" if is_beacon else classification.get("proxy_type", "unknown")
        impl_address = classification.get("implementation")
        # A beacon governs instances FROM the beacon address itself.
        beacon = address if is_beacon else classification.get("beacon")
        admin = classification.get("admin")
        facets = classification.get("facets")

        # Update contracts table with proxy info
        from sqlalchemy import func
        from sqlalchemy import select as sa_select

        contract_row = session.execute(
            sa_select(Contract).where(Contract.job_id == job.id).limit(1)
        ).scalar_one_or_none()
        if contract_row:
            contract_row.is_proxy = not is_beacon
            contract_row.proxy_type = proxy_type
            contract_row.implementation = impl_address
            contract_row.beacon = beacon
            contract_row.admin = admin
            session.commit()

            # Proxy-of-HIGH-impl runtime adoption — counterpart to the
            # migration's fourth branch, fired at the moment we learn
            # the proxy's impl. Closes the gap where a proxy is
            # cascade-discovered without HIGH evidence on the proxy
            # itself, but its impl IS HIGH-owned (e.g. ether.fi's
            # ``LRTSquaredCore`` impl pointed at by ``0x8f08…``). Safety
            # filter: require the proxy to also be referenced by some
            # HIGH-owned contract of the same protocol — keeps
            # arbitrary forks / EIP-1167 clones / ERC-6551 TBAs out.
            # See services/discovery/source_confidence.py + the
            # adopt-structural-orphans migration for the data model.
            # This is a best-effort runtime fast-path; the migration
            # is the safety net for any orphan this lookup misses, so
            # transient DB errors are logged + swallowed rather than
            # failing the analysis.
            contract_proto_id = getattr(contract_row, "protocol_id", None)
            contract_addr = (getattr(contract_row, "address", None) or "").lower() or None
            if contract_proto_id is None and impl_address and contract_addr:
                from db.models import ContractDependency

                try:
                    # Impl shares the proxy's chain (the job's own chain); qualify
                    # so a same-address impl on another chain can't stand in, and
                    # coalesce so mainnet still matches legacy NULL-chain rows.
                    impl_chain_name = _parent_chain_name(job)
                    impl_row = session.execute(
                        sa_select(Contract)
                        .where(
                            Contract.address == impl_address.lower(),
                            func.lower(func.coalesce(Contract.chain, "ethereum")) == impl_chain_name,
                        )
                        .limit(1)
                    ).scalar_one_or_none()
                except Exception as exc:
                    logger.debug("Job %s: structural-adoption impl lookup failed: %s", job.id, exc)
                    impl_row = None
                if impl_row is not None and getattr(impl_row, "protocol_id", None) is not None:
                    # Parent must be HIGH-source-owned, mirroring the
                    # ``asserts_ownership`` gate. A LOW-source parent
                    # (``upgrade_history`` backfill, ``structural_adoption``)
                    # with ``protocol_id`` set must not act as evidence —
                    # that'd silently relax the runtime one-hop limit.
                    from services.discovery.source_confidence import HIGH_CONFIDENCE_SOURCES

                    try:
                        referenced_by_same_protocol = session.execute(
                            sa_select(ContractDependency.id)
                            .join(Contract, Contract.id == ContractDependency.contract_id)
                            .where(
                                ContractDependency.dependency_address == contract_addr,
                                Contract.protocol_id == impl_row.protocol_id,
                                Contract.discovery_sources.overlap(list(HIGH_CONFIDENCE_SOURCES)),
                            )
                            .limit(1)
                        ).scalar_one_or_none()
                    except Exception as exc:
                        logger.debug(
                            "Job %s: structural-adoption dep-reference lookup failed: %s",
                            job.id,
                            exc,
                        )
                        referenced_by_same_protocol = None
                    if referenced_by_same_protocol is not None:
                        contract_row.protocol_id = impl_row.protocol_id
                        merged_sources = list(getattr(contract_row, "discovery_sources", None) or [])
                        if "structural_adoption" not in merged_sources:
                            merged_sources.append("structural_adoption")
                        contract_row.discovery_sources = merged_sources
                        session.commit()
                        logger.info(
                            "Job %s: structurally adopted proxy %s into protocol %s "
                            "(impl %s is HIGH-owned, proxy referenced by same protocol)",
                            job.id,
                            contract_addr,
                            impl_row.protocol_id,
                            impl_address,
                        )

        store_artifact(
            session,
            job.id,
            "contract_flags",
            data={
                "is_proxy": not is_beacon,
                "classification_type": classification_type,
                "proxy_type": proxy_type,
                "implementation": impl_address,
                "beacon": beacon,
                "admin": admin,
                "facets": facets,
            },
        )

        logger.info(
            "Job %s: %s classified as %s, implementation=%s",
            job.id,
            "beacon" if is_beacon else "proxy",
            proxy_type,
            impl_address or "unknown",
        )

        # Queue implementation addresses for analysis
        impl_entries: list[tuple[str, str]] = []  # (address, label)
        if impl_address:
            impl_entries.append((impl_address, "impl"))
        if facets:
            for i, facet in enumerate(facets):
                if facet != impl_address:  # avoid duplicates
                    impl_entries.append((facet, f"facet {i + 1}"))

        base_name = job.name or contract_name
        force = bool(request.get("force"))
        # Within-cascade dedupe under --force: same impl reached via multiple proxy paths must not spawn N copies.
        root_job_id = request.get("root_job_id") or str(job.id)
        # Coalesce a chainless request via the job's first-class chain (same
        # derivation as the child stamp below): reconcile_impl_job_for_proxy
        # disables its chain filter for chain=None, and impl singletons share
        # addresses across chains (CREATE2), so an unfiltered lookup could
        # adopt or backpatch another chain's impl job.
        chain = request.get("chain") or _parent_chain_name(job)
        from sqlalchemy import text as _sa_text

        for impl_addr, label in impl_entries:
            if force:
                # Advisory xact lock serializes the reconcile-then-INSERT against concurrent static workers.
                lock_seed = f"impl-dedupe:{root_job_id}:{chain or '-'}:{impl_addr.lower()}"
                lock_key = int(hashlib.sha1(lock_seed.encode()).hexdigest()[:15], 16)
                session.execute(_sa_text("SELECT pg_advisory_xact_lock(:k)"), {"k": lock_key})

            # Proxy-aware dedupe. A standalone (no-proxy) job for this impl is the
            # discovery-ordering race — convert it to proxy context so it stops
            # resolving against its own empty storage, rather than skipping it. A
            # same-proxy job is a true duplicate; a different-proxy job means a
            # shared impl (N proxies → 1 impl), which spawns its own per-deployment
            # job keyed by deployment_address.
            decision = reconcile_impl_job_for_proxy(
                session,
                impl_addr=impl_addr,
                proxy_addr=address,
                proxy_type=proxy_type,
                chain=chain,
                root_job_id=root_job_id if force else None,
            )
            if decision in ("skip", "backpatched"):
                _redirect_proxy_policy_dependencies(
                    session,
                    chain=chain,
                    proxy_addr=address,
                    impl_addr=impl_addr,
                )
                logger.info(
                    "Job %s: %s %s -> %s (proxy %s)",
                    job.id,
                    label,
                    impl_addr,
                    decision,
                    address,
                )
                continue

            impl_name = f"{base_name}: ({label})"
            # Structural propagation: the impl IS a same-protocol
            # component of the parent proxy. When the parent itself has
            # direct-evidence ownership, the child inherits via the
            # ``parent_relationship='implementation'`` branch in
            # ``asserts_ownership`` rather than needing its own HIGH
            # source. See services/discovery/source_confidence.py.
            from services.discovery.source_confidence import asserts_ownership

            parent_owns_high = asserts_ownership(
                list(contract_row.discovery_sources) if contract_row and contract_row.discovery_sources else None
            )
            child_request = {
                "address": impl_addr,
                "name": impl_name,
                "rpc_url": rpc_url,
                "parent_job_id": str(job.id),
                "root_job_id": root_job_id,
                "proxy_address": address,
                "proxy_type": proxy_type,
                "discovery_relationship": "implementation",
                "parent_owns_high": parent_owns_high,
            }
            # Always stamp the child's chain from the parent (inv. 6): a None here
            # used to cascade and let the impl child derive its own default chain,
            # divorcing it from the proxy's chain. Mainnet parents carry
            # chain="ethereum", so this is unchanged there.
            impl_chain = request.get("chain") or _parent_chain_name(job)
            child_request["chain"] = impl_chain
            # Defense in depth (inv. 14): the impl shares the proxy's chain, so a
            # gated parent implies a gated impl — but a disabled chain must spawn
            # no analysis work, so the gate is asserted here too.
            if not chain_enabled(impl_chain):
                logger.info(
                    "Skipping implementation child: chain not enabled for this deployment",
                    extra={
                        "address": impl_addr,
                        "chain": impl_chain,
                        "reason": "chain_not_enabled",
                        "site": "static_impl",
                    },
                )
                continue
            if getattr(job, "protocol_id", None):
                child_request["protocol_id"] = job.protocol_id
            if force:
                child_request["force"] = True
            child_job = create_job(session, child_request)
            _redirect_proxy_policy_dependencies(
                session,
                chain=chain,
                proxy_addr=address,
                impl_addr=impl_addr,
            )
            logger.info(
                "Job %s: created %s job %s for %s (%s)",
                job.id,
                label,
                child_job.id,
                impl_addr,
                impl_name,
            )

        return classification

    def _resolve_secondary_impls(self, session, job, address: str, analysis_data) -> None:
        """1A: detect + queue split-proxy secondary implementations.

        When an impl analysed in proxy context (``request.proxy_address`` set)
        has a fallback/receive that delegatecalls a state-var address, resolve
        that secondary logic contract against the PROXY's storage and analyse it
        the same way (a proxy-child job) so its admin functions resolve to the
        proxy's controller instead of stranding on an ownerless orphan node.
        Best-effort — never fails the parent analysis.
        """
        request = job.request if isinstance(job.request, dict) else {}
        proxy_address = request.get("proxy_address")
        if not (isinstance(proxy_address, str) and proxy_address.startswith("0x") and len(proxy_address) == 42):
            return
        # One level only: a secondary impl doesn't itself spawn secondaries.
        if request.get("discovery_relationship") == "secondary_implementation":
            return
        pointers = (analysis_data or {}).get("secondary_impl_pointers") or []
        if not pointers:
            return
        rpc_url = _request_rpc_url(job)
        if not rpc_url:
            return
        try:
            from sqlalchemy import func
            from sqlalchemy import select as sa_select

            from services.discovery.secondary_impl import (
                queue_secondary_impl_jobs,
                resolve_secondary_impl_addresses,
            )

            # Chain from the first-class ``jobs.chain_id`` column, coalesced so a
            # mainnet lookup finds legacy NULL-chain rows while an L2 lookup stays
            # isolated (invariants 1/6/12).
            proxy_chain_name = _parent_chain_name(job)
            proxy_stmt = (
                sa_select(Contract)
                .where(
                    Contract.address == proxy_address.lower(),
                    func.lower(func.coalesce(Contract.chain, "ethereum")) == proxy_chain_name,
                )
                .limit(1)
            )
            proxy_contract = session.execute(proxy_stmt).scalar_one_or_none()
            if proxy_contract is None:
                logger.warning("Job %s: secondary-impl proxy row %s not found; skipping", job.id, proxy_address)
                return
            secondary_addrs = resolve_secondary_impl_addresses(
                rpc_url,
                proxy_address,
                pointers,
                implementation=proxy_contract.implementation,
                chain_id=_parent_chain_id(job),
            )
            if not secondary_addrs:
                return
            created = queue_secondary_impl_jobs(
                session,
                proxy_contract=proxy_contract,
                secondary_addrs=secondary_addrs,
                parent_job=job,
                rpc_url=rpc_url,
                proxy_type=request.get("proxy_type") or proxy_contract.proxy_type,
                root_job_id=request.get("root_job_id") or str(job.id),
                chain=proxy_chain_name,
                protocol_id=getattr(job, "protocol_id", None),
                force=bool(request.get("force")),
                base_name=job.name or proxy_contract.contract_name or "Contract",
            )
            logger.info(
                "Job %s: split-proxy secondary impls for proxy %s -> %s (%d job(s) queued)",
                job.id,
                proxy_address,
                secondary_addrs,
                len(created),
            )
        except Exception as exc:
            from utils.secrets import sanitize_string

            record_degraded(phase="secondary_impl_resolution", exc=exc, context={"address": address})
            logger.warning("Job %s: secondary-impl resolution failed: %s", job.id, sanitize_string(str(exc)))

    def _scaffold_project(
        self,
        project_dir: Path,
        sources: dict[str, str],
        meta: dict,
        build_settings: dict,
        remappings: list[str],
    ) -> None:
        """Write source files, foundry.toml, remappings to the temp project."""
        sources = _relax_pragmas(sources)
        for filepath, content in sources.items():
            full_path = _confine(project_dir, filepath)
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content)

        solc_version = _detect_solc_version(sources)
        src_dir = _detect_src_dir(sources)
        evm_version = sanitize_evm_version(build_settings.get("evm_version", "shanghai"))
        optimizer = str(bool(build_settings.get("optimization_used", True))).lower()
        optimizer_runs = int(build_settings.get("runs", 200) or 200)

        (project_dir / "foundry.toml").write_text(
            textwrap.dedent(
                f"""\
                [profile.default]
                src = "{src_dir}"
                out = "out"
                libs = ["lib"]
                solc_version = "{solc_version}"
                evm_version = "{evm_version}"
                optimizer = {optimizer}
                optimizer_runs = {optimizer_runs}
                auto_detect_solc = false
            """
            )
        )

        # Prune remappings to only those whose target dirs have actual source files
        pruned = _prune_remappings(remappings, set(sources.keys()))
        if pruned:
            (project_dir / "remappings.txt").write_text("\n".join(pruned) + "\n")

        (project_dir / "contract_meta.json").write_text(json.dumps(meta, indent=2) + "\n")

    def _run_dependency_phase(
        self,
        session,
        job,
        project_dir: Path,
        contract_name: str,
        address: str,
        target_classification: dict | None = None,
    ) -> None:
        """Build dependency artifacts before compile-dependent analysis starts."""
        self.update_detail(session, job, "Discovering dependencies")

        request = job.request if isinstance(job.request, dict) else {}
        deps_rpc = _request_rpc_url(job)
        # Chain from the first-class ``jobs.chain_id`` column (via
        # ``_parent_chain_name``), not a mainnet default: the dynamic-dependency
        # txlist and the upgrade-history getLogs both hit Etherscan and must
        # query the proxy's own chain, or an L2 proxy's timeline/deps come back
        # silently empty from mainnet (F1/F2).
        phase_chain_id = require_chain(chain=_parent_chain_name(job), context="dependency phase").chain_id
        dynamic_rpc_raw = request.get("dynamic_rpc")
        dynamic_rpc = dynamic_rpc_raw if isinstance(dynamic_rpc_raw, str) and dynamic_rpc_raw.strip() else deps_rpc
        dynamic_tx_limit = request.get("dynamic_tx_limit", 10)
        dynamic_tx_hashes = request.get("dynamic_tx_hashes")

        logger.info(
            "Static stage dependency discovery started for job %s address=%s contract=%s",
            job.id,
            address,
            contract_name,
        )

        # ---- Sequential setup: read every cached artifact + compute incremental anchors. ----
        _raw_static_deps = get_artifact(session, job.id, "static_dependencies")
        cached_static_deps = _raw_static_deps if isinstance(_raw_static_deps, dict) else None

        tx_hashes = dynamic_tx_hashes if isinstance(dynamic_tx_hashes, list) else None
        prev_dyn = _load_prev_dynamic_deps(session, job, tx_hashes)
        dyn_start_block = _start_block_from_prev_dyn(prev_dyn)

        prev_uh_raw = get_artifact(session, job.id, "upgrade_history")
        prev_uh = prev_uh_raw if isinstance(prev_uh_raw, dict) else None
        uh_from_block = _from_block_for_upgrade_history(prev_uh)

        # ---- Parallel section: 3 RPC/Etherscan-bound sub-phases. ----
        # Each sub-phase gets its own ``code_cache`` dict; the global locked
        # ``_GETCODE_CACHE`` in services.clients.rpc dedups across them so the only cost
        # is independent dict lookups per thread.
        proxy_addr = request.get("proxy_address")

        def run_static() -> dict:
            if cached_static_deps is not None:
                return cached_static_deps
            return find_dependencies(address, deps_rpc, code_cache={}, chain_id=_parent_chain_id(job))

        def run_dynamic() -> dict:
            return find_dynamic_dependencies(
                address,
                rpc_url=dynamic_rpc,
                tx_limit=int(dynamic_tx_limit),
                tx_hashes=tx_hashes,
                proxy_address=proxy_addr,
                code_cache={},
                start_block=dyn_start_block,
                chain_id=phase_chain_id,
            )

        def run_upgrade_history() -> dict | None:
            from services.discovery.upgrade_history import build_upgrade_history

            # Always call ``build_upgrade_history``: when the target isn't a proxy
            # it returns an empty proxies dict cheaply and the test harness still
            # observes the call. Real Etherscan fetches only happen when
            # ``proxy_meta`` is non-empty inside the helper.
            minimal_deps = {
                "address": address,
                "target_classification": target_classification or {},
                "dependencies": {},
            }
            # Rebuilt as a plain dict: the worker merges prior history into it.
            return dict(build_upgrade_history(minimal_deps, from_block=uh_from_block, chain_id=phase_chain_id))

        from services.concurrency import parallel_map

        def _hb() -> None:
            self._heartbeat(session, job)

        sub_phases = [("static", run_static), ("dynamic", run_dynamic), ("upgrade_history", run_upgrade_history)]
        with log_timed_phase(logger, "dependency_parallel"):
            results = parallel_map(lambda task: task[1](), sub_phases, max_workers=3, heartbeat=_hb)

        outcomes: dict[str, object | BaseException] = {
            name: outcome for (name, _fn), (_task, outcome) in zip(sub_phases, results)
        }

        # ---- Static dependencies: persist + branch on success. ----
        deps_output: dict | None = None
        static_outcome = outcomes["static"]
        if isinstance(static_outcome, BaseException):
            record_degraded(
                phase="dependency_static",
                exc=static_outcome,
                context={"address": address},
            )
            logger.warning(
                "Static stage static dependency discovery failed for job %s address=%s: %s",
                job.id,
                address,
                static_outcome,
            )
        else:
            deps_output = static_outcome  # pyright: ignore[reportAssignmentType]
            if cached_static_deps is None and isinstance(deps_output, dict):
                store_artifact(session, job.id, "static_dependencies", data=deps_output)
            static_dep_count = len(deps_output.get("dependencies", [])) if isinstance(deps_output, dict) else 0
            record_stage_metric("static_dependencies", static_dep_count)
            logger.info(
                "Static stage static dependencies %s for job %s address=%s count=%d",
                "loaded from cache" if cached_static_deps is not None else "complete",
                job.id,
                address,
                static_dep_count,
            )

        # ---- Dynamic dependencies: merge with prev, persist. ----
        dyn_output: dict | None = None
        dyn_outcome = outcomes["dynamic"]
        if isinstance(dyn_outcome, NoNewTransactionsError):
            if prev_dyn:
                dyn_output = prev_dyn
                store_artifact(session, job.id, "dynamic_dependencies", data=prev_dyn)
            else:
                record_degraded(
                    phase="dependency_dynamic",
                    exc=dyn_outcome,
                    context={"address": address, "reason": "no_representative_transactions"},
                )
        elif isinstance(dyn_outcome, BaseException):
            record_degraded(
                phase="dependency_dynamic",
                exc=dyn_outcome,
                context={"address": address},
            )
            logger.warning(
                "Static stage dynamic dependency discovery failed for job %s address=%s: %s",
                job.id,
                address,
                dyn_outcome,
            )
        else:
            dyn_output = dyn_outcome  # pyright: ignore[reportAssignmentType]
            if prev_dyn and not tx_hashes and isinstance(dyn_output, dict):
                dyn_output = _merge_dynamic_deps(prev_dyn, dyn_output)
            if isinstance(dyn_output, dict):
                store_artifact(session, job.id, "dynamic_dependencies", data=dyn_output)
                record_stage_metric("dynamic_dependencies", len(dyn_output.get("dependencies", [])))
                logger.info(
                    "Static stage dynamic dependencies complete for job %s address=%s count=%d",
                    job.id,
                    address,
                    len(dyn_output.get("dependencies", [])),
                )

        # ---- Upgrade history: merge + persist (handled below alongside the cleaner pre-classify path). ----
        uh_outcome_raw = outcomes["upgrade_history"]
        uh_pre: dict | None
        if isinstance(uh_outcome_raw, BaseException):
            record_degraded(
                phase="dependency_upgrade_history",
                exc=uh_outcome_raw,
                context={"address": address, "subphase": "parallel"},
            )
            logger.warning(
                "Static stage upgrade history failed for job %s address=%s: %s",
                job.id,
                address,
                uh_outcome_raw,
            )
            uh_pre = None
        elif isinstance(uh_outcome_raw, dict):
            uh_pre = uh_outcome_raw
        else:
            uh_pre = None

        # Mirror the resolution order inside find_dependencies /
        # find_dynamic_dependencies so classification hits the same
        # endpoint discovery actually used.
        resolved_rpc = deps_rpc or dynamic_rpc

        cls_output = None
        if resolved_rpc:
            unique_deps = sorted(
                set((deps_output or {}).get("dependencies", []) + (dyn_output or {}).get("dependencies", []))
            )
            record_stage_metric("dependencies", len(unique_deps))
            try:
                from services.discovery.static_dependencies import normalize_address

                pre_classified = {}
                if target_classification:
                    pre_classified[normalize_address(address)] = target_classification

                # Load previous classifications to skip already-classified addresses.
                # Validate cached proxy classifications against live on-chain
                # state so upgraded dependencies get re-classified.
                prev_cls = get_artifact(session, job.id, "classifications")
                if isinstance(prev_cls, dict):
                    validated_cls = _validate_cached_dep_classifications(
                        prev_cls, resolved_rpc, chain_id=_parent_chain_id(job)
                    )
                    for cls_addr, cls_info in validated_cls.items():
                        if cls_addr not in pre_classified:
                            pre_classified[cls_addr] = cls_info

                with log_timed_phase(logger, "classification", dep_count=len(unique_deps)) as ph:
                    cls_output = classify_contracts(
                        address,
                        unique_deps,
                        resolved_rpc,
                        dynamic_edges=(dyn_output or {}).get("dependency_graph"),
                        code_cache=None,
                        chain_id=_parent_chain_id(job),
                        pre_classified=pre_classified or None,
                    )
                    # Store classifications artifact for future cache hits
                    store_artifact(session, job.id, "classifications", data=cls_output)
                    discovered_count = len(cls_output.get("discovered_addresses", []))
                    record_stage_metric("discovered_addresses", discovered_count)
                    ph["discovered"] = discovered_count
                logger.info(
                    "Static stage dependency classification complete for job %s address=%s discovered=%d",
                    job.id,
                    address,
                    discovered_count,
                )
            except Exception as exc:
                record_degraded(
                    phase="dependency_classification",
                    exc=exc,
                    context={"address": address},
                )
                logger.warning(
                    "Static stage dependency classification failed for job %s address=%s: %s",
                    job.id,
                    address,
                    exc,
                )
        else:
            logger.info(
                "Static stage dependency classification skipped for job %s address=%s (no resolved RPC)",
                job.id,
                address,
            )

        if deps_output or dyn_output:
            unified = build_unified_dependencies(
                address, deps_output, dyn_output, cls_output, target_classification=target_classification
            )
            # Load cached enrichment data (contract names + selectors are immutable)
            prev_enrichment = get_artifact(session, job.id, "enrichment_cache")
            info_cache: dict[str, tuple[str | None, dict[str, str]]] = {}
            if isinstance(prev_enrichment, dict):
                for _addr, _data in prev_enrichment.items():
                    if isinstance(_data, dict):
                        info_cache[_addr] = (_data.get("name"), _data.get("selectors", {}))

            with log_timed_phase(logger, "enrichment"):
                enrich_dependency_metadata(
                    unified,
                    info_cache=info_cache,
                    chain_id=require_chain(chain=_parent_chain_name(job), context="dependency enrichment").chain_id,
                )

            # Store updated enrichment cache (includes any newly fetched entries)
            enrichment_data = {
                addr: {"name": name, "selectors": selectors} for addr, (name, selectors) in info_cache.items()
            }
            store_artifact(session, job.id, "enrichment_cache", data=enrichment_data)

            # Write to contract_dependencies table
            from sqlalchemy import select as sa_select

            contract_row = session.execute(
                sa_select(Contract).where(Contract.job_id == job.id).limit(1)
            ).scalar_one_or_none()
            if contract_row:
                from db.models import ContractDependency

                session.query(ContractDependency).filter(ContractDependency.contract_id == contract_row.id).delete()
                for dep_addr, dep_info in unified.get("dependencies", {}).items():
                    if not isinstance(dep_info, dict):
                        continue
                    impl = dep_info.get("implementation")
                    if isinstance(impl, dict):
                        impl_addr = impl.get("address")
                    elif isinstance(impl, str):
                        impl_addr = impl
                    else:
                        impl_addr = None
                    session.add(
                        ContractDependency(
                            contract_id=contract_row.id,
                            dependency_address=dep_addr.lower(),
                            dependency_name=dep_info.get("contract_name"),
                            relationship_type=dep_info.get("type", "regular"),
                            source=dep_info.get("source"),
                            proxy_type=dep_info.get("proxy_type"),
                            implementation=impl_addr,
                            admin=dep_info.get("admin"),
                        )
                    )
                session.commit()

            store_artifact(session, job.id, "dependencies", data=unified)

            proxy_addr = request.get("proxy_address")
            proxy_name = (job.name or "").split(":")[0].strip() if proxy_addr else None
            proxy_type = request.get("proxy_type") if proxy_addr else None
            target_label = _contract_label_from_meta(project_dir)
            dependency_graph = build_dependency_visualization(
                unified,
                target_label=target_label,
                proxy_address=proxy_addr,
                proxy_name=proxy_name,
                proxy_type=proxy_type,
            )
            if dependency_graph.get("nodes"):
                store_artifact(session, job.id, "dependency_graph_viz", data=dependency_graph)
                logger.info(
                    "Static stage dependency graph complete for job %s address=%s nodes=%d edges=%d",
                    job.id,
                    address,
                    len(dependency_graph.get("nodes", [])),
                    len(dependency_graph.get("edges", [])),
                )
            else:
                logger.info(
                    "Static stage dependencies complete for job %s address=%s (no graph nodes)",
                    job.id,
                    address,
                )

            # Upgrade history was computed in the parallel section above using
            # ``target_classification`` only. Apply known names from the unified
            # deps so we can drop redundant Etherscan name lookups, then merge
            # with any prior cached upgrade history and persist.
            try:
                uh = _finalize_upgrade_history(
                    session,
                    job,
                    address,
                    uh_pre,
                    prev_uh,
                    unified,
                    contract_row=contract_row,
                )
                if uh:
                    logger.info(
                        "Static stage upgrade history complete for job %s address=%s upgrades=%d",
                        job.id,
                        address,
                        uh.get("total_upgrades", 0),
                    )
            except Exception as exc:
                record_degraded(
                    phase="dependency_upgrade_history",
                    exc=exc,
                    context={"address": address, "subphase": "finalize"},
                )
                logger.warning(
                    "Static stage upgrade history failed for job %s address=%s: %s",
                    job.id,
                    address,
                    exc,
                )
        else:
            logger.warning(
                "Static stage dependency artifacts skipped for job %s address=%s (no dependency outputs)",
                job.id,
                address,
            )

    def _run_analysis_phase(
        self, session, job, project_dir: Path, contract_name: str, address: str
    ) -> ContractAnalysis | None:
        """Run structured contract analysis. Returns the analysis dict or None on failure."""
        self.update_detail(session, job, "Building structured contract analysis")
        try:
            analysis_data, semantic_predicate_trees, semantic_effects = collect_contract_analysis_with_artifacts(
                project_dir
            )
        except Exception as exc:
            record_degraded(
                phase="contract_analysis",
                exc=exc,
                context={"address": address, "contract_name": contract_name},
            )
            _log_phase_error(str(job.id), address, contract_name, "contract_analysis", str(exc))
            store_artifact(session, job.id, "analysis_error", data={"error": str(exc)})
            return None

        # ``predicate_trees`` and ``effects`` are the semantic artifacts
        # consumed by policy resolution. ``default=str`` is defence in depth:
        # a stray non-JSON analyzer object (a Slither ``Constant`` reached
        # ``derived_from.callee`` before provenance stringified it) must
        # degrade to its string form rather than kill the whole static job.
        (project_dir / "contract_analysis.json").write_text(json.dumps(analysis_data, indent=2, default=str) + "\n")
        if semantic_predicate_trees is not None:
            (project_dir / "predicate_trees.json").write_text(
                json.dumps(semantic_predicate_trees, indent=2, default=str) + "\n"
            )
        if semantic_effects is not None:
            (project_dir / "effects.json").write_text(json.dumps(semantic_effects, indent=2, default=str) + "\n")

        store_artifact(session, job.id, "contract_analysis", data=analysis_data)
        if semantic_predicate_trees is not None:
            try:
                store_artifact(session, job.id, "predicate_trees", data=semantic_predicate_trees)
            except Exception as exc:
                record_degraded(
                    phase="predicate_trees_artifact_store",
                    exc=exc,
                    context={"address": address, "contract_name": contract_name, "job_id": str(job.id)},
                )
                logger.exception(
                    "Static stage: predicate_trees artifact store failed for job %s",
                    job.id,
                )
        if semantic_effects is not None:
            try:
                store_artifact(session, job.id, "effects", data=semantic_effects)
            except Exception as exc:
                record_degraded(
                    phase="effects_artifact_store",
                    exc=exc,
                    context={"address": address, "contract_name": contract_name, "job_id": str(job.id)},
                )
                logger.exception(
                    "Static stage: effects artifact store failed for job %s",
                    job.id,
                )
        self._write_analysis_tables(session, job, analysis_data)
        logger.info(
            "Static stage contract analysis complete for job %s address=%s contract=%s",
            job.id,
            address,
            contract_name,
        )
        return analysis_data

    def _write_analysis_tables(self, session, job: Job, analysis: ContractAnalysis | dict) -> None:
        """Extract structured data from contract_analysis JSON into relational tables."""
        from sqlalchemy import select as sa_select

        contract_row = session.execute(
            sa_select(Contract).where(Contract.job_id == job.id).limit(1)
        ).scalar_one_or_none()
        if not contract_row:
            return

        summary = analysis.get("summary", {})
        subject = analysis.get("subject", {})

        # Update contract name from analysis if available
        if subject.get("name"):
            contract_row.contract_name = subject["name"]

        # Write contract_summary
        existing_summary = session.execute(
            sa_select(ContractSummary).where(ContractSummary.contract_id == contract_row.id)
        ).scalar_one_or_none()
        if existing_summary:
            session.delete(existing_summary)
            session.flush()

        session.add(
            ContractSummary(
                contract_id=contract_row.id,
                control_model=summary.get("control_model"),
                is_upgradeable=summary.get("is_upgradeable"),
                is_pausable=summary.get("is_pausable"),
                has_timelock=summary.get("has_timelock"),
                is_factory=summary.get("is_factory"),
                is_nft=summary.get("is_nft"),
                standards=summary.get("standards", []),
                source_verified=subject.get("source_verified"),
            )
        )

        semantic_section = analysis.get("semantic_control", {})

        # Write role_definitions
        session.query(RoleDefinition).filter(RoleDefinition.contract_id == contract_row.id).delete()
        for rd in semantic_section.get("role_definitions", []):
            session.add(
                RoleDefinition(
                    contract_id=contract_row.id,
                    role_name=rd.get("role", ""),
                    declared_in=rd.get("declared_in"),
                )
            )

        session.commit()

    def _publish_materialization(self, session, job: Job, address: str, contract_name: str) -> None:
        """Record this job's analysis bundle in ``contract_materializations`` (F4a).

        Until now the versioned store had exactly one writer: the authority
        recursion, which materializes whichever dependencies it happens to
        visit. Monitoring enrolls from that store, so whether a contract was
        watched on its real tracking plan or on the baseline registry alone was
        decided by an accident of graph traversal (136 of 183 monitored
        contracts read ``no_current_materialization`` while their own jobs held
        a substantive plan). Publishing here makes coverage follow from analysis
        having run — invariant 8.

        Reads back the three artifacts this stage just stored rather than taking
        them as arguments: the artifacts are what the job actually left behind,
        they are identical on the fresh and the static-cache paths, and a bundle
        that failed to store is one this row must not claim to hold.

        A row is stamped ``ANALYSIS_SCHEMA_VERSION``, so it may only be written
        for a bundle PROVEN to be of that era. The stamp lives on the job, but
        only the fetch path writes it — a same-address cache hit copies the
        donor's artifacts and returns before it, leaving NULL. NULL is not
        "current", so ``proven_analysis_schema_version`` follows the cache chain
        to the era that was actually witnessed, and a job whose era stays
        undetermined publishes nothing. Same rule the promotion sweep applies to
        the same fact.

        Best-effort in every arm. Supply is not the analysis: a bucket outage, a
        keccak we cannot read, or a row another writer holds must never fail a
        job whose analysis succeeded. Each refusal is logged with its reason.
        """
        from db.contract_materializations import (
            ANALYSIS_SCHEMA_VERSION,
            PRODUCED_BY_PIPELINE,
            PUBLISH_ALREADY_CURRENT,
            PUBLISH_REFRESHED,
            PUBLISH_WRITTEN,
            build_provenance,
            is_enabled,
            publish_materialization,
        )
        from db.queue import proven_analysis_schema_version

        if not is_enabled():
            return

        era = proven_analysis_schema_version(session, job)
        if era != ANALYSIS_SCHEMA_VERSION:
            record_degraded(
                phase="materialization_publish",
                exc=RuntimeError(f"analyzer era not proven current (job era={era})"),
                context={"address": address, "job_era": era},
            )
            logger.warning(
                "Static stage: no materialization published for %s — analyzer era not proven current (job era=%s)",
                address,
                era,
                extra={"address": address, "job_era": era, "outcome": "schema_version_not_proven"},
            )
            return

        try:
            analysis = get_artifact(session, job.id, "contract_analysis")
            tracking_plan = get_artifact(session, job.id, "control_tracking_plan")
            predicate_trees = get_artifact(session, job.id, "predicate_trees")
        except Exception as exc:
            record_degraded(phase="materialization_publish", exc=exc, context={"address": address})
            logger.warning(
                "Static stage: materialization publish skipped for %s — artifacts unreadable: %s",
                address,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
            return
        if not isinstance(analysis, dict) or not isinstance(tracking_plan, dict):
            # The plan phase records its own failure; a row without both halves
            # would read downstream as a contract with no analysis and no plan.
            logger.info(
                "Static stage: no materialization published for %s — analysis or tracking plan absent",
                address,
            )
            return

        chain = _parent_chain_name(job)
        request = job.request if isinstance(job.request, dict) else {}
        # Did THIS job's analysis produce these artifacts, or did it copy an
        # ancestor's? The era gate above proves they are of the current era; it
        # says nothing about which of two same-era bundles is the later record.
        produced_here = not request.get("static_cached")
        try:
            from services.clients.rpc import get_code_with_keccak

            _code, keccak = get_code_with_keccak(_request_rpc_url(job) or "", address, chain_id=_parent_chain_id(job))
        except Exception as exc:
            # The row is keyed on bytecode. Without the keccak there is no key,
            # and inventing one would key the bundle to code nobody read.
            record_degraded(phase="materialization_publish", exc=exc, context={"address": address})
            logger.warning(
                "Static stage: materialization publish skipped for %s — bytecode keccak not determined: %s",
                address,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
            return

        try:
            outcome = publish_materialization(
                chain=chain,
                address=address,
                bytecode_keccak=keccak,
                contract_name=contract_name,
                analysis=analysis,
                tracking_plan=tracking_plan,
                predicate_trees=predicate_trees if isinstance(predicate_trees, dict) else None,
                source_content_hash=job.source_content_hash,
                provenance=build_provenance(PRODUCED_BY_PIPELINE, source_job_id=job.id),
                # Only a bundle THIS job produced may overwrite a current row.
                # On the static-cache path these artifacts are an ancestor's,
                # copied — same era (the gate above proves that), but not the
                # newer record: a fresh analysis and a later cache hit reproducing
                # its ancestor would then take turns overwriting each other, and
                # each flip moves where monitoring watches.
                refresh_on_differ=produced_here,
            )
        except Exception as exc:
            record_degraded(phase="materialization_publish", exc=exc, context={"address": address})
            logger.warning(
                "Static stage: materialization publish failed for %s: %s",
                address,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
            return
        if outcome in (PUBLISH_WRITTEN, PUBLISH_REFRESHED):
            log = logger.info
        elif outcome == PUBLISH_ALREADY_CURRENT:
            # The steady state on every re-run of an unchanged contract.
            log = logger.debug
        else:
            log = logger.warning
        log(
            "Static stage: materialization %s for %s (%s)",
            outcome,
            address,
            chain,
            extra={"address": address, "chain": chain, "outcome": outcome},
        )

    def _run_tracking_plan_phase(
        self, session, job, analysis: ContractAnalysis | dict, contract_name: str, address: str
    ) -> None:
        """Build control tracking plan. Non-fatal on failure."""
        self.update_detail(session, job, "Building control tracking plan")
        try:
            tracking_plan = build_control_tracking_plan(cast(ContractAnalysis, analysis))
            store_artifact(session, job.id, "control_tracking_plan", data=tracking_plan)
            logger.info(
                "Static stage tracking plan complete for job %s address=%s contract=%s",
                job.id,
                address,
                contract_name,
            )
        except Exception as exc:
            record_degraded(
                phase="tracking_plan",
                exc=exc,
                context={"address": address, "contract_name": contract_name},
            )
            _log_phase_error(str(job.id), address, contract_name, "tracking_plan", str(exc))
            store_artifact(session, job.id, "tracking_plan_error", data={"error": str(exc)})


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        force=True,
    )
    StaticWorker().run_loop()


if __name__ == "__main__":
    main()
