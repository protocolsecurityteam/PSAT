"""Static analysis worker: runs Slither and contract analysis in a temp directory."""

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


# WARNING, not ERROR: callers continue with a stub artifact (degraded, not failed). Pair each call with
# ``record_degraded``.
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
    """eRPC URL for the job's chain via ``jobs.chain_id`` (``_parent_chain_name``), not the request: a chainless
    submission has the mainnet default only in the column, so a request-only read would silently skip
    classification and deps. A local-node override in the request still wins.
    """
    request = job.request if isinstance(job.request, dict) else {}
    explicit = request.get("rpc_url")
    return default_rpc_url(
        explicit_rpc_url=explicit if isinstance(explicit, str) else None,
        chain=_parent_chain_name(job),
    )


def _parent_chain_id(job: Job) -> int:
    """The parent job's ``chain_id`` (inv.

    6): the column, else derived from ``request["chain"]``, else mainnet. Arms the inv-7 URL/chain guard.
    """
    chain_id = getattr(job, "chain_id", None)
    if isinstance(chain_id, int):
        return chain_id
    request = job.request if isinstance(job.request, dict) else {}
    return derive_job_chain_id(request.get("chain"), job.address) or 1


def _parent_chain_name(job: Job) -> str:
    """Canonical chain name of the parent, stamped on spawned impl children so chain never cascades as ``None`` (inv.

    6). Mainnet is ``"ethereum"``.
    """
    chain_id = _parent_chain_id(job)
    try:
        return chain_by_id(chain_id).name
    except UnknownChainError as exc:
        # Stamping "ethereum" for an unregistered chain is a wrong answer, so report it, once per chain per job (this
        # runs ~10 times per job). Stored on the job row, not a ContextVar, since all jobs share the worker's context.
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

    Resolution can find an authority proxy before static creates its impl child; once it exists, the edge must wait on
    the impl job, where policy artifacts are produced.
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
    """Human-readable label for the dependency graph, from ``contract_meta.json`` (else the workspace dir name);
    generic proxy names are replaced with the job's ``display_name``.
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


def _load_prev_dynamic_deps(session, job, tx_hashes: list[str] | None) -> dict | None:
    """The persisted dynamic_dependencies artifact, if any; tx-hash overrides skip it."""
    if tx_hashes:
        return None
    raw = get_artifact(session, job.id, "dynamic_dependencies")
    return raw if isinstance(raw, dict) else None


def _finalize_upgrade_history(
    session,
    job,
    address: str,
    uh_pre: dict | None,
    prev_uh: dict | None,
    unified: dict,
    contract_row: Contract | None = None,
) -> dict | None:
    """Backfill known names, merge with cached history, persist, and project to rows: ``UpgradeEvent`` rows for
    overview aggregates, and historical impl ``Contract`` rows so audit coverage can match past impls. Projection
    is best-effort; the stored artifact allows re-running.
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

    # Non-fatal: the artifact is already stored.
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
            backfill_protocol_id = contract_row.protocol_id or contract_row.nominated_protocol_id
            if backfill_protocol_id is not None and stats["impl_addrs"]:
                # Nominated, not stamped (invariant 1); membership is earned via the gate (W2).
                backfill_historical_impl_contracts(
                    session,
                    protocol_id=backfill_protocol_id,
                    chain=contract_row.chain,
                    impl_addrs=stats["impl_addrs"],
                    current_impl_address=contract_row.implementation,
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

    # A separate failure domain: the executor fold does more wire calls, and a failure there must cost only the receipt
    # facts.
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
            # Roll back so later statements don't hit PendingRollbackError.
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


# Implementation baked into bytecode; reusable without a slot check.
_IMMUTABLE_PROXY_TYPES = frozenset({"eip1167"})

# Multiple facets can't be verified with one slot check.
_MULTI_FACET_PROXY_TYPES = frozenset({"eip2535"})

_PROXY_FIELDS = _MUTABLE_CONTRACT_FIELDS


def _validate_cached_dep_classifications(
    prev_cls: dict,
    rpc_url: str,
    *,
    chain_id: int | None = None,
) -> dict[str, dict]:
    """Validate cached dependency proxy classifications against live state with one call each.

    Returns ``{address: classification}`` for entries still valid; stale ones are dropped so ``classify_contracts``
    redoes them. Non-proxies, immutable and multi-facet proxies are kept as-is.
    """
    valid: dict[str, dict] = {}

    for addr, cls_info in prev_cls.get("classifications", {}).items():
        if not isinstance(cls_info, dict):
            continue

        if cls_info.get("type") != "proxy":
            valid[addr] = cls_info
            continue

        proxy_type = cls_info.get("proxy_type")
        cached_impl = cls_info.get("implementation")

        if proxy_type in _IMMUTABLE_PROXY_TYPES:
            valid[addr] = cls_info
            continue

        if proxy_type in _MULTI_FACET_PROXY_TYPES:
            continue

        # Nothing to compare (e.g. beacon-only or partial).
        if not cached_impl:
            valid[addr] = cls_info
            continue

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
    """Copy proxy fields from *src_contract* (or *proxy_state*, which wins) to *contract_row* and return a
    ``classify_single``-style dict. *proxy_state* covers the case where ``copy_static_cache`` reset the shared
    row's proxy fields.
    """
    for field in _PROXY_FIELDS:
        if proxy_state is not None:
            setattr(contract_row, field, proxy_state.get(field))
        else:
            setattr(contract_row, field, getattr(src_contract, field))
    session.commit()

    # §3.4 event 2a fires on the cache path too: copied pointers are the same fact delta.
    from services.discovery.membership_gate import FactsDelta, evaluate_committed

    own_address = (getattr(contract_row, "address", None) or "").lower()
    edge_addrs = tuple(
        sorted(
            {
                value.lower()
                for value in (getattr(contract_row, f, None) for f in ("implementation", "beacon", "admin"))
                if isinstance(value, str) and value.startswith("0x") and value.lower() != own_address
            }
        )
    )
    row_id = getattr(contract_row, "id", None)
    evaluate_committed(
        session,
        FactsDelta(new_edge_addresses=edge_addrs, recheck_contract_ids=(row_id,) if isinstance(row_id, int) else ()),
        context="static_proxy_cache_reuse",
    )

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
    """Reuse proxy classification from a cached source job if still valid; ``None`` means run ``_resolve_proxy``."""
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

    # ``copy_static_cache`` may have reused this row and reset its proxy fields; read the saved state from the artifact.
    cached_proxy_state: dict | None = None
    if src_contract is None:
        _raw_proxy = get_artifact(session, job.id, "cached_proxy_state")
        if not isinstance(_raw_proxy, dict):
            return None
        cached_proxy_state = _raw_proxy
        src_contract = contract_row

    # Prefer the artifact's pre-reset snapshot.
    src_is_proxy = cached_proxy_state["is_proxy"] if cached_proxy_state else src_contract.is_proxy
    src_proxy_type = cached_proxy_state.get("proxy_type") if cached_proxy_state else src_contract.proxy_type
    src_implementation = cached_proxy_state.get("implementation") if cached_proxy_state else src_contract.implementation

    if not src_is_proxy:
        return _apply_proxy_cache(session, src_contract, contract_row, proxy_state=cached_proxy_state)

    proxy_type = src_proxy_type

    if proxy_type in _MULTI_FACET_PROXY_TYPES:
        return None

    if proxy_type in _IMMUTABLE_PROXY_TYPES:
        return _apply_proxy_cache(session, src_contract, contract_row, proxy_state=cached_proxy_state)

    cached_impl = src_implementation
    if not cached_impl:
        return None

    rpc_url = _request_rpc_url(job)
    if not rpc_url:
        return None

    # ``resolve_current_implementation`` handles every proxy type.
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

        Two jobs for the same ``(address, chain)`` collide on the unique key and ``workers/discovery.py`` rebinds the
        row to the last writer, so fall back to address+chain (as ``company_overview.prefetch_contracts`` does).
        """
        from sqlalchemy import func
        from sqlalchemy import select as sa_select

        row = session.execute(sa_select(Contract).where(Contract.job_id == job.id).limit(1)).scalar_one_or_none()
        if row is not None or not job.address:
            return row
        # Chain from ``jobs.chain_id`` (a chainless request has ``chain=None`` but a real chain_id), mainnet-coalesced
        # for legacy NULL rows (invariants 1/6/12).
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

        contract_row = self._load_contract_row(session, job)
        if not contract_row:
            raise RuntimeError("Contract row not found for this job")

        contract_name = contract_row.contract_name or "Contract"
        address = contract_row.address or job.address or "0x0"
        job_id_str = str(job.id)

        # Meta dict for downstream tools that still expect it.
        meta = {
            "address": address,
            "contract_name": contract_name,
            "compiler_version": contract_row.compiler_version or "",
            "language": contract_row.language or "solidity",
            "evm_version": contract_row.evm_version or "shanghai",
            "source_format": contract_row.source_format or "flat",
            "source_file_count": contract_row.source_file_count or len(sources),
            "remappings": list(contract_row.remappings or []),
            # Carried, not defaulted: NULL means the fetch fact never reached this row, which a default would erase.
            # Consumed by ``core._source_verified``.
            "source_verified": contract_row.source_verified,
        }
        build_settings = {
            "evm_version": contract_row.evm_version or "shanghai",
            "optimization_used": contract_row.optimization or False,
            "runs": contract_row.optimization_runs or 200,
        }
        remappings = meta.get("remappings", [])

        # Lets the graph builder use the display name instead of a proxy's Etherscan name.
        if job.name:
            meta["display_name"] = job.name

        request = job.request if isinstance(job.request, dict) else {}

        logger.info(
            "Static stage started for job %s address=%s contract=%s",
            job_id_str,
            address,
            contract_name,
        )

        # Saves several RPC calls when the proxy hasn't been upgraded.
        cached_proxy = _check_proxy_cache(session, job, contract_row)
        if cached_proxy is not None:
            target_classification = cached_proxy
            # Same artifact _resolve_proxy would produce.
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
            # Always run: hidden proxies often evade cheap classifiers. The result is reused by classify_contracts().
            target_classification = self._resolve_proxy(session, job, address, contract_name)

        # Proxies skip Slither/analysis (just a thin wrapper) but still get dependency discovery.
        session.refresh(contract_row)
        is_proxy = contract_row.is_proxy
        record_stage_metric("is_proxy", bool(is_proxy))

        # Cached static data: skip Slither, analysis and tracking plan; dependencies still run (resolution needs them).
        has_cached_static = bool(request.get("static_cached"))

        tmp_dir = tempfile.mkdtemp(prefix="psat_static_")
        project_dir = Path(tmp_dir)
        try:
            self._scaffold_project(project_dir, sources, meta, build_settings, remappings)

            # Phase 0: always runs.
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
                # Proxy jobs skip resolution and policy.
                from db.queue import complete_job

                complete_job(session, job.id, f"Proxy {contract_name} — impl child job queued for full analysis")
                raise JobHandledDirectly()
            elif has_cached_static:
                logger.info(
                    "Static stage cache hit for job %s (%s) — skipping Slither/analysis/tracking plan",
                    job_id_str,
                    contract_name,
                )
                self.update_detail(session, job, "Static analysis complete (cached)")
                # The cached analysis still has secondary_impl_pointers, so secondaries resolve on the cache path too.
                cached_analysis = get_artifact(session, job.id, "contract_analysis")
                secondary_analysis = cached_analysis if isinstance(cached_analysis, dict) else None
            else:
                # Phase 1, using Slither's Python IR.
                with log_timed_phase(logger, "contract_analysis"):
                    analysis_data = self._run_analysis_phase(session, job, project_dir, contract_name, address)

                if analysis_data is None:
                    raise RuntimeError(f"Contract analysis failed for {contract_name} ({address}).")

                with log_timed_phase(logger, "tracking_plan"):
                    self._run_tracking_plan_phase(session, job, analysis_data, contract_name, address)
                secondary_analysis = analysis_data if isinstance(analysis_data, dict) else None

            # One call site for both fresh and cached paths, so cached impls in proxy context still get secondary
            # linkage.
            if secondary_analysis is not None:
                self._resolve_secondary_impls(session, job, address, secondary_analysis)

            # Both paths leave the same three artifacts, so publish once here.
            self._publish_materialization(session, job, address, contract_name)

            self.update_detail(session, job, "Static analysis complete")
            logger.info("Static analysis complete for job %s (%s)", job_id_str, contract_name)

        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _resolve_proxy(self, session, job, address: str, contract_name: str) -> dict | None:
        """Detect proxy type on-chain and resolve the implementation, spawning a child job for it.

        Returns the ``classify_single`` result for ``classify_contracts(pre_classified=...)``, or ``None`` when skipped
        or failed.
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
            # #121: proxy slots unreadable. Recording is_proxy=False would erase a real implementation's access-control
            # surface, so record and re-raise (transient) to retry.
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
        # A beacon is analysed as itself (so its owner() is found) but still spawns its implementation as a
        # beacon-context child; other non-proxies return.
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
        # A beacon governs instances from its own address.
        beacon = address if is_beacon else classification.get("beacon")
        admin = classification.get("admin")
        facets = classification.get("facets")

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

            # §3.4 event 2a: new pointers are a fact delta for the gate (the proxy and every pointer target). Never a
            # stamp (invariant 1).
            from services.discovery.membership_gate import FactsDelta, evaluate_committed

            edge_addrs = tuple(
                sorted(
                    {
                        a.lower()
                        for a in (impl_address, beacon, admin, *(facets or []))
                        if isinstance(a, str) and a.startswith("0x") and a.lower() != address.lower()
                    }
                )
            )
            row_id = getattr(contract_row, "id", None)
            evaluate_committed(
                session,
                FactsDelta(
                    new_edge_addresses=edge_addrs,
                    recheck_contract_ids=(row_id,) if isinstance(row_id, int) else (),
                ),
                context=f"static_proxy_classification:{job.id}",
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

        impl_entries: list[tuple[str, str]] = []  # (address, label)
        if impl_address:
            impl_entries.append((impl_address, "impl"))
        if facets:
            for i, facet in enumerate(facets):
                if facet != impl_address:  # avoid duplicates
                    impl_entries.append((facet, f"facet {i + 1}"))

        base_name = job.name or contract_name
        force = bool(request.get("force"))
        # Under --force, the same impl reached via several proxies spawns once per cascade.
        root_job_id = request.get("root_job_id") or str(job.id)
        # Coalesce a chainless request via the job's chain: with chain=None the reconcile has no chain filter, and
        # CREATE2 impls share addresses across chains.
        chain = request.get("chain") or _parent_chain_name(job)
        from sqlalchemy import text as _sa_text

        for impl_addr, label in impl_entries:
            if force:
                # Serializes reconcile-then-insert across workers.
                lock_seed = f"impl-dedupe:{root_job_id}:{chain or '-'}:{impl_addr.lower()}"
                lock_key = int(hashlib.sha1(lock_seed.encode()).hexdigest()[:15], 16)
                session.execute(_sa_text("SELECT pg_advisory_xact_lock(:k)"), {"k": lock_key})

            # A standalone job for this impl is the discovery-order race: convert it to proxy context. Same proxy is a
            # duplicate; a different proxy is a shared impl and gets its own per-deployment job.
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
            # The child carries the proxy's membership (spec §5.2), which the evaluate above may have just set; never a
            # source tag.
            parent_is_member = bool(contract_row is not None and contract_row.protocol_id is not None)
            child_request = {
                "address": impl_addr,
                "name": impl_name,
                "rpc_url": rpc_url,
                "parent_job_id": str(job.id),
                "root_job_id": root_job_id,
                "proxy_address": address,
                "proxy_type": proxy_type,
                "discovery_relationship": "implementation",
                "parent_is_member": parent_is_member,
            }
            # Always stamp the parent's chain (inv. 6) so the child can't default elsewhere.
            impl_chain = request.get("chain") or _parent_chain_name(job)
            child_request["chain"] = impl_chain
            # Defence in depth (inv. 14): a disabled chain spawns nothing.
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
        """1A: detect and queue split-proxy secondary implementations.

        When an impl in proxy context delegatecalls a state-var address from fallback/receive, resolve it against the
        proxy's storage and analyse it as a proxy child, so its admin functions resolve to the proxy's controller.
        Best-effort.
        """
        request = job.request if isinstance(job.request, dict) else {}
        proxy_address = request.get("proxy_address")
        if not (isinstance(proxy_address, str) and proxy_address.startswith("0x") and len(proxy_address) == 42):
            return
        # One level only.
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

            # From ``jobs.chain_id``, mainnet-coalesced (invariants 1/6/12).
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

        # Keep only remappings whose targets contain sources.
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
        self.update_detail(session, job, "Discovering dependencies")

        request = job.request if isinstance(job.request, dict) else {}
        deps_rpc = _request_rpc_url(job)
        # The job's chain, not mainnet: dynamic deps and upgrade history both hit Etherscan, and an L2 proxy would
        # otherwise come back empty (F1/F2).
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

        # Sequential setup: cached artifacts and incremental anchors.
        _raw_static_deps = get_artifact(session, job.id, "static_dependencies")
        cached_static_deps = _raw_static_deps if isinstance(_raw_static_deps, dict) else None

        tx_hashes = dynamic_tx_hashes if isinstance(dynamic_tx_hashes, list) else None
        prev_dyn = _load_prev_dynamic_deps(session, job, tx_hashes)
        dyn_start_block = _start_block_from_prev_dyn(prev_dyn)

        prev_uh_raw = get_artifact(session, job.id, "upgrade_history")
        prev_uh = prev_uh_raw if isinstance(prev_uh_raw, dict) else None
        uh_from_block = _from_block_for_upgrade_history(prev_uh)

        # Parallel section: three RPC/Etherscan-bound sub-phases. Each has its own code_cache; the locked global
        # ``_GETCODE_CACHE`` dedups across them.
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

            # Always called: it returns quickly for non-proxies, and tests observe the call.
            minimal_deps = {
                "address": address,
                "target_classification": target_classification or {},
                "dependencies": {},
            }
            # A plain dict because prior history is merged into it.
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

        # Static dependencies: persist and branch on success.
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

        # Dynamic dependencies: merge with previous and persist.
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

        # Upgrade history.
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

        # Same resolution order as find_dependencies / find_dynamic_dependencies, so classification uses the same
        # endpoint.
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

                # Reuse previous classifications, revalidating proxies so upgraded dependencies are redone.
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
            # Contract names and selectors are immutable, so cache them.
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

            enrichment_data = {
                addr: {"name": name, "selectors": selectors} for addr, (name, selectors) in info_cache.items()
            }
            store_artifact(session, job.id, "enrichment_cache", data=enrichment_data)

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

            # Apply known names from the unified deps to avoid Etherscan lookups, merge with cached history, persist.
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

        # ``predicate_trees`` and ``effects`` feed policy. ``default=str`` so a stray non-JSON analyzer object degrades
        # rather than killing the job.
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
        from sqlalchemy import select as sa_select

        contract_row = session.execute(
            sa_select(Contract).where(Contract.job_id == job.id).limit(1)
        ).scalar_one_or_none()
        if not contract_row:
            return

        summary = analysis.get("summary", {})
        subject = analysis.get("subject", {})

        if subject.get("name"):
            contract_row.contract_name = subject["name"]

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

        Previously only the authority recursion wrote this store, so whether monitoring used a contract's real tracking
        plan depended on graph traversal. Publishing here makes coverage follow from analysis (invariant 8).

        Reads back the three stored artifacts (identical on fresh and cache paths; an unstored bundle must not be
        claimed). A row stamped ``ANALYSIS_SCHEMA_VERSION`` requires a bundle proven to be of that era: cache hits leave
        the job's stamp NULL, so ``proven_analysis_schema_version`` follows the cache chain, and an undetermined era
        publishes nothing.

        Best-effort: storage outages, unreadable keccaks or rows held by other writers never fail a successful job;
        refusals are logged.
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
            # The plan phase records its own failure; a row missing either half would read as no analysis.
            logger.info(
                "Static stage: no materialization published for %s — analysis or tracking plan absent",
                address,
            )
            return

        chain = _parent_chain_name(job)
        request = job.request if isinstance(job.request, dict) else {}
        # Whether this job produced the artifacts or copied an ancestor's; the era gate doesn't say which same-era
        # bundle is newer.
        produced_here = not request.get("static_cached")
        try:
            from services.clients.rpc import get_code_with_keccak

            _code, keccak = get_code_with_keccak(_request_rpc_url(job) or "", address, chain_id=_parent_chain_id(job))
        except Exception as exc:
            # No keccak, no key.
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
                # Only a bundle this job produced may overwrite a current row; otherwise a fresh analysis and a later
                # cache copy would keep flipping it.
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
            # Steady state on unchanged re-runs.
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
