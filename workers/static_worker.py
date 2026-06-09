"""Static analysis worker — runs Slither and contract analysis in a temp directory."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import shutil
import tempfile
import textwrap
import time
from pathlib import Path
from typing import Any, cast

from sqlalchemy import select

from db.models import Contract, ContractSummary, Job, JobDependency, JobStage, RoleDefinition
from db.queue import (
    create_job,
    get_source_files,
    reconcile_impl_job_for_proxy,
    require_contract_for_job,
    store_artifact,
)
from schemas.control_tracking import ControlTrackingPlan
from services.artifacts import (
    STATIC_ANALYSIS_ARTIFACT,
    make_job_contract,
    make_job_stage_context,
    make_stage_artifact,
)
from services.discovery import (
    build_dependency_visualization,
    build_unified_dependencies,
    classify_contracts,
    enrich_dependency_metadata,
    find_dependencies,
    find_dynamic_dependencies,
)
from services.resolution.tracking_plan import build_control_tracking_plan
from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts
from services.static.contract_analysis_pipeline.analysis_types import ContractAnalysis
from utils.logging import log_timed_phase, record_degraded, record_stage_metric
from utils.rpc import (
    default_rpc_url,
    require_supported_chain_id,
)  # used for address comparison
from workers.base import BaseWorker, JobHandledDirectly

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


# Phase errors are job-failing. Pair every call site with ``record_degraded`` so
# the failure also shows up in the stage_errors artifact.
def _log_phase_error(job_id: str, address: str, contract_name: str, phase: str, error: str) -> None:
    logger.error(
        _ERROR_TEMPLATE.format(
            job_id=job_id,
            address=address,
            contract_name=contract_name,
            phase=phase,
            error=error,
        )
    )


def _rpc_url_for_chain_id(*, chain_id: int) -> str:
    return default_rpc_url(chain_id=chain_id)


def _resolve_job_chain_id(job: Job, contract_row: Contract | None = None) -> int:
    return require_supported_chain_id(
        chain_id=(
            contract_row.chain_id if contract_row is not None and contract_row.chain_id is not None else job.chain_id
        ),
        context=f"static job {job.id}",
    )


def _redirect_proxy_policy_dependencies(
    session,
    *,
    chain_id: int,
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
    chain_id = require_supported_chain_id(chain_id=chain_id, context=f"proxy dependency redirect {proxy_addr}")
    if proxy_addr == impl_addr:
        return 0

    stmt = select(JobDependency).where(
        JobDependency.provider_address == proxy_addr,
        JobDependency.provider_chain_id == chain_id,
        JobDependency.required_stage == JobStage.policy,
        JobDependency.status == "pending",
    )
    rows = session.execute(stmt).scalars().all()

    changed = 0
    now = datetime.now(timezone.utc)
    for row in rows:
        duplicate = session.execute(
            select(JobDependency)
            .where(
                JobDependency.depender_job_id == row.depender_job_id,
                JobDependency.provider_chain_id == row.provider_chain_id,
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


def _apply_known_names_to_uh(uh: dict, unified: dict) -> None:
    """Backfill ``contract_name`` on historical implementations using the unified deps' name lookup.

    The parallel ``build_upgrade_history`` call ran with an empty deps dict, so
    impl names that were already known via the static/dynamic deps are missing
    here. Apply them in place without fetching external metadata.
    """
    known_names: dict[str, str] = {}
    for addr, info in unified.get("dependencies", {}).items():
        if isinstance(info, dict) and info.get("contract_name"):
            known_names[addr] = info["contract_name"]
        impl = info.get("implementation") if isinstance(info, dict) else None
        if isinstance(impl, dict) and impl.get("contract_name"):
            known_names[impl["address"]] = impl["contract_name"]

    for proxy_info in uh.get("proxies", {}).values():
        for impl in proxy_info.get("implementations", []):
            if impl.get("contract_name"):
                continue
            name = known_names.get(impl["address"])
            if name:
                impl["contract_name"] = name


def _known_impl_names_from_upgrade_history(uh: dict) -> dict[str, str]:
    known_names: dict[str, str] = {}
    proxies = uh.get("proxies", {})
    if not isinstance(proxies, dict):
        return known_names
    for proxy_info in proxies.values():
        if not isinstance(proxy_info, dict):
            continue
        for impl in proxy_info.get("implementations", []):
            if not isinstance(impl, dict):
                continue
            address = impl.get("address")
            name = impl.get("contract_name")
            if isinstance(address, str) and isinstance(name, str) and address and name:
                known_names[address.lower()] = name
    return known_names


def _finalize_upgrade_history(
    session,
    job,
    address: str,
    uh_pre: dict | None,
    unified: dict,
    contract_row: Contract | None = None,
) -> dict | None:
    """Apply known-name backfill, persist, and project to relational rows.

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
    uh = uh_pre

    if not uh.get("proxies"):
        return None

    store_artifact(session, job.id, "upgrade_history", data=uh)

    # Project the artifact's "upgraded" events into UpgradeEvent rows and
    # backfill historical impl Contract rows. Both operate on the in-memory
    # dict — no re-read of storage. Errors here are non-fatal: the artifact
    # is already stored, so a failure leaves the data still recoverable
    # via re-running this stage.
    if contract_row is not None:
        try:
            from services.discovery.upgrade_history import (
                backfill_historical_impl_contracts,
                project_to_events,
            )

            stats = project_to_events(
                session,
                subject_contract_id=contract_row.id,
                subject_chain_id=contract_row.chain_id,
                artifact_data=uh,
            )
            session.commit()
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
                    chain_id=_resolve_job_chain_id(job, contract_row),
                    impl_addrs=stats["impl_addrs"],
                    parent_proxy_sources=contract_row.discovery_sources,
                    parent_proxy_current_impl_address=contract_row.implementation,
                    known_names=_known_impl_names_from_upgrade_history(uh),
                )
        except Exception as exc:
            record_degraded(
                phase="static_upgrade_history_projection",
                exc=exc,
                context={"job_id": job.id, "address": address},
            )
            logger.error(
                "Upgrade event projection failed for job %s: %s",
                job.id,
                exc,
            )
            raise RuntimeError(f"upgrade event projection failed for {address}") from exc

    return uh


# ---------------------------------------------------------------------------
# Source / project helpers
# ---------------------------------------------------------------------------
# Minimum solc version to avoid known compiler bugs (e.g. Natspec.cpp assertion in 0.8.21).
_MIN_SOLC = "0.8.24"


def _detect_solc_version(sources: dict[str, str]) -> str:
    min_tuple = tuple(int(x) for x in _MIN_SOLC.split("."))
    versions = []
    for content in sources.values():
        for m in re.finditer(r"pragma\s+solidity\s+(<=|>=|[<>^~=]?)\s*(0\.\d+\.\d+)", content):
            op, ver = m.group(1), m.group(2)
            # ``<``/``<=`` is a *ceiling* (e.g. ``pragma solidity <0.9.0``), not a
            # target. Treating it as the compiler version pins a solc that may
            # not exist — 0.9.0 has no release artifact, so ``forge build`` dies
            # with "version not found in artifacts for this platform: 0.9.0".
            # Keep ^ ~ >= = and bare versions; drop upper bounds.
            if op in ("<", "<="):
                continue
            versions.append(ver)
    if not versions:
        return _MIN_SOLC
    detected = max(versions, key=lambda v: tuple(int(x) for x in v.split(".")))
    detected_tuple = tuple(int(x) for x in detected.split("."))
    # Enforce the minimum only for the 0.8.x line that is affected by the bug.
    if detected_tuple[:2] == min_tuple[:2] and detected_tuple < min_tuple:
        return _MIN_SOLC
    return detected


def _relax_pragmas(sources: dict[str, str]) -> dict[str, str]:
    """Rewrite exact pragma constraints to '^X.Y.Z'.

    Foundry nightly validates pragma constraints against solc_version even with
    auto_detect_solc = false. Both bare '0.8.28' and '=0.8.28' are exact
    constraints that prevent using a newer patch-level compiler.
    """
    relaxed = {}
    for path, content in sources.items():
        # Match 'pragma solidity =0.8.28' or bare 'pragma solidity 0.8.28'
        relaxed[path] = re.sub(
            r"(pragma\s+solidity\s+)=?\s*(0\.\d+\.\d+)",
            r"\1^\2",
            content,
        )
    return relaxed


def _detect_src_dir(sources: dict[str, str]) -> str:
    """Pick the foundry `src` directory based on where source files live.

    Priority:
      1. "src" if any file starts with src/
      2. "contracts" if any file starts with contracts/
      3. "." to catch files at root or under lib/
    """
    for path in sources:
        if path.startswith("src/"):
            return "src"
    for path in sources:
        if path.startswith("contracts/"):
            return "contracts"
    return "."


def _prune_remappings(remappings: list[str], source_paths: set[str]) -> list[str]:
    """Keep only remappings whose target directory actually contains files in the source bundle.

    A remapping like ``@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/``
    is only useful if we have files under ``lib/openzeppelin-contracts/contracts/``.
    Remappings pointing to dirs with zero files just confuse solc/Slither.
    """
    kept: list[str] = []
    dropped: list[str] = []
    for entry in remappings:
        # Parse "prefix=target" (Foundry remapping format)
        if "=" not in entry:
            kept.append(entry)
            continue
        _prefix, target = entry.split("=", 1)
        target = target.rstrip("/")
        # Check if any source file lives under this target path
        if any(p == target or p.startswith(target + "/") for p in source_paths):
            kept.append(entry)
        else:
            dropped.append(entry)
    if dropped:
        logger.info(
            "Pruned %d/%d remappings with no matching source files: %s",
            len(dropped),
            len(remappings),
            ", ".join(d.split("=")[0] for d in dropped),
        )
    return kept


class StaticWorker(BaseWorker):
    stage = JobStage.static
    next_stage = JobStage.resolution

    @staticmethod
    def _load_contract_row(session, job):
        """Resolve the canonical Contract row for the job's ``(chain_id, address)``."""
        return require_contract_for_job(session, job, context=f"static worker contract lookup for {job.id}")

    def process(self, session, job):
        sources = get_source_files(session, job.id)
        if not sources:
            raise RuntimeError("No source files found in DB for this job")

        # Read from contracts table instead of artifacts
        contract_row = self._load_contract_row(session, job)
        if not contract_row:
            raise RuntimeError("Contract row not found for this job")

        contract_name = contract_row.contract_name or "Contract"
        address = contract_row.address or job.address
        if not address:
            raise RuntimeError(f"static worker job {job.id} requires contract address")
        job_id_str = str(job.id)
        request = job.request if isinstance(job.request, dict) else {}
        chain_id = _resolve_job_chain_id(job, contract_row)
        if job.chain_id != chain_id or contract_row.chain_id != chain_id:
            job.chain_id = chain_id
            contract_row.chain_id = chain_id
            session.commit()
        request_proxy_address = request.get("proxy_address") if isinstance(request.get("proxy_address"), str) else None
        implementation_addresses = [
            item
            for item in [
                contract_row.implementation,
                *(contract_row.secondary_implementations or []),
            ]
            if item
        ]
        if request_proxy_address and contract_row.address:
            implementation_addresses.insert(0, contract_row.address)
        is_proxy_context = bool(contract_row.is_proxy or request_proxy_address)
        proxy_address = request_proxy_address or (address if contract_row.is_proxy else None)

        # Build meta dict for downstream tools that still expect it
        meta = {
            "address": address,
            "chain_id": chain_id,
            "contract_name": contract_name,
            "label": job.name,
            "compiler_version": contract_row.compiler_version or "",
            "language": contract_row.language or "solidity",
            "evm_version": contract_row.evm_version or "shanghai",
            "source_format": contract_row.source_format or "flat",
            "source_file_count": contract_row.source_file_count or len(sources),
            "remappings": list(contract_row.remappings or []),
            "is_proxy": is_proxy_context,
            "proxy_address": proxy_address,
            "implementation_addresses": implementation_addresses,
            "admin_addresses": [contract_row.admin] if contract_row.admin else [],
            "beacon_addresses": [contract_row.beacon] if contract_row.beacon else [],
            "deployer_address": contract_row.deployer,
            "proxy_type": request.get("proxy_type") or contract_row.proxy_type,
        }
        build_settings = {
            "evm_version": contract_row.evm_version or "shanghai",
            "optimization_used": contract_row.optimization or False,
            "runs": contract_row.optimization_runs or 200,
        }
        remappings = meta.get("remappings", [])

        # Attach the job's display name so downstream tools (e.g. graph builder)
        # can use the explicit label for proxy contracts.
        if job.name:
            meta["display_name"] = job.name

        logger.info(
            "Static stage started for job %s address=%s contract=%s",
            job_id_str,
            address,
            contract_name,
        )

        # Always attempt semantic proxy classification through the chain-scoped
        # eRPC endpoint. Hidden proxies often won't match cheap static
        # classifiers, so we run this unconditionally. The result is reused by
        # classify_contracts() in the dependency phase to avoid duplicate RPC
        # calls within this job.
        target_classification = self._resolve_proxy(session, job, address, contract_name)

        # Check if proxy classification marked this as a proxy — if so,
        # skip Slither/analysis on the proxy source (it's just a thin wrapper).
        # Dependency discovery still runs because proxy-address deps are useful.
        session.refresh(contract_row)
        is_proxy = contract_row.is_proxy
        record_stage_metric("is_proxy", bool(is_proxy))

        # Create temp directory and write source files
        tmp_dir = tempfile.mkdtemp(prefix="psat_static_")
        project_dir = Path(tmp_dir)
        try:
            self._scaffold_project(project_dir, sources, meta, build_settings, remappings)

            # Phase 0: Dependency artifacts (always runs — proxy deps are useful)
            with log_timed_phase(logger, "dependency_discovery"):
                self._run_dependency_phase(
                    session,
                    job,
                    project_dir,
                    contract_name,
                    address,
                    chain_id=chain_id,
                    target_classification=target_classification,
                )

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
            else:
                # Phase 1: Contract analysis (uses Slither's Python IR — the
                # CLI subprocess that produced detector findings was removed;
                # vulnerability triage is now an out-of-band concern, not part
                # of the cascade pipeline).
                t0 = time.monotonic()
                analysis_result = self._run_analysis_phase(session, job, project_dir, contract_name, address)
                logger.info(
                    "static phase complete: contract analysis",
                    extra={"duration_ms": int((time.monotonic() - t0) * 1000), "phase": "contract_analysis"},
                )

                analysis_data, semantic_predicate_trees, semantic_effects = analysis_result

                # Phase 2: Control tracking plan
                t0 = time.monotonic()
                tracking_plan = self._run_tracking_plan_phase(session, job, analysis_data, contract_name, address)
                logger.info(
                    "static phase complete: tracking plan",
                    extra={"duration_ms": int((time.monotonic() - t0) * 1000), "phase": "tracking_plan"},
                )
                self._store_static_analysis_artifact(
                    session,
                    job,
                    contract_row,
                    chain_id=chain_id,
                    contract_analysis=analysis_data,
                    control_tracking_plan=tracking_plan,
                    predicate_trees=semantic_predicate_trees,
                    effects=semantic_effects,
                )
                secondary_analysis = analysis_data if isinstance(analysis_data, dict) else None

            # 1A: queue split-proxy secondary implementations (best-effort). SINGLE
            # call site reached by BOTH the fresh-analysis and cache-hit paths, so
            # an impl re-seen in proxy context never silently skips secondary-impl
            # linkage just because its static artifacts were cached.
            if secondary_analysis is not None:
                self._resolve_secondary_impls(session, job, address, secondary_analysis)

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
        Classifier failures are stage failures: a failed chain-scoped RPC read
        must not be recorded as ``is_proxy=False``.
        """
        from services.discovery.classifier import classify_single

        request = job.request if isinstance(job.request, dict) else {}
        chain_id = _resolve_job_chain_id(job)
        rpc_url = _rpc_url_for_chain_id(chain_id=chain_id)

        try:
            classification = classify_single(address, rpc_url, chain_id=chain_id)
        except Exception as exc:
            from utils.secrets import sanitize_string

            record_degraded(
                phase="proxy_classification",
                exc=exc,
                context={"address": address},
            )
            logger.error("Job %s: proxy classification failed: %s", job.id, sanitize_string(str(exc)))
            raise RuntimeError(f"proxy classification failed for {address}") from exc

        classification_type = classification.get("type", "regular")
        if classification_type != "proxy":
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

        proxy_type = classification.get("proxy_type", "unknown")
        impl_address = classification.get("implementation")
        beacon = classification.get("beacon")
        admin = classification.get("admin")
        facets = classification.get("facets")

        # Update contracts table with proxy info
        contract_row = require_contract_for_job(session, job, context=f"static proxy metadata write for {job.id}")
        if contract_row:
            contract_row.is_proxy = True
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

                impl_row = session.execute(
                    select(Contract)
                    .where(
                        Contract.address == impl_address.lower(),
                        Contract.chain_id == chain_id,
                    )
                    .limit(1)
                ).scalar_one_or_none()
                if impl_row is not None and getattr(impl_row, "protocol_id", None) is not None:
                    # Parent must be HIGH-source-owned, mirroring the
                    # ``asserts_ownership`` gate. A LOW-source parent
                    # (``upgrade_history`` backfill, ``structural_adoption``)
                    # with ``protocol_id`` set must not act as evidence —
                    # that'd silently relax the runtime one-hop limit.
                    from services.discovery.source_confidence import HIGH_CONFIDENCE_SOURCES

                    referenced_by_same_protocol = session.execute(
                        select(ContractDependency.id)
                        .join(Contract, Contract.id == ContractDependency.contract_id)
                        .where(
                            ContractDependency.dependency_address == contract_addr,
                            Contract.protocol_id == impl_row.protocol_id,
                            Contract.discovery_sources.overlap(list(HIGH_CONFIDENCE_SOURCES)),
                        )
                        .limit(1)
                    ).scalar_one_or_none()
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
                "is_proxy": True,
                "classification_type": classification_type,
                "proxy_type": proxy_type,
                "implementation": impl_address,
                "beacon": beacon,
                "admin": admin,
                "facets": facets,
            },
        )

        logger.info(
            "Job %s: proxy classified as %s, implementation=%s",
            job.id,
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
        from sqlalchemy import text as _sa_text

        for impl_addr, label in impl_entries:
            if force:
                # Advisory xact lock serializes the reconcile-then-INSERT against concurrent static workers.
                lock_seed = f"impl-dedupe:{root_job_id}:{chain_id}:{impl_addr.lower()}"
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
                chain_id=chain_id,
                root_job_id=root_job_id if force else None,
            )
            if decision in ("skip", "backpatched"):
                _redirect_proxy_policy_dependencies(
                    session,
                    chain_id=chain_id,
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
                "parent_job_id": str(job.id),
                "root_job_id": root_job_id,
                "chain_id": chain_id,
                "proxy_address": address,
                "proxy_type": proxy_type,
                "discovery_relationship": "implementation",
                "parent_owns_high": parent_owns_high,
            }
            if getattr(job, "protocol_id", None):
                child_request["protocol_id"] = job.protocol_id
            if force:
                child_request["force"] = True
            child_job = create_job(session, child_request)
            _redirect_proxy_policy_dependencies(
                session,
                chain_id=chain_id,
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
        Chain-scoped RPC failures are stage failures; silently skipping this
        produces incomplete proxy analysis.
        """
        request = job.request if isinstance(job.request, dict) else {}
        chain_id = _resolve_job_chain_id(job)
        proxy_address = request.get("proxy_address")
        if not (isinstance(proxy_address, str) and proxy_address.startswith("0x") and len(proxy_address) == 42):
            return
        # One level only: a secondary impl doesn't itself spawn secondaries.
        if request.get("discovery_relationship") == "secondary_implementation":
            return
        pointers = (analysis_data or {}).get("secondary_impl_pointers") or []
        if not pointers:
            return
        rpc_url = _rpc_url_for_chain_id(chain_id=chain_id)
        try:
            from sqlalchemy import select as sa_select

            from services.discovery.secondary_impl import (
                queue_secondary_impl_jobs,
                resolve_secondary_impl_addresses,
            )

            proxy_stmt = sa_select(Contract).where(Contract.address == proxy_address.lower())
            proxy_stmt = proxy_stmt.where(Contract.chain_id == chain_id)
            proxy_contract = session.execute(proxy_stmt.limit(1)).scalar_one_or_none()
            if proxy_contract is None:
                logger.error(
                    "Job %s: secondary-impl proxy row %s not found for chain_id=%s",
                    job.id,
                    proxy_address,
                    chain_id,
                )
                raise RuntimeError(f"secondary-impl proxy row {proxy_address} not found for chain_id={chain_id}")
            secondary_addrs = resolve_secondary_impl_addresses(
                rpc_url,
                proxy_address,
                pointers,
                chain_id=chain_id,
                implementation=proxy_contract.implementation,
            )
            if not secondary_addrs:
                return
            created = queue_secondary_impl_jobs(
                session,
                proxy_contract=proxy_contract,
                secondary_addrs=secondary_addrs,
                parent_job=job,
                proxy_type=request.get("proxy_type") or proxy_contract.proxy_type,
                root_job_id=request.get("root_job_id") or str(job.id),
                chain_id=chain_id,
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
            logger.error("Job %s: secondary-impl resolution failed: %s", job.id, sanitize_string(str(exc)))
            raise RuntimeError(f"secondary implementation resolution failed for {address}") from exc

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
            full_path = project_dir / filepath
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content)

        solc_version = _detect_solc_version(sources)
        src_dir = _detect_src_dir(sources)
        evm_version = build_settings.get("evm_version", "shanghai")
        optimizer = str(build_settings.get("optimization_used", True)).lower()
        optimizer_runs = build_settings.get("runs", 200)

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
        chain_id: int,
        target_classification: dict | None = None,
    ) -> None:
        """Build dependency artifacts before compile-dependent analysis starts."""
        self.update_detail(session, job, "Discovering dependencies")

        request = job.request if isinstance(job.request, dict) else {}
        deps_rpc = _rpc_url_for_chain_id(chain_id=chain_id)
        dynamic_tx_limit = request.get("dynamic_tx_limit", 10)
        dynamic_tx_hashes = request.get("dynamic_tx_hashes")

        logger.info(
            "Static stage dependency discovery started for job %s address=%s contract=%s",
            job.id,
            address,
            contract_name,
        )

        tx_hashes = dynamic_tx_hashes if isinstance(dynamic_tx_hashes, list) else None

        # ---- Parallel section: 3 network-bound sub-phases. ----
        # Each sub-phase gets its own ``code_cache`` dict; the global locked
        # ``_GETCODE_CACHE`` in utils.rpc dedups across them so the only cost
        # is independent dict lookups per thread.
        proxy_addr = request.get("proxy_address")

        def run_static() -> dict:
            return find_dependencies(address, code_cache={}, chain_id=chain_id)

        def run_dynamic() -> dict:
            return find_dynamic_dependencies(
                address,
                chain_id=chain_id,
                tx_limit=int(dynamic_tx_limit),
                tx_hashes=tx_hashes,
                proxy_address=proxy_addr,
                code_cache={},
                start_block=None,
            )

        def run_upgrade_history() -> dict | None:
            from services.discovery.upgrade_history import build_upgrade_history

            # Always call ``build_upgrade_history``: when the target isn't a proxy
            # it returns an empty proxies dict cheaply and the test harness still
            # observes the call. eRPC log fetches only happen when ``proxy_meta``
            # is non-empty inside the helper.
            minimal_deps = {
                "address": address,
                "target_classification": target_classification or {},
                "dependencies": {},
            }
            return build_upgrade_history(minimal_deps, chain_id=chain_id, from_block=0)

        from utils.concurrency import parallel_map

        def _hb() -> None:
            self._heartbeat(session, job)

        t0 = time.monotonic()
        sub_phases = [("static", run_static), ("dynamic", run_dynamic), ("upgrade_history", run_upgrade_history)]
        results = parallel_map(lambda task: task[1](), sub_phases, max_workers=3, heartbeat=_hb)
        elapsed_parallel = time.monotonic() - t0
        logger.info(
            "static phase complete: dependency parallel section",
            extra={"duration_ms": int(elapsed_parallel * 1000), "phase": "dependency_parallel"},
        )

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
            logger.error(
                "Static stage static dependency discovery failed for job %s address=%s: %s",
                job.id,
                address,
                static_outcome,
            )
            raise RuntimeError(f"static dependency discovery failed for {address}") from static_outcome
        else:
            deps_output = static_outcome  # type: ignore[assignment]
            if isinstance(deps_output, dict):
                store_artifact(session, job.id, "static_dependencies", data=deps_output)
            static_dep_count = len(deps_output.get("dependencies", [])) if isinstance(deps_output, dict) else 0
            record_stage_metric("static_dependencies", static_dep_count)
            logger.info(
                "Static stage static dependencies complete for job %s address=%s count=%d",
                job.id,
                address,
                static_dep_count,
            )

        # ---- Dynamic dependencies: persist current chain-scoped results. ----
        dyn_output: dict | None = None
        dyn_outcome = outcomes["dynamic"]
        if isinstance(dyn_outcome, BaseException):
            record_degraded(
                phase="dependency_dynamic",
                exc=dyn_outcome,
                context={"address": address},
            )
            logger.error(
                "Static stage dynamic dependency discovery failed for job %s address=%s: %s",
                job.id,
                address,
                dyn_outcome,
            )
            raise RuntimeError(f"dynamic dependency discovery failed for {address}") from dyn_outcome
        else:
            dyn_output = dyn_outcome  # type: ignore[assignment]
            if isinstance(dyn_output, dict):
                store_artifact(session, job.id, "dynamic_dependencies", data=dyn_output)
                record_stage_metric("dynamic_dependencies", len(dyn_output.get("dependencies", [])))
                logger.info(
                    "Static stage dynamic dependencies complete for job %s address=%s count=%d",
                    job.id,
                    address,
                    len(dyn_output.get("dependencies", [])),
                )

        # ---- Upgrade history: persist current chain-scoped results. ----
        uh_outcome_raw = outcomes["upgrade_history"]
        uh_pre: dict | None
        if isinstance(uh_outcome_raw, BaseException):
            record_degraded(
                phase="dependency_upgrade_history",
                exc=uh_outcome_raw,
                context={"address": address, "subphase": "parallel"},
            )
            logger.error(
                "Static stage upgrade history failed for job %s address=%s: %s",
                job.id,
                address,
                uh_outcome_raw,
            )
            raise RuntimeError(f"upgrade history discovery failed for {address}") from uh_outcome_raw
        elif isinstance(uh_outcome_raw, dict):
            uh_pre = uh_outcome_raw
        else:
            uh_pre = None

        # Classification uses the same chain-scoped eRPC endpoint discovery used
        # by static and dynamic dependency discovery.
        resolved_rpc = deps_rpc

        cls_output = None
        unique_deps = sorted(
            set((deps_output or {}).get("dependencies", []) + (dyn_output or {}).get("dependencies", []))
        )
        record_stage_metric("dependencies", len(unique_deps))
        try:
            t0 = time.monotonic()
            from services.discovery.static_dependencies import normalize_address

            pre_classified = {}
            if target_classification:
                pre_classified[normalize_address(address)] = target_classification

            cls_output = classify_contracts(
                address,
                unique_deps,
                resolved_rpc,
                chain_id=chain_id,
                dynamic_edges=(dyn_output or {}).get("dependency_graph"),
                code_cache=None,
                pre_classified=pre_classified or None,
            )
            # Store classifications artifact for downstream stages.
            store_artifact(session, job.id, "classifications", data=cls_output)
            record_stage_metric("discovered_addresses", len(cls_output.get("discovered_addresses", [])))
            logger.info(
                "static phase complete: classification (%d deps)",
                len(unique_deps),
                extra={
                    "duration_ms": int((time.monotonic() - t0) * 1000),
                    "phase": "classification",
                    "dep_count": len(unique_deps),
                },
            )
            logger.info(
                "Static stage dependency classification complete for job %s address=%s discovered=%d",
                job.id,
                address,
                len(cls_output.get("discovered_addresses", [])),
            )
        except Exception as exc:
            record_degraded(
                phase="dependency_classification",
                exc=exc,
                context={"address": address},
            )
            logger.error(
                "Static stage dependency classification failed for job %s address=%s: %s",
                job.id,
                address,
                exc,
            )
            raise RuntimeError(f"dependency classification failed for {address}") from exc

        if deps_output or dyn_output:
            unified = build_unified_dependencies(
                address, deps_output, dyn_output, cls_output, target_classification=target_classification
            )
            info_cache: dict[str, tuple[str | None, dict[str, str]]] = {}

            t0 = time.monotonic()
            enrich_dependency_metadata(unified, chain_id=chain_id, info_cache=info_cache)
            logger.info(
                "static phase complete: dependency enrichment",
                extra={"duration_ms": int((time.monotonic() - t0) * 1000), "phase": "enrichment"},
            )

            # Write to contract_dependencies table
            contract_row = require_contract_for_job(session, job, context=f"static dependency write for {job.id}")
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
            # deps without external metadata fetches, then persist.
            try:
                uh = _finalize_upgrade_history(
                    session,
                    job,
                    address,
                    uh_pre,
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
                logger.error(
                    "Static stage upgrade history failed for job %s address=%s: %s",
                    job.id,
                    address,
                    exc,
                )
                raise RuntimeError(f"upgrade history finalization failed for {address}") from exc
        else:
            logger.warning(
                "Static stage dependency artifacts skipped for job %s address=%s (no dependency outputs)",
                job.id,
                address,
            )

    def _run_analysis_phase(
        self, session, job, project_dir: Path, contract_name: str, address: str
    ) -> tuple[ContractAnalysis, dict[str, Any] | None, Any]:
        """Run structured contract analysis."""
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
            raise RuntimeError(f"contract analysis failed for {address}") from exc

        # ``predicate_trees`` and ``effects`` are the semantic artifacts
        # consumed by policy resolution.
        (project_dir / "contract_analysis.json").write_text(json.dumps(analysis_data, indent=2) + "\n")
        if semantic_predicate_trees is not None:
            (project_dir / "predicate_trees.json").write_text(json.dumps(semantic_predicate_trees, indent=2) + "\n")
        if semantic_effects is not None:
            (project_dir / "effects.json").write_text(json.dumps(semantic_effects, indent=2) + "\n")

        self._write_analysis_tables(session, job, analysis_data)
        logger.info(
            "Static stage contract analysis complete for job %s address=%s contract=%s",
            job.id,
            address,
            contract_name,
        )
        return analysis_data, semantic_predicate_trees, semantic_effects

    def _write_analysis_tables(self, session, job: Job, analysis: ContractAnalysis | dict) -> None:
        """Extract structured data from contract_analysis JSON into relational tables."""
        contract_row = require_contract_for_job(session, job, context=f"static analysis table write for {job.id}")

        summary = analysis.get("summary", {})
        subject = analysis.get("subject", {})

        # Update contract name from analysis if available
        if subject.get("name"):
            contract_row.contract_name = subject["name"]

        # Write contract_summary
        existing_summary = session.execute(
            select(ContractSummary).where(ContractSummary.contract_id == contract_row.id)
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
                risk_level=summary.get("static_risk_level"),
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

    def _run_tracking_plan_phase(
        self, session, job, analysis: ContractAnalysis | dict, contract_name: str, address: str
    ) -> ControlTrackingPlan:
        """Build control tracking plan."""
        self.update_detail(session, job, "Building control tracking plan")
        try:
            tracking_plan = build_control_tracking_plan(cast(ContractAnalysis, analysis))
            logger.info(
                "Static stage tracking plan complete for job %s address=%s contract=%s",
                job.id,
                address,
                contract_name,
            )
            return tracking_plan
        except Exception as exc:
            record_degraded(
                phase="tracking_plan",
                exc=exc,
                context={"address": address, "contract_name": contract_name},
            )
            _log_phase_error(str(job.id), address, contract_name, "tracking_plan", str(exc))
            store_artifact(session, job.id, "tracking_plan_error", data={"error": str(exc)})
            raise RuntimeError(f"tracking plan failed for {address}") from exc

    def _store_static_analysis_artifact(
        self,
        session,
        job: Job,
        contract_row: Contract,
        *,
        chain_id: int,
        contract_analysis: ContractAnalysis,
        control_tracking_plan: ControlTrackingPlan,
        predicate_trees: Any,
        effects: Any,
    ) -> None:
        data = {
            "contract_analysis": contract_analysis,
            "control_tracking_plan": control_tracking_plan,
            "predicate_trees": predicate_trees if isinstance(predicate_trees, dict) else None,
            "effects": effects if isinstance(effects, dict) else None,
        }
        if contract_row.job_id != job.id:
            contract_row.job_id = job.id
            session.flush()
        artifact = make_stage_artifact(
            kind=STATIC_ANALYSIS_ARTIFACT,
            stage="static",
            schema_version="static_analysis.v1",
            context=make_job_stage_context(
                job,
                stage="static",
                schema_version="static_analysis.v1",
                chain_id=chain_id,
            ),
            contract=make_job_contract(session, job, contract_row),
            data=data,
        )
        store_artifact(session, job.id, STATIC_ANALYSIS_ARTIFACT, data=artifact)


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        force=True,
    )
    StaticWorker().run_loop()


if __name__ == "__main__":
    main()
