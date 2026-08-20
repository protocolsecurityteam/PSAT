"""Static-data caching: cache lookup, row copy, and cache-copy paths."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.models import (
    Artifact,
    Base,
    Contract,
    ContractSummary,
    Job,
    JobStage,
    JobStatus,
    SourceFile,
    derive_job_chain_id,
)
from db.storage import artifact_key, get_storage_client, source_file_key
from utils.chains import canonical_chain
from utils.logging import record_degraded

from ._chains import _job_chain_name, _mainnet_coalesced_chain
from .artifacts import get_artifact, store_artifact

logger = logging.getLogger("db.queue")

# ---------------------------------------------------------------------------
# Static data caching
# ---------------------------------------------------------------------------

# Artifact names that constitute cached static data (immutable, never change).
# slither_results / analysis_report were removed when vulnerability-detector
# triage was split out of PSAT's pipeline; downstream stages don't depend on
# them, and the only writer (StaticWorker._run_slither_phase) is gone.
# predicate_trees / effects are emitted by semantic static analysis and are
# required by resolution and policy, so cache hits must carry them forward.
_STATIC_ARTIFACT_NAMES = frozenset(
    {
        "contract_analysis",
        "control_tracking_plan",
        "predicate_trees",
        "effects",
        "static_dependencies",
        "enrichment_cache",
    }
)

# Artifacts copied as a starting baseline but appended to on subsequent runs.
_SEED_ARTIFACT_NAMES = frozenset(
    {
        "dynamic_dependencies",
        "classifications",
        "upgrade_history",
    }
)

# Contract columns that are mutable (resolved live by _resolve_proxy) and
# must NOT be carried over from a cached job.
_MUTABLE_CONTRACT_FIELDS = frozenset({"is_proxy", "proxy_type", "implementation", "beacon", "admin"})


def copy_row(session: Session, source: Base, *, exclude: frozenset[str] = frozenset(), **overrides: Any) -> Base:
    """Copy a SQLAlchemy row, returning a new detached instance.

    - Primary keys are always skipped (auto-generated).
    - Columns with a ``server_default`` (e.g. ``created_at``) are skipped
      so the DB assigns fresh values, unless explicitly passed in *overrides*.
    - *exclude* names additional columns to drop.
    - *overrides* supply values that differ from the source (e.g. remapped
      foreign keys, zeroed-out mutable fields).

    Lists are shallow-copied so the new row doesn't share references with
    the source.
    """
    from sqlalchemy import inspect as sa_inspect

    mapper = sa_inspect(type(source))
    kwargs: dict[str, Any] = {}
    for attr in mapper.column_attrs:
        key = attr.key
        if key in exclude:
            continue
        col = attr.columns[0]
        if col.primary_key:
            continue
        if key in overrides:
            kwargs[key] = overrides[key]
            continue
        if col.server_default is not None:
            continue
        value = getattr(source, key)
        if isinstance(value, list):
            value = list(value)
        kwargs[key] = value

    new_row = type(source)(**kwargs)
    session.add(new_row)
    return new_row


def proven_analysis_schema_version(session: Session, job: Job) -> int | None:
    """The analyzer era *job*'s static artifacts were produced under, or None.

    ``jobs.analysis_schema_version`` is stamped only on the fetch path
    (``workers/discovery``): a same-address cache hit copies the donor's
    artifacts and returns before the stamp, so the column reads NULL on 32 of
    the working DB's 86 completed cache-hit jobs. NULL is not "current" — it is
    the absence of the fact — and a consumer that treats it as current stamps an
    era nothing witnessed onto the bundle.

    The fact is still recoverable: ``copy_static_cache`` copies the donor's
    artifacts verbatim, so the donor's era IS this job's artifacts' era. The
    chain is followed until a stamped job is found.

    **Walked to termination, not to a hop budget.** Every cache-hit re-run of an
    address appends one hop, so the chain grows without bound on exactly the
    addresses that get re-analyzed most; measured on the working DB, all 32
    unstamped jobs terminate at a stamped v5 donor between 1 and 14 hops away —
    a fixed budget silently converts the far end of that distribution into
    "no witnessed era" and refuses supply for the busiest contracts. Termination
    rests on the visited set instead: each hop moves to a distinct job id, so a
    finite table is exhausted in finite steps whatever the links look like.
    """
    version = getattr(job, "analysis_schema_version", None)
    if isinstance(version, int):
        return version

    seen: set[str] = {str(getattr(job, "id", ""))}
    current: Job | None = job
    while True:
        request = current.request if current is not None and isinstance(current.request, dict) else {}
        donor_id = request.get("cache_source_job_id")
        if not donor_id or str(donor_id) in seen:
            return None
        seen.add(str(donor_id))
        try:
            current = session.get(Job, donor_id)
        except Exception as exc:
            # A DB error reads exactly like "no donor", which publishes "no
            # witnessed era" for a job that has one. Nothing here can recover it
            # — the caller's contract is a value or None — so the honest move is
            # to say the None came from a failed read. The sole caller is the
            # static worker, inside a job, so the WARNING is paired with
            # ``record_degraded``: this module sits outside the level-contract
            # checker's perimeter, which is why the pairing is stated here
            # rather than enforced.
            record_degraded(
                phase="donor_era_walk",
                exc=exc,
                context={"donor_job_id": str(donor_id), "job_id": str(getattr(job, "id", ""))},
            )
            logger.warning(
                "donor-era walk could not read a donor job; the era reads as not witnessed",
                extra={"donor_job_id": str(donor_id), "exc_type": type(exc).__name__, "error": str(exc)},
            )
            return None
        if current is None:
            return None
        version = getattr(current, "analysis_schema_version", None)
        if isinstance(version, int):
            return version


def find_completed_static_cache(
    session: Session,
    address: str,
    chain: str | None = None,
    source_content_hash: str | None = None,
) -> Job | None:
    """Find a previously completed job for *address* (and *chain*) that has all required static data.

    Returns the cached :class:`Job` if one exists with:
    - status = completed, stage = done
    - at least one ``source_files`` row
    - the ``contract_analysis`` artifact (key indicator that the static stage finished)
    - a ``contracts`` row for this address/chain with a ``contract_summaries`` row

    The contract lookup uses (address, chain) rather than ``job_id`` so that
    the cache remains valid even after ``copy_static_cache`` reassigned the
    Contract row to a later target job.

    **Cross-chain fallback (invariant 1):** when the exact ``(address, chain)``
    lookup misses and *source_content_hash* is supplied, a second lookup finds a
    completed job that analyzed the *same verified source* under the current
    analyzer schema version — regardless of its chain or address. That donor's
    code plane is reusable for this deployment (its state is re-resolved per
    chain by the copy path). The primary ``(address, chain)`` behaviour is
    unchanged, so mainnet re-runs are byte-identical; the fallback only fires on
    a primary miss. Returns ``None`` when no suitable cache exists.
    """
    stmt = (
        select(Job)
        .where(
            func.lower(Job.address) == address.lower(),
            Job.status == JobStatus.completed,
            Job.stage == JobStage.done,
        )
        .order_by(Job.updated_at.desc())
    )
    # SQL-side chain filtering on the first-class ``jobs.chain_id`` column
    # (invariant 1). The M0.2 backfill populated chain_id for every
    # address-scoped row, so ``chain_id = :id`` is a total, collision-free
    # filter; ``derive_job_chain_id`` maps the caller's chain string to the same
    # id the dual-write stored (unknown/missing → 1) so mainnet is unchanged.
    if chain is not None:
        stmt = stmt.where(Job.chain_id == derive_job_chain_id(chain, address))
    candidates = session.execute(stmt).scalars().all()

    for candidate in candidates:
        src_count = session.execute(
            select(SourceFile).where(SourceFile.job_id == candidate.id).limit(1)
        ).scalar_one_or_none()
        if not src_count:
            continue

        # Look up by (address, chain), not job_id — copy_static_cache may have reassigned.
        # Join ContractSummary so .limit(1) skips stub rows that lack the cached summary.
        contract_stmt = (
            select(Contract)
            .join(ContractSummary, ContractSummary.contract_id == Contract.id)
            .where(func.lower(Contract.address) == address.lower())
        )
        if chain is not None:
            # Mainnet-coalesced so a mainnet lookup matches legacy NULL-chain
            # rows; a non-mainnet lookup stays isolated.
            contract_stmt = contract_stmt.where(
                func.lower(func.coalesce(Contract.chain, "ethereum"))
                == _mainnet_coalesced_chain(canonical_chain(chain))
            )
        contract_row = session.execute(contract_stmt.limit(1)).scalar_one_or_none()
        if not contract_row:
            continue

        # Static-stage-finished check. For non-proxy contracts the canonical
        # indicator is ``contract_analysis`` (slither output + summary).
        # Proxies never produce ``contract_analysis`` on their own job —
        # it lives on the impl child — so require ``contract_flags`` instead,
        # which proxies do write (is_proxy + proxy_type). Without this
        # branch, re-discovered proxies would miss the cache and do a full
        # fresh Etherscan fetch + slither run every time.
        required_artifact = "contract_flags" if contract_row.is_proxy else "contract_analysis"
        has_required = session.execute(
            select(Artifact).where(Artifact.job_id == candidate.id, Artifact.name == required_artifact).limit(1)
        ).scalar_one_or_none()
        if not has_required:
            continue

        summary = session.execute(
            select(ContractSummary).where(ContractSummary.contract_id == contract_row.id).limit(1)
        ).scalar_one_or_none()
        if not summary:
            continue

        return candidate

    # Cross-chain fallback: the exact (address, chain) lookup missed; if we know
    # this deployment's source hash, reuse a completed job that analyzed the same
    # source on any chain (invariant 1).
    if source_content_hash:
        return _find_static_cache_by_source_hash(session, source_content_hash)

    return None


def _find_static_cache_by_source_hash(session: Session, source_content_hash: str) -> Job | None:
    """Most-recent completed job whose verified source hashes to *source_content_hash*
    under the current analyzer schema version, with a real analyzed root (a
    ``contract_analysis`` artifact + a summaried contract).

    Version-gated so a bumped analyzer misses stale donors (``jobs`` rows carry
    the schema version they were analyzed under). Proxies are never donors — they
    carry ``contract_flags`` rather than ``contract_analysis`` and are analyzed
    per chain.
    """
    from db.contract_materializations import ANALYSIS_SCHEMA_VERSION

    candidates = (
        session.execute(
            select(Job)
            .where(
                Job.status == JobStatus.completed,
                Job.stage == JobStage.done,
                Job.source_content_hash == source_content_hash,
                Job.analysis_schema_version == ANALYSIS_SCHEMA_VERSION,
            )
            .order_by(Job.updated_at.desc())
        )
        .scalars()
        .all()
    )
    for candidate in candidates:
        if candidate.address is None:
            continue
        has_src = session.execute(
            select(SourceFile).where(SourceFile.job_id == candidate.id).limit(1)
        ).scalar_one_or_none()
        if not has_src:
            continue
        # A summaried contract at the donor's own (address, chain) proves the
        # static tables landed; contract_analysis proves the analysis (not a
        # proxy stub). Chain-qualified: a CREATE2 same-address deployment on
        # another chain can carry different source, so the donor job must pair
        # with its own chain's row.
        donor_contract = session.execute(
            select(Contract)
            .join(ContractSummary, ContractSummary.contract_id == Contract.id)
            .where(
                func.lower(Contract.address) == candidate.address.lower(),
                func.lower(func.coalesce(Contract.chain, "ethereum"))
                == _mainnet_coalesced_chain(_job_chain_name(candidate)),
            )
            .limit(1)
        ).scalar_one_or_none()
        if not donor_contract:
            continue
        has_analysis = session.execute(
            select(Artifact).where(Artifact.job_id == candidate.id, Artifact.name == "contract_analysis").limit(1)
        ).scalar_one_or_none()
        if not has_analysis:
            continue
        return candidate
    return None


def find_previous_company_inventory(
    session: Session,
    company: str,
    exclude_job_id: Any = None,
    chain: str | None = None,
) -> Job | None:
    """Find the most recent completed company job with a contract_inventory artifact.

    When *chain* is given, only jobs whose ``request["chain"]`` matches are
    considered, preventing cross-chain inventory contamination.
    """
    stmt = (
        select(Job)
        .where(
            func.lower(Job.company) == company.lower(),
            Job.status == JobStatus.completed,
            Job.stage == JobStage.done,
        )
        .order_by(Job.updated_at.desc())
    )
    # Company/root jobs are address-less, so ``jobs.chain_id`` is NULL for them
    # (M0.2's CHECK requires chain_id only for address-scoped rows). Their chain
    # identity lives solely in ``request->>'chain'``, so the SQL-side chain
    # predicate keys on the JSONB value — an exact-string match that preserves
    # the prior Python-side ``req.get("chain") != chain`` semantics, including
    # excluding candidates whose request omits ``chain`` (NULL != value).
    if chain is not None:
        stmt = stmt.where(Job.request["chain"].as_string() == chain)
    candidates = session.execute(stmt).scalars().all()
    for candidate in candidates:
        if exclude_job_id and candidate.id == exclude_job_id:
            continue
        art = session.execute(
            select(Artifact).where(Artifact.job_id == candidate.id, Artifact.name == "contract_inventory").limit(1)
        ).scalar_one_or_none()
        if art:
            return candidate
    return None


def find_existing_job_for_address(session: Session, address: str, chain: str | None = None) -> Job | None:
    """Find a non-failed job for *address* (and *chain*), case-insensitive.

    When *chain* is given, only jobs whose ``request["chain"]`` matches are
    returned, so an Ethereum job won't suppress a Base job at the same address.
    """
    stmt = select(Job).where(
        func.lower(Job.address) == address.lower(),
        Job.status != JobStatus.failed,
    )
    # SQL-side chain filtering on ``jobs.chain_id`` (invariant 1). The M0.2
    # backfill populated every address-scoped row, so this is total;
    # ``derive_job_chain_id`` resolves the caller's chain string to the stored
    # id (unknown/missing → 1), matching the dual-write.
    if chain is not None:
        stmt = stmt.where(Job.chain_id == derive_job_chain_id(chain, address))
    return session.execute(stmt.limit(1)).scalar_one_or_none()


def is_known_proxy(session: Session, address: str, chain: str | None = None) -> bool:
    """Return True if *address* (on *chain*) has been classified as a proxy in any prior analysis."""
    stmt = select(Contract).where(
        func.lower(Contract.address) == address.lower(),
        Contract.is_proxy.is_(True),
    )
    if chain is not None:
        # Mainnet-coalesced so a mainnet lookup matches legacy NULL-chain rows;
        # a non-mainnet lookup stays isolated.
        stmt = stmt.where(
            func.lower(func.coalesce(Contract.chain, "ethereum")) == _mainnet_coalesced_chain(canonical_chain(chain))
        )
    return session.execute(stmt.limit(1)).scalar_one_or_none() is not None


def copy_static_cache(session: Session, source_job_id: Any, target_job_id: Any) -> int | None:
    """Copy all cached static data from *source_job_id* to *target_job_id*.

    Copies:
    - ``contracts`` row (immutable fields only; proxy fields left as defaults)
    - ``source_files`` rows
    - ``contract_summaries`` and ``role_definitions``
      rows (linked to the new contract row)
    - Static artifacts (``contract_analysis``, ``control_tracking_plan``,
      ``predicate_trees``, ``effects``, ``static_dependencies``,
      ``enrichment_cache``)

    The source contract is looked up by (address, chain) rather than by
    ``job_id`` so that subsequent cache copies still work after a prior copy
    reassigned the Contract row.

    Returns the new ``Contract.id`` on success, or ``None`` on failure.
    """
    # Guard: if the target already has a contract row, return early.
    existing = session.execute(select(Contract).where(Contract.job_id == target_job_id).limit(1)).scalar_one_or_none()
    if existing:
        return existing.id

    # Resolve the source job's address and chain so we can find the Contract
    # by its natural key (address, chain) rather than by job_id.  A prior
    # copy_static_cache may have reassigned the Contract row's job_id to a
    # different target, so job_id lookup is unreliable after the first copy.
    src_job = session.get(Job, source_job_id)
    if not src_job or not src_job.address:
        return None

    src_req = src_job.request if isinstance(src_job.request, dict) else {}
    src_chain = src_req.get("chain")

    # Join ContractSummary so we copy a summaried row, not a stub (mirrors find_completed_static_cache).
    src_contract_stmt = (
        select(Contract)
        .join(ContractSummary, ContractSummary.contract_id == Contract.id)
        .where(func.lower(Contract.address) == src_job.address.lower())
    )
    if src_chain is not None:
        # Mainnet-coalesced so a mainnet lookup matches legacy NULL-chain rows;
        # a non-mainnet lookup stays isolated.
        src_contract_stmt = src_contract_stmt.where(
            func.lower(func.coalesce(Contract.chain, "ethereum"))
            == _mainnet_coalesced_chain(canonical_chain(src_chain))
        )
    src_contract = session.execute(src_contract_stmt.limit(1)).scalar_one_or_none()
    if not src_contract:
        return None

    # The unique constraint on (address, chain) means src_contract IS the
    # only Contract for this address/chain.  Reassign it to the target job.
    src_contract.job_id = target_job_id

    # Save the current proxy state so _check_proxy_cache can compare it
    # against the live on-chain implementation to decide whether
    # re-classification is needed.  The Contract row keeps its proxy
    # fields intact — zeroing them would corrupt data for the old
    # completed job that also references this row via address lookup.
    _cached_proxy_state = {
        "is_proxy": src_contract.is_proxy,
        "proxy_type": src_contract.proxy_type,
        "implementation": src_contract.implementation,
        "beacon": src_contract.beacon,
        "admin": src_contract.admin,
    }
    store_artifact(session, target_job_id, "cached_proxy_state", data=_cached_proxy_state)

    session.flush()
    new_contract = src_contract

    storage = get_storage_client()

    # --- source files ---
    src_files = session.execute(select(SourceFile).where(SourceFile.job_id == source_job_id)).scalars().all()
    for sf in src_files:
        if sf.storage_key and storage is not None:
            new_key = source_file_key(target_job_id, sf.path)
            storage.copy(sf.storage_key, new_key)
            session.add(SourceFile(job_id=target_job_id, path=sf.path, content=None, storage_key=new_key))
        else:
            copy_row(session, sf, job_id=target_job_id)

    # --- artifacts (static + seed) ---
    src_artifacts = (
        session.execute(
            select(Artifact).where(
                Artifact.job_id == source_job_id,
                Artifact.name.in_(_STATIC_ARTIFACT_NAMES | _SEED_ARTIFACT_NAMES),
            )
        )
        .scalars()
        .all()
    )
    for art in src_artifacts:
        if art.storage_key and storage is not None:
            new_key = artifact_key(target_job_id, art.name)
            storage.copy(art.storage_key, new_key)
            stmt = pg_insert(Artifact).values(
                job_id=target_job_id,
                name=art.name,
                data=None,
                text_data=None,
                storage_key=new_key,
                stored_object_size_bytes=art.stored_object_size_bytes,
                content_type=art.content_type,
            )
            stmt = stmt.on_conflict_do_update(
                constraint="uq_artifact_job_name",
                set_={
                    "data": None,
                    "text_data": None,
                    "storage_key": stmt.excluded.storage_key,
                    "stored_object_size_bytes": stmt.excluded.stored_object_size_bytes,
                    "content_type": stmt.excluded.content_type,
                },
            )
            session.execute(stmt)
        else:
            store_artifact(session, target_job_id, art.name, data=art.data, text_data=art.text_data)

    session.commit()
    return new_contract.id


# Code-plane artifacts safe to reuse across a same-source deployment. Unlike the
# same-chain ``copy_static_cache`` set, this EXCLUDES ``static_dependencies`` and
# ``enrichment_cache`` (dependency addresses / Etherscan enrichment differ per
# chain and are re-derived by the static/discovery stage) and every
# ``_SEED_ARTIFACT_NAMES`` member (dynamic_dependencies / classifications /
# upgrade_history are on-chain-derived and MERGED on re-run — cross-chain merge
# would be wrong). ``contract_analysis`` / ``control_tracking_plan`` carry the one
# deployment-specific field (the contract address), which is re-stamped on copy.
_CROSS_CHAIN_STATIC_ARTIFACTS = frozenset({"contract_analysis", "control_tracking_plan", "predicate_trees", "effects"})


def copy_static_cache_cross_chain(
    session: Session,
    source_job_id: Any,
    target_job_id: Any,
    *,
    target_address: str,
) -> int | None:
    """Reuse a donor job's CODE plane for a same-source deployment on another chain.

    Unlike :func:`copy_static_cache` (which reassigns the donor's Contract row —
    correct only same-chain), this leaves the donor untouched and copies onto the
    target's OWN Contract row (already created per-chain by discovery, with the
    right address/chain/deployer/proxy state). It copies only source-derived
    artifacts, re-stamping the contract address in ``contract_analysis`` /
    ``control_tracking_plan`` so resolution reads the target deployment's state,
    and it copies the summary + role definitions (the static worker skips
    ``_write_analysis_tables`` on a cache hit). The STATE plane (proxy impl,
    controllers, balances, events, monitoring) is untouched and resolved per
    ``(chain, address)`` downstream.

    Returns the target ``Contract.id`` on success, or ``None`` if the target has
    no contract row or the donor lacks the expected artifacts.
    """
    from db.models import RoleDefinition

    target_contract = session.execute(
        select(Contract).where(Contract.job_id == target_job_id).limit(1)
    ).scalar_one_or_none()
    if target_contract is None:
        return None

    src_job = session.get(Job, source_job_id)
    if src_job is None or not src_job.address:
        return None

    # Chain-qualified on the donor job's own chain: a CREATE2 same-address
    # deployment on another chain can carry different source, and its
    # summary/roles must never be the ones copied.
    donor_contract = session.execute(
        select(Contract)
        .join(ContractSummary, ContractSummary.contract_id == Contract.id)
        .where(
            func.lower(Contract.address) == src_job.address.lower(),
            func.lower(func.coalesce(Contract.chain, "ethereum")) == _mainnet_coalesced_chain(_job_chain_name(src_job)),
        )
        .limit(1)
    ).scalar_one_or_none()
    if donor_contract is None:
        return None

    target_addr_norm = target_address.lower()

    # --- summary + role definitions (source-level; re-linked to target) ---
    donor_summary = session.execute(
        select(ContractSummary).where(ContractSummary.contract_id == donor_contract.id).limit(1)
    ).scalar_one_or_none()
    if (
        donor_summary is not None
        and not session.execute(
            select(ContractSummary).where(ContractSummary.contract_id == target_contract.id).limit(1)
        ).scalar_one_or_none()
    ):
        copy_row(session, donor_summary, contract_id=target_contract.id)

    existing_roles = session.execute(
        select(RoleDefinition).where(RoleDefinition.contract_id == target_contract.id).limit(1)
    ).scalar_one_or_none()
    if not existing_roles:
        donor_roles = (
            session.execute(select(RoleDefinition).where(RoleDefinition.contract_id == donor_contract.id))
            .scalars()
            .all()
        )
        for rd in donor_roles:
            copy_row(session, rd, contract_id=target_contract.id)

    # --- code-plane artifacts (re-stamp the deployment address) ---
    for name in _CROSS_CHAIN_STATIC_ARTIFACTS:
        payload = get_artifact(session, source_job_id, name)
        if payload is None:
            continue
        if name == "contract_analysis" and isinstance(payload, dict) and isinstance(payload.get("subject"), dict):
            payload = {**payload, "subject": {**payload["subject"], "address": target_addr_norm}}
        elif name == "control_tracking_plan" and isinstance(payload, dict):
            payload = {**payload, "contract_address": target_addr_norm}
        store_artifact(session, target_job_id, name, data=payload)

    session.commit()
    return target_contract.id
