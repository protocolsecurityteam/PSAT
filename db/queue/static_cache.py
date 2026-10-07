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
from .artifacts import (
    SEMANTIC_PAYLOAD_KEYS,
    analysis_reports_failure,
    failed_semantic_artifact,
    get_artifact,
    store_artifact,
)

logger = logging.getLogger("db.queue")


# Immutable static artifacts carried by a cache hit; ``predicate_trees``/``effects`` are required by resolution and
# policy.
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

# Copied as a baseline and appended to on later runs.
_SEED_ARTIFACT_NAMES = frozenset(
    {
        "dynamic_dependencies",
        "classifications",
        "upgrade_history",
    }
)

# Resolved live by _resolve_proxy; never carried over from a cached job.
_MUTABLE_CONTRACT_FIELDS = frozenset({"is_proxy", "proxy_type", "implementation", "beacon", "admin"})


def copy_row(session: Session, source: Base, *, exclude: frozenset[str] = frozenset(), **overrides: Any) -> Base:
    """Copy a row as a new detached instance: primary keys and ``server_default`` columns are skipped (unless in
    *overrides*), *exclude* drops more, lists are shallow-copied.
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

    ``jobs.analysis_schema_version`` is stamped only on the fetch path, so cache-hit jobs are NULL, which isn't
    "current". Since ``copy_static_cache`` copies the donor's artifacts verbatim, the donor chain is followed to a
    stamped job. Walked to termination (with a visited set), not a hop budget: chains grow with every re-run of busy
    addresses.
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
            # A DB error would read as "no witnessed era"; record it. Paired with ``record_degraded`` by hand since this
            # module is outside the level-contract checker.
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


def _semantic_bundle_complete(session: Session, job_id: Any) -> bool:
    """Whether a donor holds both semantic artifacts, readable and not a failed build, under an analysis that doesn't
    report a failure.

    A failed build (``<name>_error``, or the older error shape under the artifact's own name) copied into a new job
    would never be rebuilt.
    """
    names = set(
        session.execute(
            select(Artifact.name).where(
                Artifact.job_id == job_id,
                Artifact.name.in_(
                    [*SEMANTIC_PAYLOAD_KEYS, *(f"{name}_error" for name in SEMANTIC_PAYLOAD_KEYS)],
                ),
            )
        ).scalars()
    )
    if not names.issuperset(SEMANTIC_PAYLOAD_KEYS) or any(f"{name}_error" in names for name in SEMANTIC_PAYLOAD_KEYS):
        return False
    for name in ("contract_analysis", *SEMANTIC_PAYLOAD_KEYS):
        try:
            value = get_artifact(session, job_id, name)
        except Exception as exc:
            # Paired with ``record_degraded`` by hand since this module is outside the level-contract checker.
            record_degraded(
                phase="static_cache_donor", exc=exc, context={"donor_job_id": str(job_id), "artifact": name}
            )
            logger.warning(
                "static-cache donor artifact unreadable; the donor is skipped",
                extra={"donor_job_id": str(job_id), "artifact": name, "exc_type": type(exc).__name__},
            )
            return False
        if not isinstance(value, dict) or failed_semantic_artifact(name, value):
            return False
        # A failed claim matcher leaves complete-shaped effects; only the analysis says its claims are missing.
        if name == "contract_analysis" and analysis_reports_failure(value):
            return False
    return True


def find_completed_static_cache(
    session: Session,
    address: str,
    chain: str | None = None,
    source_content_hash: str | None = None,
) -> Job | None:
    """A completed job for *address*/*chain* with all static data (source files, ``contract_analysis``, a summaried
    contract row), or ``None``.

    Looks up the contract by (address, chain), since ``copy_static_cache`` may have reassigned it. If that misses and
    *source_content_hash* is given, falls back to any completed job with the same verified source under the current
    analyzer; the primary path is unchanged.
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
    # Filter on ``jobs.chain_id``.
    if chain is not None:
        stmt = stmt.where(Job.chain_id == derive_job_chain_id(chain, address))
    candidates = session.execute(stmt).scalars().all()

    for candidate in candidates:
        src_count = session.execute(
            select(SourceFile).where(SourceFile.job_id == candidate.id).limit(1)
        ).scalar_one_or_none()
        if not src_count:
            continue

        # By (address, chain), not job_id; the summary join skips stub rows.
        contract_stmt = (
            select(Contract)
            .join(ContractSummary, ContractSummary.contract_id == Contract.id)
            .where(func.lower(Contract.address) == address.lower())
        )
        if chain is not None:
            # Mainnet-coalesced.
            contract_stmt = contract_stmt.where(
                func.lower(func.coalesce(Contract.chain, "ethereum"))
                == _mainnet_coalesced_chain(canonical_chain(chain))
            )
        contract_row = session.execute(contract_stmt.limit(1)).scalar_one_or_none()
        if not contract_row:
            continue

        # Proxies never write ``contract_analysis`` (it's on the impl child), so require ``contract_flags`` for them;
        # otherwise re-discovered proxies always miss.
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

        if not contract_row.is_proxy and not _semantic_bundle_complete(session, candidate.id):
            continue

        return candidate

    # Cross-chain fallback.
    if source_content_hash:
        return _find_static_cache_by_source_hash(session, source_content_hash)

    return None


def _find_static_cache_by_source_hash(session: Session, source_content_hash: str) -> Job | None:
    """The newest completed job with this source hash under the current analyzer and a real analysed root.

    Proxies are never donors.
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
        # Chain-qualified: a same-address deployment on another chain may have different source.
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
        if not _semantic_bundle_complete(session, candidate.id):
            continue
        return candidate
    return None


def find_previous_company_inventory(
    session: Session,
    company: str,
    exclude_job_id: Any = None,
    chain: str | None = None,
) -> Job | None:
    """The newest completed company job with a contract_inventory artifact, filtered by *chain* when given."""
    stmt = (
        select(Job)
        .where(
            func.lower(Job.company) == company.lower(),
            Job.status == JobStatus.completed,
            Job.stage == JobStage.done,
        )
        .order_by(Job.updated_at.desc())
    )
    # Company jobs have NULL ``chain_id``, so match ``request->>'chain'`` exactly (requests without a chain are
    # excluded).
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
    """A non-failed job for *address* (case-insensitive), filtered by *chain* when given."""
    stmt = select(Job).where(
        func.lower(Job.address) == address.lower(),
        Job.status != JobStatus.failed,
        Job.request["effects_resume_work_id"].astext.is_(None),
    )
    if chain is not None:
        stmt = stmt.where(Job.chain_id == derive_job_chain_id(chain, address))
    return session.execute(stmt.limit(1)).scalar_one_or_none()


def is_known_proxy(session: Session, address: str, chain: str | None = None) -> bool:
    stmt = select(Contract).where(
        func.lower(Contract.address) == address.lower(),
        Contract.is_proxy.is_(True),
    )
    if chain is not None:
        # Mainnet-coalesced.
        stmt = stmt.where(
            func.lower(func.coalesce(Contract.chain, "ethereum")) == _mainnet_coalesced_chain(canonical_chain(chain))
        )
    return session.execute(stmt.limit(1)).scalar_one_or_none() is not None


def copy_static_cache(session: Session, source_job_id: Any, target_job_id: Any) -> int | None:
    """Copy cached static data from *source_job_id* to *target_job_id*: the contract row (immutable fields), source
    files, summaries and role definitions, and static artifacts. The source contract is found by (address, chain)
    since earlier copies reassign it. Returns the new ``Contract.id``, or ``None``.
    """
    existing = session.execute(select(Contract).where(Contract.job_id == target_job_id).limit(1)).scalar_one_or_none()
    if existing:
        return existing.id

    # Find the contract by (address, chain); job_id is unreliable after a prior copy.
    src_job = session.get(Job, source_job_id)
    if not src_job or not src_job.address:
        return None

    src_req = src_job.request if isinstance(src_job.request, dict) else {}
    src_chain = src_req.get("chain")

    src_contract_stmt = (
        select(Contract)
        .join(ContractSummary, ContractSummary.contract_id == Contract.id)
        .where(func.lower(Contract.address) == src_job.address.lower())
    )
    if src_chain is not None:
        # Mainnet-coalesced.
        src_contract_stmt = src_contract_stmt.where(
            func.lower(func.coalesce(Contract.chain, "ethereum"))
            == _mainnet_coalesced_chain(canonical_chain(src_chain))
        )
    src_contract = session.execute(src_contract_stmt.limit(1)).scalar_one_or_none()
    if not src_contract:
        return None

    # The only contract for this (address, chain) (unique key); reassign it.
    src_contract.job_id = target_job_id

    # Save proxy state for ``_check_proxy_cache``; the row's fields stay intact for the older job that also references
    # it.
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

    src_files = session.execute(select(SourceFile).where(SourceFile.job_id == source_job_id)).scalars().all()
    for sf in src_files:
        if sf.storage_key and storage is not None:
            new_key = source_file_key(target_job_id, sf.path)
            storage.copy(sf.storage_key, new_key)
            session.add(SourceFile(job_id=target_job_id, path=sf.path, content=None, storage_key=new_key))
        else:
            copy_row(session, sf, job_id=target_job_id)

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


# Code-plane artifacts safe to reuse across chains. Excludes ``static_dependencies``, ``enrichment_cache`` and the seed
# artifacts (chain-specific or merged). ``contract_analysis``/``control_tracking_plan`` have their address re-stamped on
# copy.
_CROSS_CHAIN_STATIC_ARTIFACTS = frozenset({"contract_analysis", "control_tracking_plan", "predicate_trees", "effects"})


def copy_static_cache_cross_chain(
    session: Session,
    source_job_id: Any,
    target_job_id: Any,
    *,
    target_address: str,
) -> int | None:
    """Reuse a donor's code plane for a same-source deployment on another chain.

    Unlike :func:`copy_static_cache` it leaves the donor alone and copies onto the target's own contract row:
    source-derived artifacts (address re-stamped), plus summary and role definitions. State is resolved per ``(chain,
    address)`` downstream. Returns the target ``Contract.id``, or ``None``.
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

    # Chain-qualified to the donor's own chain.
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
