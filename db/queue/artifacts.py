"""Artifact and source-file storage (inline + object-storage backed)."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy import update as sa_update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.models import Artifact, Job, SourceFile
from db.storage import (
    StorageError,
    StorageKeyAbsent,
    StorageKeyMissing,
    artifact_key,
    content_shortfall,
    deserialize_artifact,
    get_storage_client,
    serialize_artifact,
    source_file_key,
)

logger = logging.getLogger("db.queue")


def count_analysis_children(session: Session, root_job_id: str) -> int:
    """Count analysis jobs (jobs with an address) linked to a root job."""
    from sqlalchemy import func

    count = (
        session.execute(
            select(func.count(Job.id)).where(
                Job.address.isnot(None),
                Job.request["root_job_id"].as_string() == root_job_id,
            )
        ).scalar()
        or 0
    )
    return count


def _artifact_row_to_value(artifact: Artifact) -> dict | list | str | None:
    """Resolve an Artifact row to its decoded payload (handles inline + storage).

    Three outcomes, deliberately distinguishable:
      * a value — the body was read;
      * ``StorageKeyMissing`` — the row names a key and no object exists at any
        candidate for it (proven-absent);
      * ``StorageKeyAbsent`` — the row names no key and holds no inline body, so
        whether a body exists is not determined.
    ``None`` is returned only when the row genuinely stores a null payload.
    """
    if artifact.storage_key:
        client = get_storage_client()
        if client is None:
            raise RuntimeError(
                f"Artifact {artifact.name} on job {artifact.job_id} has storage_key but storage is not configured"
            )
        body = client.get(artifact.storage_key)
        return deserialize_artifact(body, artifact.content_type)
    if artifact.data is not None:
        return artifact.data
    if artifact.text_data is not None:
        return artifact.text_data
    raise StorageKeyAbsent(f"Artifact {artifact.name} on job {artifact.job_id} has no storage_key and no inline body")


def _mirror_contract_flags_to_job(session: Session, job_id: Any, name: str, data: Any) -> None:
    """Mirror ``contract_flags.is_proxy`` onto ``Job.is_proxy`` so /api/jobs
    can answer the proxy-flag question without resolving the artifact body."""
    if name != "contract_flags" or not isinstance(data, dict):
        return
    is_proxy = data.get("is_proxy") is True
    session.execute(sa_update(Job).where(Job.id == job_id).values(is_proxy=is_proxy))


def store_artifact(session: Session, job_id: Any, name: str, data: Any = None, text_data: str | None = None) -> None:
    """Upsert an artifact for a job (unique on job_id + name).

    When ``ARTIFACT_STORAGE_*`` env vars are set, the body is written to object
    storage and only metadata (storage_key, stored_object_size_bytes, content_type) is stored
    in Postgres. Otherwise, the body lives inline in ``data`` / ``text_data``.

    Each publication has a unique immutable body key. Failed publication can
    delete only its own body; a competing winner's pointer remains readable.
    """
    client = get_storage_client()
    if client is not None:
        body, content_type = serialize_artifact(data, text_data)
        key = artifact_key(job_id, name)

        client.put(key, body, content_type, metadata={"artifact_name": name, "job_id": str(job_id)})
        stmt = pg_insert(Artifact).values(
            job_id=job_id,
            name=name,
            data=None,
            text_data=None,
            storage_key=key,
            stored_object_size_bytes=len(body),
            content_type=content_type,
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
        try:
            session.execute(stmt)
            _mirror_contract_flags_to_job(session, job_id, name, data)
            session.commit()
        except Exception:
            session.rollback()
            try:
                client.delete(key)
            except StorageError:
                logger.warning("Failed to clean up orphan storage object %s", key)
            raise
        return

    stmt = pg_insert(Artifact).values(
        job_id=job_id,
        name=name,
        data=data,
        text_data=text_data,
    )
    stmt = stmt.on_conflict_do_update(
        constraint="uq_artifact_job_name",
        set_={
            "data": stmt.excluded.data,
            "text_data": stmt.excluded.text_data,
            "storage_key": None,
            "stored_object_size_bytes": None,
            "content_type": None,
        },
    )
    session.execute(stmt)
    _mirror_contract_flags_to_job(session, job_id, name, data)
    session.commit()


def get_artifact(session: Session, job_id: Any, name: str) -> dict | list | str | None:
    """Read an artifact by job_id and name."""
    stmt = select(Artifact).where(Artifact.job_id == job_id, Artifact.name == name)
    artifact = session.execute(stmt).scalar_one_or_none()
    if artifact is None:
        return None
    return _artifact_row_to_value(artifact)


def get_all_artifacts(session: Session, job_id: Any) -> dict[str, Any]:
    """Read all artifacts for a job. Returns {name: data_or_text}.

    Storage-backed bodies are fetched in parallel via
    ``StorageClient.get_many_results`` so a job with N storage artifacts pays
    one HTTP round-trip's worth of latency instead of N.

    **Fails closed.** If any row's body could not be read this raises rather
    than returning a short dict. A short dict is byte-identical to "this job
    produced fewer artifacts", so a bucket outage rendered as *"this analysis
    has no effective_permissions"* — the substitution of an unanswered question
    for a proven negative.

    That includes the keyless row — a row with no ``storage_key`` and no inline
    body, which ``_artifact_row_to_value`` raises ``StorageKeyAbsent`` for on
    the single-row path. It is the *third* state (nothing was ever addressed,
    so whether a body exists is not determined), and this function used to drop
    it from the returned dict with no exception and no shortfall entry — a
    silence one call away from ``/api/analyses/{id}``, which publishes exactly
    these two maps.

    Which exception says *why*, and the type is load-bearing because it is all
    ``workers.retry_policy`` gets to see: ``StorageContentAbsent`` (every
    shortfall proven absent at every candidate — determined, terminal) or
    ``StorageContentNotDetermined`` (at least one body we could not ask about —
    transient). Both carry ``values`` (what did read) plus the two shortfall
    maps, so a caller that may legitimately degrade opts in explicitly and
    publishes them beside it; see ``services/aggregations/analysis_detail``.
    """
    stmt = select(Artifact).where(Artifact.job_id == job_id)
    artifacts = session.execute(stmt).scalars().all()
    result: dict[str, Any] = {}
    storage_lookups: dict[str, tuple[str, str | None]] = {}
    proven_absent: dict[str, str] = {}
    not_determined: dict[str, str] = {}
    for artifact in artifacts:
        if artifact.storage_key:
            storage_lookups[artifact.name] = (artifact.storage_key, artifact.content_type)
        elif artifact.data is not None:
            result[artifact.name] = artifact.data
        elif artifact.text_data is not None:
            result[artifact.name] = artifact.text_data
        else:
            # No key and no inline body: the same row shape ``_artifact_row_to_value``
            # raises ``StorageKeyAbsent`` for. Not determined, never absent —
            # dropping it here made a row that exists and a name the job never
            # emitted the same answer.
            not_determined[artifact.name] = (
                "row records no storage_key and holds no inline body — whether a body exists is not determined"
            )

    if storage_lookups:
        client = get_storage_client()
        if client is None:
            raise RuntimeError(f"job {job_id} has artifacts with storage_key but storage is not configured")
        reads = client.get_many_results([key for key, _ in storage_lookups.values()])
        for name, (key, content_type) in storage_lookups.items():
            read = reads.get(key)
            if read is None or not read.read:
                # ``BlobRead`` already separated "the bucket answered, and holds
                # no such object" from "the bucket could not be asked". Keep them
                # in separate maps: which one it is decides both what the API may
                # publish and whether the job is worth retrying.
                if read is not None and read.proven_absent:
                    proven_absent[name] = f"no object at any candidate for {key}"
                else:
                    not_determined[name] = f"could not read {key}: {read.error if read is not None else 'not fetched'}"
                continue
            assert read.body is not None
            value = deserialize_artifact(read.body, content_type)
            if value is not None:
                result[name] = value

    short = {**proven_absent, **not_determined}
    if short:
        logger.error(
            "get_all_artifacts: job %s has %d/%d artifact bodies unread (%d proven absent, %d not determined): %s",
            job_id,
            len(short),
            len(artifacts),
            len(proven_absent),
            len(not_determined),
            ", ".join(sorted(short)),
        )
        raise content_shortfall(
            f"job {job_id}: {len(short)}/{len(artifacts)} artifact bodies could not be read "
            f"({len(proven_absent)} proven absent, {len(not_determined)} not determined)",
            values=result,
            proven_absent=proven_absent,
            not_determined=not_determined,
        )

    return result


def store_source_files(session: Session, job_id: Any, files: dict[str, str]) -> None:
    """Bulk insert source files for a job (replaces existing).

    When object storage is configured, every body is uploaded first with the
    path carried in user-metadata (so the path is recoverable from storage
    alone). Only after all uploads succeed do we swap the DB rows. If any
    upload fails, already-uploaded objects are deleted so the bucket does not
    accumulate orphans pointing at nothing.
    """
    client = get_storage_client()
    if client is None:
        session.query(SourceFile).filter(SourceFile.job_id == job_id).delete()
        for path, content in files.items():
            session.add(SourceFile(job_id=job_id, path=path, content=content))
        session.commit()
        return

    # Fan out the per-file uploads — Etherscan-verified contracts often have
    # 30-100 source files and the prior sequential loop was paying one S3/MinIO
    # RTT per file on the static-stage critical path. Threading-only: each
    # ``client.put`` is an independent HTTP request to object storage with no
    # shared session state.
    from services.concurrency import parallel_map

    items = list(files.items())

    def _upload(item: tuple[str, str]) -> tuple[str, str]:
        path, content = item
        key = source_file_key(job_id, path)
        client.put(
            key,
            content.encode("utf-8"),
            "text/plain; charset=utf-8",
            metadata={"path": path, "job_id": str(job_id)},
        )
        return path, key

    upload_results = parallel_map(_upload, items)
    entries: list[tuple[str, str]] = []
    uploaded_keys: list[str] = []
    failure: BaseException | None = None
    for _item, outcome in upload_results:
        if isinstance(outcome, BaseException):
            if failure is None:
                failure = outcome
            continue
        path, key = outcome
        entries.append((path, key))
        uploaded_keys.append(key)

    if failure is not None:
        for key in uploaded_keys:
            try:
                client.delete(key)
            except StorageError:
                logger.warning("Failed to clean up orphan source file object %s", key)
        raise failure

    try:
        # All uploads succeeded — swap DB rows atomically.
        session.query(SourceFile).filter(SourceFile.job_id == job_id).delete()
        for path, key in entries:
            session.add(SourceFile(job_id=job_id, path=path, content=None, storage_key=key))
        session.commit()
    except Exception:
        session.rollback()
        for key in uploaded_keys:
            try:
                client.delete(key)
            except StorageError:
                logger.warning("Failed to clean up orphan source file object %s", key)
        raise


def get_source_files(session: Session, job_id: Any) -> dict[str, str]:
    """Returns {relative_path: file_content} for all source files of a job.

    **Fails closed** on an unreadable body, raising ``StorageContentAbsent``
    (every unread body proven absent at every candidate — determined, terminal)
    or ``StorageContentNotDetermined`` (at least one we could not ask about —
    transient), each carrying ``values`` (the files that did read) plus the
    ``proven_absent`` / ``not_determined`` maps of path → why.

    A row recording neither a key nor inline content is counted as
    ``not_determined`` for the same reason: the row is evidence the path
    belongs to the contract, and nothing was ever addressed for it.

    Silently returning the short dict made "this contract has no source" and
    "every body failed to load" the same answer, and the consumers act on it:
    ``workers.static_worker`` compiles whatever it is handed, so a partial read
    became a static analysis over a partial contract with no record that
    anything was missing.
    """
    stmt = select(SourceFile).where(SourceFile.job_id == job_id)
    rows = session.execute(stmt).scalars().all()
    out: dict[str, str] = {}
    client = get_storage_client()

    storage_rows: list[tuple[str, str]] = []
    keyless: dict[str, str] = {}
    for row in rows:
        if row.storage_key:
            if client is None:
                raise RuntimeError(
                    f"SourceFile {row.path} on job {row.job_id} has storage_key but storage is not configured"
                )
            storage_rows.append((row.path, row.storage_key))
        elif row.content is not None:
            out[row.path] = row.content
        else:
            # Neither a key nor a body: the row exists, so this path is part of
            # the contract, but nothing was ever addressed for it. Not
            # determined. Dropping it handed the static worker a source tree
            # that silently omits a file — the same shape as the storage
            # shortfall below, one branch earlier.
            keyless[row.path] = "row records no storage_key and holds no inline content — content is not determined"

    if not storage_rows:
        if keyless:
            logger.error(
                "get_source_files: job %s read %d/%d source files; %d rows record neither key nor content",
                job_id,
                len(out),
                len(rows),
                len(keyless),
            )
            raise content_shortfall(
                f"job {job_id}: {len(keyless)}/{len(rows)} source bodies could not be read "
                f"(0 proven absent, {len(keyless)} not determined)",
                values=out,
                proven_absent=None,
                not_determined=keyless,
            )
        return out

    # Fan out the storage GETs the same way ``store_source_files`` fans out
    # the PUTs — these blocked the static + resolution + policy stages on
    # 30-100 sequential MinIO/S3 RTTs each.
    from services.concurrency import parallel_map

    # Capture into a non-None local so the closure's type narrows past pyright
    # (the loop above already raised when client was None for any storage_row).
    storage_client = client
    assert storage_client is not None

    def _fetch(item: tuple[str, str]) -> tuple[str, str | StorageError]:
        # Returns the body, or the storage error itself — the caller sorts by
        # error type. Flattening a lost object and an unreachable bucket into
        # one "unreadable" here is what made the whole read report as transient
        # while the same key read directly reported terminal.
        path, key = item
        try:
            return path, storage_client.get(key).decode("utf-8")
        except StorageError as exc:
            logger.error("get_source_files: job %s path %s unreadable: %s", job_id, path, exc)
            return path, exc

    fetch_results = parallel_map(_fetch, storage_rows)
    proven_absent: dict[str, str] = {}
    not_determined: dict[str, str] = dict(keyless)
    for item, outcome in fetch_results:
        if isinstance(outcome, BaseException):
            raise outcome
        path, content = outcome
        if isinstance(content, StorageKeyMissing):
            proven_absent[path] = f"no object at any candidate for {item[1]}"
            continue
        if isinstance(content, StorageError):
            not_determined[path] = f"could not read {item[1]}: {content}"
            continue
        out[path] = content
    short = {**proven_absent, **not_determined}
    if short:
        logger.error(
            "get_source_files: job %s read %d/%d source files; %d bodies unread (%d proven absent, %d not determined)",
            job_id,
            len(out),
            len(rows),
            len(short),
            len(proven_absent),
            len(not_determined),
        )
        raise content_shortfall(
            f"job {job_id}: {len(short)}/{len(rows)} source bodies could not be read "
            f"({len(proven_absent)} proven absent, {len(not_determined)} not determined)",
            values=out,
            proven_absent=proven_absent,
            not_determined=not_determined,
        )
    return out
