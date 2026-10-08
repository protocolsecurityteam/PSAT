"""Artifact and source-file storage (inline and object-storage backed)."""

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
    """Resolve an Artifact row to its payload (inline or storage).

      * a value: the body was read;
      * ``StorageKeyMissing``: no object exists at any candidate for the key (proven absent);
      * ``StorageKeyAbsent``: no key and no inline body (not determined).

    ``None`` only when the row really stores null.
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
    """Mirror ``contract_flags.is_proxy`` onto ``Job.is_proxy`` for /api/jobs."""
    if name != "contract_flags" or not isinstance(data, dict):
        return
    is_proxy = data.get("is_proxy") is True
    session.execute(sa_update(Job).where(Job.id == job_id).values(is_proxy=is_proxy))


def store_artifact(session: Session, job_id: Any, name: str, data: Any = None, text_data: str | None = None) -> None:
    """Upsert an artifact (unique on job_id + name).

    With ``ARTIFACT_STORAGE_*`` set the body goes to object storage and only metadata is stored; otherwise it's inline.
    If the DB write fails after the put, the object is deleted only if the row didn't already exist (a same-key
    overwrite would otherwise break the old row).
    """
    client = get_storage_client()
    if client is not None:
        body, content_type = serialize_artifact(data, text_data)
        key = artifact_key(job_id, name)
        preexisting = session.execute(
            select(Artifact.id).where(Artifact.job_id == job_id, Artifact.name == name).limit(1)
        ).scalar_one_or_none()

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
            if preexisting is None:
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
    stmt = select(Artifact).where(Artifact.job_id == job_id, Artifact.name == name)
    artifact = session.execute(stmt).scalar_one_or_none()
    if artifact is None:
        return None
    return _artifact_row_to_value(artifact)


# The key a successful build of each semantic artifact always carries. A failed build is stored under
# ``<name>_error``; older jobs stored ``{"schema_version": ..., "error": ...}`` under the artifact's own name.
SEMANTIC_PAYLOAD_KEYS = {"predicate_trees": "trees", "effects": "functions"}


def failed_semantic_artifact(name: str, value: Any) -> bool:
    """Whether *value* is a failed ``predicate_trees``/``effects`` build: an ``error`` and no payload."""
    payload_key = SEMANTIC_PAYLOAD_KEYS.get(name)
    return payload_key is not None and isinstance(value, dict) and "error" in value and payload_key not in value


def analysis_reports_failure(analysis: Any) -> bool:
    """Whether a ``contract_analysis`` says one of its semantic builds failed."""
    status = analysis.get("analysis_status") if isinstance(analysis, dict) else None
    return isinstance(status, dict) and status.get("static_analysis_completed") is False


def usable_semantic_artifact(name: str, value: Any) -> dict | None:
    """A read ``predicate_trees``/``effects`` artifact, or ``None`` when it is missing, not an object, or a failed
    build. A failure must read as not determined, never as a contract with no guards or no effects.
    """
    if not isinstance(value, dict) or failed_semantic_artifact(name, value):
        return None
    return value


def get_all_artifacts(session: Session, job_id: Any) -> dict[str, Any]:
    """All artifacts for a job as ``{name: data_or_text}``, fetching storage bodies in parallel.

    Fails closed: an unreadable body (including a keyless row, the third state) raises rather than returning a short
    dict, which would look like the job produced fewer artifacts. ``StorageContentAbsent`` when every shortfall is
    proven absent (terminal), else ``StorageContentNotDetermined`` (transient); ``workers.retry_policy`` classifies by
    type. Both carry ``values`` and the shortfall maps for callers that opt into degrading (see
    ``services/aggregations/analysis_detail``).
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
            # No key and no inline body: not determined, never absent.
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
                # Keep proven-absent and couldn't-ask apart; it decides what the API may publish and whether to retry.
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
    """Replace a job's source files.

    With object storage, every body is uploaded first (path in user metadata), then the DB rows are swapped; on any
    upload failure the uploaded objects are deleted.
    """
    client = get_storage_client()
    if client is None:
        session.query(SourceFile).filter(SourceFile.job_id == job_id).delete()
        for path, content in files.items():
            session.add(SourceFile(job_id=job_id, path=path, content=content))
        session.commit()
        return

    # Parallel uploads (sources often have 30-100 files); each ``put`` is independent.
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
    """``{relative_path: file_content}`` for a job's source files.

    Fails closed on an unreadable body with ``StorageContentAbsent`` (terminal) or ``StorageContentNotDetermined``
    (transient), carrying ``values`` and the ``proven_absent``/``not_determined`` maps. A keyless row counts as not
    determined. A short dict would let ``workers.static_worker`` silently analyse a partial contract.
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
            # The row proves the path belongs to the contract; nothing was addressed for it, so not determined.
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

    # Parallel GETs, mirroring ``store_source_files``.
    from services.concurrency import parallel_map

    # Narrows the type for the closure.
    storage_client = client
    assert storage_client is not None

    def _fetch(item: tuple[str, str]) -> tuple[str, str | StorageError]:
        # Return the error itself so the caller can distinguish lost objects from an unreachable bucket.
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
