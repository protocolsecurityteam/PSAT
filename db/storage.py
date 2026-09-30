"""Object storage client for artifact bodies (Fly Tigris in prod, minio in dev/test)."""

from __future__ import annotations

import contextvars
import functools
import hashlib
import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any
from uuid import UUID

logger = logging.getLogger(__name__)

JSON_CONTENT_TYPE = "application/json"
TEXT_CONTENT_TYPE = "text/plain; charset=utf-8"
DEFAULT_PRESIGN_TTL = 300

_VALID_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class StorageError(RuntimeError): ...


class StorageUnavailable(StorageError):
    """Storage backend unreachable or misconfigured."""


class StorageKeyMissing(StorageError):
    """The bucket holds no object at the requested key: proven absent, unlike ``StorageKeyAbsent`` (no key to ask
    about). ``routers.analyses`` answers 404 for this and 503 for that; ``workers.retry_policy`` treats this as
    terminal and that as transient. ``tried`` lists every candidate key requested (``storage_key_candidates``).
    """

    def __init__(self, key: str, tried: list[str] | None = None) -> None:
        self.key = key
        self.tried = list(tried) if tried else [key]
        super().__init__(f"no object at key {key!r} (tried: {', '.join(self.tried)})")


class StorageKeyAbsent(StorageError):
    """The row records no storage key, so nothing was requested and existence is not determined.

    Collapsing this with ``StorageKeyMissing`` once made thousands of unreadable rows read as empty.

    ``routers.analyses`` answers 503 with ``X-PSAT-Artifact-State: not_determined`` (never 404),
    ``workers.retry_policy`` treats it as transient, and ``db.queue.get_all_artifacts`` reports it in
    ``not_determined``.

    Reachable (``store_artifact`` with no payload and no storage backend) and tested, though no current row has this
    shape. Keyless ``contract_materializations`` cells don't reach it (``_hydrate`` reads inline first).
    """


class StorageContentIncomplete(StorageError):
    """A collection read couldn't return a body for every row.

    Raised instead of returning a short collection, which would look like the rows don't exist. ``values`` has what did
    read, for callers that can degrade explicitly.

    The shortfall is split: ``proven_absent`` (the bucket answered for every candidate; retrying won't help) and
    ``not_determined`` (couldn't ask or parse; only a retry can resolve it). The subclasses carry the same split in the
    type, for consumers that only see the type.
    """

    def __init__(
        self,
        message: str,
        *,
        values: Any = None,
        proven_absent: dict[str, str] | None = None,
        not_determined: dict[str, str] | None = None,
    ) -> None:
        self.values = values
        self.proven_absent = dict(proven_absent or {})
        self.not_determined = dict(not_determined or {})
        super().__init__(message)


class StorageContentAbsent(StorageContentIncomplete):
    """Every shortfall was proven absent: determined, so terminal for ``workers.retry_policy``, like
    ``StorageKeyMissing``. Deliberately not a subclass of ``StorageContentNotDetermined``.
    """


class StorageContentNotDetermined(StorageContentIncomplete):
    """At least one body's existence couldn't be established (unreachable, unconfigured, unparseable). Transient."""


def content_shortfall(
    message: str,
    *,
    values: Any = None,
    proven_absent: dict[str, str] | None = None,
    not_determined: dict[str, str] | None = None,
) -> StorageContentIncomplete:
    """The shortfall exception matching its cause: any not-determined entry makes the whole read not-determined."""
    if not_determined:
        return StorageContentNotDetermined(
            message, values=values, proven_absent=proven_absent, not_determined=not_determined
        )
    return StorageContentAbsent(message, values=values, proven_absent=proven_absent, not_determined=None)


@dataclass(frozen=True)
class BlobRead:
    """One key's outcome in a batch fetch: ``body`` (read), ``StorageKeyMissing`` (proven absent at every candidate),
    or another error (not determined; never render as absence).
    """

    body: bytes | None = None
    error: StorageError | None = None

    @property
    def read(self) -> bool:
        return self.body is not None

    @property
    def proven_absent(self) -> bool:
        return isinstance(self.error, StorageKeyMissing)

    @property
    def not_determined(self) -> bool:
        return self.error is not None and not isinstance(self.error, StorageKeyMissing)


_KEY_ROOTS = frozenset(
    {
        "artifacts",  # artifact_key()
        "source_files",  # source_file_key()
        "contract_materializations",  # services/static materialization blobs
        "audits",  # services/audits/** (never prefixed — the control)
        "exa-cache",  # services/clients/exa._CACHE_KEY_PREFIX
        "tavily-cache",  # services/clients/tavily._CACHE_KEY_PREFIX
        "protocol_scores",  # protocol_score_document_key()
    }
)

# Preview environments scope the shared bucket with ``pr-<n>/``.
_PREVIEW_PREFIX_RE = re.compile(r"^pr-\d+$")


def _safe_name(name: str) -> str:
    if not _VALID_NAME_RE.match(name):
        raise ValueError(f"Unsafe artifact name for storage key: {name!r}")
    return name


def _key_prefix() -> str:
    """Optional key prefix scoping preview envs in a shared bucket (e.g.

    ``pr-123/``), normalized to empty or a single trailing slash.
    """
    prefix = os.environ.get("ARTIFACT_STORAGE_PREFIX", "").strip().strip("/")
    return f"{prefix}/" if prefix else ""


def storage_key_candidates(key: str) -> list[str]:
    """Every bucket key a DB-recorded ``key`` may resolve to.

    Keys include the writing environment's ``ARTIFACT_STORAGE_PREFIX``, so reading another environment's rows also tries
    the key with that scope stripped. Only a leading segment that looks like an environment scope (not one of our
    namespaces) is removable, so a genuinely absent object stays absent. Read-path only; DB values aren't rewritten.
    """
    if not key:
        return []
    head, sep, tail = key.partition("/")
    if not sep or head in _KEY_ROOTS or not tail:
        return [key]
    env_prefix = _key_prefix().rstrip("/")
    if not (_PREVIEW_PREFIX_RE.match(head) or (env_prefix and head == env_prefix)):
        return [key]
    if tail.partition("/")[0] not in _KEY_ROOTS:
        return [key]
    return [key, tail]


def artifact_key(job_id: UUID | str, name: str) -> str:
    return f"{_key_prefix()}artifacts/{job_id}/{_safe_name(name)}"


def source_file_key(job_id: UUID | str, path: str) -> str:
    """Deterministic key for a source file (path hashed to avoid unsafe characters)."""
    digest = hashlib.sha1(path.encode("utf-8")).hexdigest()
    return f"{_key_prefix()}source_files/{job_id}/{digest}"


def protocol_score_document_key(protocol_id: int, token: str) -> str:
    """Key for a spilled ``protocol_scores`` document.

    ``token`` is minted per row because two folds can share a ``computed_at`` tick, and a collision would point the
    newer row at the older body.
    """
    return f"{_key_prefix()}protocol_scores/{int(protocol_id)}/{_safe_name(token)}.json"


def serialize_artifact(data: Any | None, text_data: str | None) -> tuple[bytes, str]:
    if data is not None:
        body = json.dumps(data, default=str).encode("utf-8")
        return body, JSON_CONTENT_TYPE
    if text_data is not None:
        return text_data.encode("utf-8"), TEXT_CONTENT_TYPE
    return b"", TEXT_CONTENT_TYPE


def deserialize_artifact(body: bytes, content_type: str | None) -> dict | list | str:
    if content_type and content_type.startswith("application/json"):
        return json.loads(body.decode("utf-8"))
    return body.decode("utf-8")


class StorageClient:
    """Thin wrapper over an S3-compatible backend (Tigris, minio, S3, R2)."""

    def __init__(
        self,
        endpoint: str,
        bucket: str,
        access_key: str,
        secret_key: str,
        region: str = "auto",
    ) -> None:
        try:
            import boto3
            from botocore.config import Config
        except ImportError as exc:
            raise StorageUnavailable(
                "boto3 is required for object storage; install it (uv sync) or unset ARTIFACT_STORAGE_*"
            ) from exc

        self.bucket = bucket
        self.endpoint = endpoint
        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
            config=Config(
                signature_version="s3v4",
                s3={"addressing_style": "path"},
                # Tigris TLS handshakes exceed 2s at p99 under load.
                connect_timeout=10,
                read_timeout=5,
                # Botocore's standard retry for transient timeouts, before surfacing StorageUnavailable.
                retries={"max_attempts": 3, "mode": "standard"},
                # The default 10 is too small for the get_many fan-out plus concurrent worker I/O and caused connection
                # churn.
                max_pool_connections=64,
            ),
        )

    def put(
        self,
        key: str,
        body: bytes,
        content_type: str,
        metadata: dict[str, str] | None = None,
    ) -> None:
        from botocore.exceptions import BotoCoreError, ClientError

        params: dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": key,
            "Body": body,
            "ContentType": content_type,
        }
        if metadata:
            params["Metadata"] = metadata
        try:
            self._client.put_object(**params)
        except (BotoCoreError, ClientError) as exc:
            raise StorageUnavailable(f"put_object failed for {key}: {exc}") from exc

    def _get_one(self, key: str) -> bytes:
        from botocore.exceptions import BotoCoreError, ClientError

        try:
            response = self._client.get_object(Bucket=self.bucket, Key=key)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {"NoSuchKey", "404"}:
                raise StorageKeyMissing(key) from exc
            raise StorageUnavailable(f"get_object failed for {key}: {exc}") from exc
        except BotoCoreError as exc:
            raise StorageUnavailable(f"get_object transport error for {key}: {exc}") from exc
        return response["Body"].read()

    def get(self, key: str) -> bytes:
        """Fetch a key via ``storage_key_candidates``.

        Transport failures propagate immediately; only a 404 moves to the next candidate.
        """
        if not key:
            raise StorageKeyAbsent("storage read requested with no key")
        candidates = storage_key_candidates(key)
        for candidate in candidates:
            try:
                return self._get_one(candidate)
            except StorageKeyMissing:
                continue
        raise StorageKeyMissing(key, candidates)

    def get_many_results(self, keys: list[str]) -> dict[str, BlobRead]:
        """Fetch keys concurrently, returning a ``BlobRead`` per key (read, proven absent, or not determined).

        Anything publishing results as evidence must use this rather than ``get_many``. The boto3 client is thread-safe.
        """
        if not keys:
            return {}
        unique = list(dict.fromkeys(keys))

        def _fetch(k: str) -> tuple[str, BlobRead]:
            try:
                return k, BlobRead(body=self.get(k))
            except StorageKeyMissing as exc:
                # A missing object means the DB row asserts a key the bucket doesn't have; never silent.
                logger.error("get_many: %s", exc)
                return k, BlobRead(error=exc)
            except StorageError as exc:
                logger.warning("get_many: transport error fetching %s: %s", k, exc)
                return k, BlobRead(error=exc)

        # Copy the context per key so trace/job ids reach each call's logs.
        def _fetch_with_ctx(k: str) -> tuple[str, BlobRead]:
            ctx = contextvars.copy_context()
            return ctx.run(_fetch, k)

        with ThreadPoolExecutor(max_workers=16) as ex:
            return dict(ex.map(_fetch_with_ctx, unique))

    def get_many(self, keys: list[str]) -> dict[str, bytes | None]:
        """``get_many_results`` with the cause discarded (``None`` for both absent and unreachable).

        Only for callers whose fallback doesn't depend on the cause or publish absence (``/stage_timings``, effects
        selection re-sweeps).
        """
        return {k: r.body for k, r in self.get_many_results(keys).items()}

    def presign(self, key: str, expires_in: int = DEFAULT_PRESIGN_TTL) -> str:
        from botocore.exceptions import BotoCoreError, ClientError

        candidates = storage_key_candidates(key)
        target = candidates[0] if candidates else key
        if len(candidates) > 1:
            # Resolve the candidate here rather than hand out a presigned URL that 404s.
            for candidate in candidates:
                try:
                    self._client.head_object(Bucket=self.bucket, Key=candidate)
                    target = candidate
                    break
                except ClientError:
                    continue
        try:
            return self._client.generate_presigned_url(
                "get_object",
                Params={"Bucket": self.bucket, "Key": target},
                ExpiresIn=expires_in,
            )
        except (BotoCoreError, ClientError) as exc:
            raise StorageUnavailable(f"presign failed for {target}: {exc}") from exc

    def delete(self, key: str) -> None:
        from botocore.exceptions import BotoCoreError, ClientError

        try:
            self._client.delete_object(Bucket=self.bucket, Key=key)
        except (BotoCoreError, ClientError) as exc:
            raise StorageUnavailable(f"delete failed for {key}: {exc}") from exc

    def copy(self, src_key: str, dst_key: str) -> None:
        from botocore.exceptions import BotoCoreError, ClientError

        candidates = storage_key_candidates(src_key)
        last: Exception | None = None
        for candidate in candidates:
            try:
                self._client.copy_object(
                    Bucket=self.bucket,
                    Key=dst_key,
                    CopySource={"Bucket": self.bucket, "Key": candidate},
                )
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code in {"NoSuchKey", "404"}:
                    last = exc
                    continue
                raise StorageUnavailable(f"copy {candidate} -> {dst_key} failed: {exc}") from exc
            except BotoCoreError as exc:
                raise StorageUnavailable(f"copy {candidate} -> {dst_key} failed: {exc}") from exc
        raise StorageKeyMissing(src_key, candidates) from last

    def ensure_bucket(self) -> None:
        from botocore.exceptions import ClientError

        try:
            self._client.head_bucket(Bucket=self.bucket)
        except ClientError:
            self._client.create_bucket(Bucket=self.bucket)

    def health_check(self) -> None:
        from botocore.exceptions import BotoCoreError, ClientError

        try:
            self._client.head_bucket(Bucket=self.bucket)
        except (BotoCoreError, ClientError) as exc:
            raise StorageUnavailable(f"head_bucket failed for {self.bucket}: {exc}") from exc


def _read_env() -> tuple[str | None, str | None, str | None, str | None]:
    return (
        os.environ.get("ARTIFACT_STORAGE_ENDPOINT"),
        os.environ.get("ARTIFACT_STORAGE_BUCKET"),
        os.environ.get("ARTIFACT_STORAGE_ACCESS_KEY"),
        os.environ.get("ARTIFACT_STORAGE_SECRET_KEY"),
    )


@functools.lru_cache(maxsize=1)
def get_storage_client() -> StorageClient | None:
    """A StorageClient if ``ARTIFACT_STORAGE_*`` is set, else None (callers use inline Postgres storage)."""
    endpoint, bucket, access_key, secret_key = _read_env()
    if not (endpoint and bucket and access_key and secret_key):
        logger.info("ARTIFACT_STORAGE_* env vars not all set — artifact bodies will be stored inline in Postgres")
        return None
    return StorageClient(endpoint, bucket, access_key, secret_key)


def reset_client_cache() -> None:
    """Drop the cached client so env is re-read (tests)."""
    get_storage_client.cache_clear()
