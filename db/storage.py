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


class StorageError(RuntimeError):
    """Base class for storage failures."""


class StorageUnavailable(StorageError):
    """Storage backend is unreachable or misconfigured."""


class StorageKeyMissing(StorageError):
    """A key was requested and the bucket holds no object at it.

    This is *proven-absent for that key* — the second of the three states, never
    "we had no key to try", which is the third and is ``StorageKeyAbsent``. Every
    consumer must keep them apart: ``routers.analyses`` answers 404 for this one
    and 503 for that one, and ``workers.retry_policy`` calls this one terminal
    and that one transient. ``tried`` lists
    every candidate key actually requested (see ``storage_key_candidates``) so
    a reader can tell a one-shot miss from an exhausted fallback.
    """

    def __init__(self, key: str, tried: list[str] | None = None) -> None:
        self.key = key
        self.tried = list(tried) if tried else [key]
        super().__init__(f"no object at key {key!r} (tried: {', '.join(self.tried)})")


class StorageKeyAbsent(StorageError):
    """The row records no storage key at all — nothing was ever requested.

    Distinct from ``StorageKeyMissing``: that one means the bucket was asked
    and answered "not here"; this one means we never had an address to ask
    about, so the content's existence is *not determined*. Collapsing the two
    is what let 8,256 unreadable rows read as empty.

    Because it is the third state, its consumers must treat it as one:
    ``routers.analyses`` answers 503 with ``X-PSAT-Artifact-State:
    not_determined`` (never a 404, which is byte-identical to an artifact the
    job never produced), ``workers.retry_policy`` classifies it transient (only
    a re-run can turn it into a fact), and ``db.queue.get_all_artifacts`` puts
    the row in its ``not_determined`` shortfall map rather than omitting it.

    **Realisation, stated honestly.** Reachable by construction and covered by
    tests, *not* yet realised on a real row: ``store_artifact`` with no payload
    under an unconfigured backend writes ``storage_key`` NULL beside a NULL
    inline body, and ``_artifact_row_to_value`` raises this for exactly that
    row. In the working DB today that shape occurs 0/5770 times in
    ``artifacts`` and 0/2261 times in ``source_files``. That is a lower bound
    on prevalence — one protocol, largely one pipeline run — never a proof the
    class is dead. It is specifically *not* the 21 keyless
    ``contract_materializations`` blob-key cells: those are read through
    ``db.contract_materializations._hydrate``, which returns the inline column
    before any key is requested, so they never reach this class.
    """


class StorageContentIncomplete(StorageError):
    """A collection read could not return a body for every row it was asked about.

    Raised instead of returning a short collection, because a short collection
    is byte-identical to "those rows do not exist" — the exact substitution this
    whole item exists to remove. ``values`` carries what *did* read so a caller
    that can legitimately degrade (an API handler rendering a partial page) can
    do so explicitly and publish the shortfall beside it; a caller that cannot
    (a pipeline stage seeding a witness) simply lets it propagate.

    The shortfall is carried in **two** maps, never one, because the reason a
    body is missing decides what may be done about it:

      * ``proven_absent`` — the bucket was asked about every candidate key and
        holds none of them. Determined; a retry re-asks an answered question.
      * ``not_determined`` — the bucket could not be asked, or could not be
        understood. A retry is the only thing that can turn it into a fact.

    Both map the row's identity (artifact name, source path, materialization
    column) to the detail. The *type* of the exception carries the same split
    for consumers that only get to see the type — see the two subclasses; a
    single class with the cause buried in prose is what let a lost object and an
    unreachable bucket share one retry verdict.
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
    """Every body this read fell short on was proven absent at every candidate.

    The bucket answered. It is a real inconsistency — a row asserts a key the
    bucket does not honour — but it is *determined*, so it is terminal for
    ``workers.retry_policy`` exactly as the single-key ``StorageKeyMissing`` is.
    Not a subclass of ``StorageContentNotDetermined``: a consumer that catches
    "we could not find out" must not silently absorb "we found out, and it is
    gone".
    """


class StorageContentNotDetermined(StorageContentIncomplete):
    """At least one body's existence could not be established.

    The bucket was unreachable, unconfigured, or answered something we could not
    parse. Transient for ``workers.retry_policy``: a stage that re-runs is the
    only thing that can turn this into a fact.
    """


def content_shortfall(
    message: str,
    *,
    values: Any = None,
    proven_absent: dict[str, str] | None = None,
    not_determined: dict[str, str] | None = None,
) -> StorageContentIncomplete:
    """Build the shortfall exception whose *type* matches the shortfall's cause.

    One unanswered question outranks any number of answered ones: if anything is
    not-determined the whole read is not-determined, because a retry might still
    complete it. Only when every shortfall is a proven absence is the read as
    determined as it will ever get.
    """
    if not_determined:
        return StorageContentNotDetermined(
            message, values=values, proven_absent=proven_absent, not_determined=not_determined
        )
    return StorageContentAbsent(message, values=values, proven_absent=proven_absent, not_determined=None)


@dataclass(frozen=True)
class BlobRead:
    """One key's outcome in a batch fetch, with the three states kept apart.

    ``body`` set — read. ``error`` a ``StorageKeyMissing`` — the bucket was
    asked about every candidate key and holds none of them (proven-absent).
    ``error`` anything else — the bucket could not be asked, so the content is
    *not determined* and must never be rendered as absence.
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
        "exa-cache",  # utils/exa._CACHE_KEY_PREFIX
        "tavily-cache",  # utils/tavily._CACHE_KEY_PREFIX
    }
)

# A preview environment scopes the shared bucket with ``pr-<n>/`` (_key_prefix).
_PREVIEW_PREFIX_RE = re.compile(r"^pr-\d+$")


def _safe_name(name: str) -> str:
    """Reject artifact names with path separators or control characters."""
    if not _VALID_NAME_RE.match(name):
        raise ValueError(f"Unsafe artifact name for storage key: {name!r}")
    return name


def _key_prefix() -> str:
    """Optional prefix for every storage key. Used to scope PR-preview envs to
    a shared bucket (e.g. ``pr-123/``) so teardown can wipe one prefix cleanly.

    Normalized to an empty string or a single trailing slash.
    """
    prefix = os.environ.get("ARTIFACT_STORAGE_PREFIX", "").strip().strip("/")
    return f"{prefix}/" if prefix else ""


def storage_key_candidates(key: str) -> list[str]:
    """Every bucket key a DB-recorded ``key`` may legitimately resolve to.

    Keys are recorded in Postgres verbatim, including the writing environment's
    ``ARTIFACT_STORAGE_PREFIX``. Reading those rows from an environment with a
    different prefix (a preview DB restored locally, prod reading a preview
    row) addresses an object that was never written there. The bytes are at the
    same path with the foreign scope removed, so the read path tries that too.

    Stripping is deliberately narrow: only a leading segment that is *not*
    itself one of this codebase's bucket namespaces and that looks like an
    environment scope is removable. ``audits/text/183.txt`` therefore yields
    exactly one candidate — an absent audit object stays absent instead of
    being explained away by a fallback.

    This is a read-path normalisation. DB values are never rewritten.
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
    """Deterministic S3 key for an artifact body."""
    return f"{_key_prefix()}artifacts/{job_id}/{_safe_name(name)}"


def source_file_key(job_id: UUID | str, path: str) -> str:
    """Deterministic S3 key for a source file (path is hashed to avoid unsafe chars)."""
    digest = hashlib.sha1(path.encode("utf-8")).hexdigest()
    return f"{_key_prefix()}source_files/{job_id}/{digest}"


def serialize_artifact(data: Any | None, text_data: str | None) -> tuple[bytes, str]:
    """Encode an artifact payload to (bytes, content_type)."""
    if data is not None:
        body = json.dumps(data, default=str).encode("utf-8")
        return body, JSON_CONTENT_TYPE
    if text_data is not None:
        return text_data.encode("utf-8"), TEXT_CONTENT_TYPE
    return b"", TEXT_CONTENT_TYPE


def deserialize_artifact(body: bytes, content_type: str | None) -> dict | list | str:
    """Decode bytes from storage back to a Python value."""
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
                # Tigris TLS handshake p99 to fly.storage.tigris.dev exceeds
                # 2s under concurrent load (observed: terminal
                # StorageUnavailable on KING Distributor impl in psat-pr-65,
                # ssl.do_handshake timing out). 10s covers tail latency.
                connect_timeout=10,
                read_timeout=5,
                # max_attempts=1 disabled botocore's built-in retry, so a
                # single transient handshake/read timeout terminally killed
                # the worker job (no next_attempt_at). Standard mode retries
                # ReadTimeoutError / ConnectTimeoutError with exponential
                # backoff before we surface StorageUnavailable.
                retries={"max_attempts": 3, "mode": "standard"},
                # boto3 default is 10 — too small for our get_many fan-out
                # (16 threads) plus concurrent put/get from the worker job
                # pool. Under load urllib3 was discarding and reopening
                # connections on every spillover, churning the Tigris pool.
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
        """Fetch a key, trying every candidate from ``storage_key_candidates``.

        A transport failure on any candidate propagates immediately — only a
        genuine 404 advances to the next one, so an unreachable bucket can
        never be reported as an absent object.
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
        """Fetch multiple keys concurrently, keeping each key's outcome apart.

        Every unique input key maps to a ``BlobRead`` that answers *which* of
        the three states this key is in — read, proven-absent at every
        candidate, or not determined because the transport failed. ``get_many``
        below flattens all three to ``bytes | None`` for callers whose degrade
        is genuinely cause-independent; anything that publishes the result as
        evidence must use this one.

        The boto3 S3 client is documented as thread-safe, so a small fixed
        pool gives effectively-parallel HTTP round-trips.
        """
        if not keys:
            return {}
        unique = list(dict.fromkeys(keys))

        def _fetch(k: str) -> tuple[str, BlobRead]:
            try:
                return k, BlobRead(body=self.get(k))
            except StorageKeyMissing as exc:
                # A missing object is a real inconsistency: the DB row asserts a
                # key the bucket does not honour. Never silent — 8,256 rows read
                # as empty for months behind this.
                logger.error("get_many: %s", exc)
                return k, BlobRead(error=exc)
            except StorageError as exc:
                logger.warning("get_many: transport error fetching %s: %s", k, exc)
                return k, BlobRead(error=exc)

        # Per-key context copy keeps trace_id/job_id bindings from the
        # caller (e.g. the API handler or worker) visible to each
        # concurrent boto call's log lines.
        def _fetch_with_ctx(k: str) -> tuple[str, BlobRead]:
            ctx = contextvars.copy_context()
            return ctx.run(_fetch, k)

        with ThreadPoolExecutor(max_workers=16) as ex:
            return dict(ex.map(_fetch_with_ctx, unique))

    def get_many(self, keys: list[str]) -> dict[str, bytes | None]:
        """``get_many_results`` with the cause discarded: bytes, or ``None`` for
        both "no object" and "could not ask".

        Only for callers whose degrade does not depend on the cause and does not
        publish absence — ``/stage_timings`` (telemetry) and effects selection
        (a ``None`` there means "re-sweep this contract", the conservative
        direction). Anything that renders or persists the result as a statement
        about the subject must call ``get_many_results``.
        """
        return {k: r.body for k, r in self.get_many_results(keys).items()}

    def presign(self, key: str, expires_in: int = DEFAULT_PRESIGN_TTL) -> str:
        from botocore.exceptions import BotoCoreError, ClientError

        candidates = storage_key_candidates(key)
        target = candidates[0] if candidates else key
        if len(candidates) > 1:
            # A presigned URL for a key with no object is a 404 the caller only
            # discovers after handing it out. Resolve here instead.
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
        """Server-side copy within the same bucket (no egress)."""
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
        """Create the bucket if it does not exist. Used by the test harness."""
        from botocore.exceptions import ClientError

        try:
            self._client.head_bucket(Bucket=self.bucket)
        except ClientError:
            self._client.create_bucket(Bucket=self.bucket)

    def health_check(self) -> None:
        """Verify the bucket is reachable. Raises StorageUnavailable on failure."""
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
    """Return a StorageClient if ARTIFACT_STORAGE_* env vars are set, else None.

    Returning None is the explicit "no object storage configured" signal —
    callers fall back to inline Postgres storage. This keeps local development
    and unit tests usable without a running minio container.
    """
    endpoint, bucket, access_key, secret_key = _read_env()
    if not (endpoint and bucket and access_key and secret_key):
        logger.info("ARTIFACT_STORAGE_* env vars not all set — artifact bodies will be stored inline in Postgres")
        return None
    return StorageClient(endpoint, bucket, access_key, secret_key)


def reset_client_cache() -> None:
    """Drop the cached client so a subsequent call re-reads env. For tests."""
    get_storage_client.cache_clear()
