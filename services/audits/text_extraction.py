"""Download audit PDFs, extract text, store it in object storage.

I/O-only at this layer — orchestration (claiming rows, DB state, rate
limiting) lives in ``workers.audit_text_extraction``. Importable and
testable without DB or S3.

``process_audit_report`` chains ``download_audit_body`` → extract (pypdf
for PDFs, UTF-8 decode for markdown/text) → ``store_audit_text`` and
returns an ``ExtractionOutcome`` the worker persists.
"""

from __future__ import annotations

import hashlib
import io
import logging
import random
import time
from dataclasses import dataclass
from typing import Final, Literal
from urllib.parse import urlparse

import requests

from db.storage import StorageUnavailable, get_storage_client
from utils.egress import UnsafeUrlError, safe_get
from utils.github_urls import github_blob_to_raw

logger = logging.getLogger(__name__)

# Size cap: >50MB is almost always a scanned-image dump anyway, plus OOM
# protection against hostile hosts. Under-500-char extracts get marked
# ``skipped`` as image-only PDFs (OCR is out of scope).
_MAX_PDF_BYTES: Final[int] = 50 * 1024 * 1024
_CONNECT_TIMEOUT: Final[float] = 10.0
_READ_TIMEOUT: Final[float] = 60.0
_MIN_USEFUL_TEXT_LENGTH: Final[int] = 500

# CDNs often serve PDFs as ``application/octet-stream`` — accept those too.
# Non-matching content-types short-circuit so we don't parse HTML error
# pages as PDFs.
_ACCEPTED_CONTENT_TYPES: Final[frozenset[str]] = frozenset(
    {
        "application/pdf",
        "application/octet-stream",
        "binary/octet-stream",
        "application/x-pdf",
    }
)

# Plain-text / markdown audit reports. raw.githubusercontent.com serves
# markdown as ``text/plain``; other hosts use ``text/markdown`` or
# ``text/x-markdown``. ``text/html`` is deliberately excluded — GitHub's
# /blob/ URLs return HTML code-view pages, not the raw file body.
_ACCEPTED_TEXT_CONTENT_TYPES: Final[frozenset[str]] = frozenset(
    {
        "text/plain",
        "text/markdown",
        "text/x-markdown",
        "text/x-rst",
    }
)

# File extensions whose URLs route through the plain-text path instead of
# pypdf. Lowercase-matched against the URL's path component.
_TEXT_URL_SUFFIXES: Final[tuple[str, ...]] = (".md", ".markdown", ".txt", ".rst")

AUDIT_TEXT_CONTENT_TYPE: Final[str] = "text/plain; charset=utf-8"

# Retry policy for transport-layer flakes. Prod observed bursts of
# ConnectionResetError(104) from auditor CDNs that turned every batch into a
# wave of permanent ``failed`` rows; retries absorb the brief upstream
# windows where every connection RSTs at once. Bounded so a genuinely dead
# host fails fast rather than wedging the worker.
_RETRY_ATTEMPTS: Final[int] = 3
_RETRY_INITIAL_BACKOFF: Final[float] = 0.5
_RETRY_BACKOFF_CAP: Final[float] = 10.0
# 408/429 are transient by spec; 5xx is the HTTP analogue of an RST. Other
# 4xx (404, 403, 410) are terminal — refetching the same URL won't fix them.
_TRANSIENT_HTTP_STATUS: Final[frozenset[int]] = frozenset({408, 429, 500, 502, 503, 504})


def _retry_sleep(seconds: float) -> None:
    """Sleep ``seconds`` with ±50% jitter. Factored out so unit tests can
    stub the wall-clock wait without monkeypatching the whole ``time``
    module — tests under ``TestDownloadAuditBodyRetry`` rely on this.
    """
    time.sleep(random.uniform(seconds * 0.5, seconds * 1.5))


# --- Errors ---------------------------------------------------------------


class TextExtractionError(RuntimeError):
    """Base class for failures during the download/extract/store flow."""


class PdfDownloadError(TextExtractionError):
    """HTTP or transport failure fetching the PDF body."""


class PdfTooLargeError(TextExtractionError):
    """Server-reported or streamed content exceeded ``_MAX_PDF_BYTES``."""


class PdfParseError(TextExtractionError):
    """pypdf could not parse the body (encrypted, corrupted, not a PDF)."""


class StorageWriteError(TextExtractionError):
    """Object storage write failed or storage is not configured."""


# --- Result type ----------------------------------------------------------


@dataclass(frozen=True)
class ExtractionOutcome:
    """Structured result of ``process_audit_report``.

    Exactly one of ``storage_key`` / ``error`` is non-None for a given status.
    ``status`` mirrors the ``AuditReport.text_extraction_status`` enum strings.
    """

    status: str  # "success" | "failed" | "skipped"
    storage_key: str | None = None
    text_size_bytes: int | None = None
    text_sha256: str | None = None
    error: str | None = None


# --- Storage key ---------------------------------------------------------


def audit_text_key(audit_report_id: int) -> str:
    """Deterministic object-storage key for an audit's extracted text body."""
    return f"audits/text/{int(audit_report_id)}.txt"


# --- Download ------------------------------------------------------------


def _url_looks_text(url: str) -> bool:
    """True when the URL's path ends in a markdown/text suffix.

    Keyed off extension, not content-type — the worker decides which
    download mode to use *before* making the request so the content-type
    check can reject mismatches (e.g. a .pdf URL returning text/html).
    """
    try:
        path = urlparse(url).path.lower()
    except Exception:
        return False
    return path.endswith(_TEXT_URL_SUFFIXES)


def _normalize_download_url(url: str) -> str:
    """Rewrite GitHub blob file links to raw-content URLs.

    Discovery should ideally persist the raw URL, but normalizing here
    keeps already-stored rows retriable and prevents one bad discovery run
    from permanently wedging extraction.
    """
    return github_blob_to_raw(url)


def download_audit_body(
    url: str,
    session: requests.Session | None = None,
    *,
    kind: Literal["pdf", "text"] = "pdf",
) -> bytes:
    """Fetch an audit body by URL. Streams to memory with a hard size cap.

    ``kind="pdf"`` accepts PDF / octet-stream content-types; ``kind="text"``
    accepts text/plain / text/markdown / text/x-markdown / text/x-rst.
    ``text/html`` is rejected in both modes — GitHub's ``/blob/`` URLs
    serve HTML code-view pages, not the raw file body, so landing on HTML
    in either mode signals a wrong URL was captured at discovery time.

    Raises ``PdfDownloadError`` for network / HTTP failures and
    ``PdfTooLargeError`` when the body exceeds ``_MAX_PDF_BYTES``.

    Retries transient transport flakes (``ConnectionError``, ``Timeout``)
    and transient HTTP statuses (408/429/5xx) with jittered exponential
    backoff. 4xx other than 408/429 and content-type mismatches are fatal
    — refetching won't change a 404 or a login-wall HTML page.
    """
    backoff = _RETRY_INITIAL_BACKOFF

    for attempt in range(_RETRY_ATTEMPTS):
        last_attempt = attempt == _RETRY_ATTEMPTS - 1
        try:
            # SSRF guard: safe_get re-validates the target and every redirect
            # hop, so a discovery-sourced URL that 302s to an internal address
            # is refused rather than followed. Fatal — a bad URL/redirect won't
            # improve on retry.
            resp = safe_get(
                url,
                timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT),
                session=session,
                stream=True,
                headers={"User-Agent": "PSAT-audit-text-extractor/0.1"},
            )
        except UnsafeUrlError as exc:
            raise PdfDownloadError(f"refused non-public URL: {exc}") from exc
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
            if last_attempt:
                raise PdfDownloadError(f"fetch error: {exc}") from exc
            logger.warning(
                "Audit fetch transient %s, retrying in %.1fs (attempt %d/%d)",
                type(exc).__name__,
                backoff,
                attempt + 1,
                _RETRY_ATTEMPTS,
            )
            _retry_sleep(backoff)
            backoff = min(backoff * 2, _RETRY_BACKOFF_CAP)
            continue
        except requests.RequestException as exc:
            # SSLError on a bad cert, InvalidURL, MissingSchema — not
            # transport flakes, retrying won't help. Fail fast.
            raise PdfDownloadError(f"fetch error: {exc}") from exc

        # Transient HTTP status: discard the response and back off. We
        # don't read the body so close immediately to release the conn.
        if resp.status_code in _TRANSIENT_HTTP_STATUS and not last_attempt:
            status = resp.status_code
            resp.close()
            logger.warning(
                "Audit fetch HTTP %d, retrying in %.1fs (attempt %d/%d)",
                status,
                backoff,
                attempt + 1,
                _RETRY_ATTEMPTS,
            )
            _retry_sleep(backoff)
            backoff = min(backoff * 2, _RETRY_BACKOFF_CAP)
            continue

        try:
            if resp.status_code != 200:
                raise PdfDownloadError(f"HTTP {resp.status_code}")

            content_type = (resp.headers.get("content-type") or "").split(";")[0].strip().lower()
            accepted = _ACCEPTED_TEXT_CONTENT_TYPES if kind == "text" else _ACCEPTED_CONTENT_TYPES
            # GitHub serves raw PDFs with content-type application/pdf; gitbook
            # CDNs often use octet-stream. Reject text/html / application/json
            # etc. — we've been redirected to an error page.
            if content_type and content_type not in accepted:
                raise PdfDownloadError(f"unexpected content-type {content_type!r}")

            # Server-reported size check — saves us the round trip if we can
            # tell upfront the body is too big.
            content_length = resp.headers.get("content-length")
            if content_length and content_length.isdigit() and int(content_length) > _MAX_PDF_BYTES:
                raise PdfTooLargeError(f"Content-Length {content_length} exceeds cap {_MAX_PDF_BYTES}")

            chunks: list[bytes] = []
            total = 0
            for chunk in resp.iter_content(chunk_size=131_072):
                if not chunk:
                    continue
                total += len(chunk)
                if total > _MAX_PDF_BYTES:
                    raise PdfTooLargeError(f"streamed body exceeded cap {_MAX_PDF_BYTES}")
                chunks.append(chunk)

            return b"".join(chunks)
        finally:
            resp.close()

    # Every branch above either returns or raises by ``last_attempt``.
    raise PdfDownloadError("retry budget exhausted")  # pragma: no cover


def download_pdf(url: str, session: requests.Session | None = None) -> bytes:
    """Fetch a PDF by URL. Thin wrapper around ``download_audit_body``.

    Kept so existing callers (CLI dry-run, tests that monkeypatch this
    symbol) continue to work.
    """
    return download_audit_body(url, session=session, kind="pdf")


def download_text(url: str, session: requests.Session | None = None) -> bytes:
    """Fetch a markdown / plain-text audit body by URL.

    Accepts ``text/plain`` / ``text/markdown`` / ``text/x-markdown`` /
    ``text/x-rst`` content-types. Rejects ``text/html`` — GitHub ``/blob/``
    URLs serve the HTML code-view page, not the raw markdown, so landing
    on HTML means discovery captured the wrong URL.
    """
    return download_audit_body(url, session=session, kind="text")


# --- Extract -------------------------------------------------------------


def _extract_link_annotation_uris(page) -> list[str]:
    """Pull ``/URI`` values out of a page's ``/Link`` annotations.

    Modern audit PDFs (Certora V3+) hyperlink the word "commit" instead
    of spelling SHAs inline — ``page.extract_text()`` only sees the
    display text ("commit"), losing the URL. Without this pass,
    ``extract_reviewed_commits`` returns ``[]`` and the whole source-
    equivalence path stays dark, collapsing audit coverage onto heuristic
    grace-zone matching.

    Only ``/Subtype == /Link`` annotations with a ``/A/URI`` field are
    collected — highlights, comments, form fields, etc. are ignored.
    pypdf's annotation graph is messy in the wild (indirect references,
    malformed dicts, missing subtypes) so every access is try-wrapped
    defensively; a broken annotation should degrade to "missed this one
    URI" not "crashed the whole extractor".
    """
    annots = page.get("/Annots")
    if annots is None:
        return []
    try:
        annots = annots.get_object() if hasattr(annots, "get_object") else annots
    except Exception:
        return []

    uris: list[str] = []
    for a in annots or []:
        try:
            obj = a.get_object() if hasattr(a, "get_object") else a
            if obj.get("/Subtype") != "/Link":
                continue
            action = obj.get("/A")
            if action is None:
                continue
            action_obj = action.get_object() if hasattr(action, "get_object") else action
            uri = action_obj.get("/URI")
            if not uri:
                continue
            uri_str = str(uri).strip()
            if uri_str:
                uris.append(uri_str)
        except Exception:
            # Malformed annotation — skip it, keep extracting the rest.
            continue
    return uris


def extract_text_from_pdf(pdf_bytes: bytes) -> str:
    """Parse a PDF page-by-page with ``\\f\\n--- page {n} ---\\n\\f`` separators.

    Scope extraction uses the markers to recover page boundaries without
    re-parsing. Empty/short output is the caller's call to skip. Raises
    ``PdfParseError`` when pypdf rejects the body outright.

    Each page's output is the visible text followed by any URIs from
    ``/Link`` annotations (one per line, under a ``[links]`` marker).
    Downstream ``extract_reviewed_commits`` picks commit SHAs straight
    out of those URL strings — GitHub's ``/commit/<40-hex>`` and
    ``/pull/*/commits/<40-hex>`` both contain the SHA as plain hex.
    """
    try:
        from pypdf import PdfReader
        from pypdf.errors import PdfReadError
    except ImportError as exc:  # pragma: no cover - dep configured in pyproject
        raise PdfParseError(f"pypdf import failed: {exc}") from exc

    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
    except PdfReadError as exc:
        raise PdfParseError(f"not a valid PDF: {exc}") from exc
    except Exception as exc:  # pypdf sometimes raises plain ValueError
        raise PdfParseError(f"pypdf failed: {exc}") from exc

    if getattr(reader, "is_encrypted", False):
        # Empty-password decrypt covers legacy print-protection PDFs.
        try:
            if not reader.decrypt(""):
                raise PdfParseError("encrypted PDF; no password available")
        except Exception as exc:
            raise PdfParseError(f"encrypted PDF decrypt failed: {exc}") from exc

    parts: list[str] = []
    for idx, page in enumerate(reader.pages, start=1):
        try:
            text = page.extract_text() or ""
        except Exception as exc:
            # Per-page noise: a malformed page yields an empty page, not a job
            # failure. DEBUG keeps the breadcrumb without flooding the log.
            logger.debug("pypdf page %d extract_text raised: %s", idx, exc)
            text = ""
        link_uris = _extract_link_annotation_uris(page)
        body = text
        if link_uris:
            body = f"{text}\n[links]\n" + "\n".join(link_uris)
        parts.append(f"\f\n--- page {idx} ---\n\f\n{body}")

    return "".join(parts).strip()


# --- Store ---------------------------------------------------------------


def store_audit_text(
    audit_report_id: int,
    text: str,
) -> tuple[str, int, str]:
    """Upload an audit's extracted text to object storage.

    Returns ``(storage_key, size_bytes, sha256_hex)``. Raises
    ``StorageWriteError`` if storage isn't configured or the put fails.
    """
    client = get_storage_client()
    if client is None:
        raise StorageWriteError("object storage not configured (ARTIFACT_STORAGE_* env vars unset)")

    body = text.encode("utf-8")
    digest = hashlib.sha256(body).hexdigest()
    key = audit_text_key(audit_report_id)

    try:
        client.put(
            key,
            body,
            AUDIT_TEXT_CONTENT_TYPE,
            metadata={
                "audit_report_id": str(audit_report_id),
                "sha256": digest,
            },
        )
    except StorageUnavailable as exc:
        raise StorageWriteError(f"storage put failed: {exc}") from exc

    return key, len(body), digest


# --- Orchestration ---------------------------------------------------------


def process_audit_report(
    audit_report_id: int,
    url: str,
    session: requests.Session | None = None,
) -> ExtractionOutcome:
    """Run download → parse → store for one audit. Never raises.

    Typed errors from each stage become ``ExtractionOutcome(status=...)``
    the worker can persist directly; unexpected exceptions still surface
    as ``status="failed"`` with the error message captured.
    """
    if not url:
        return ExtractionOutcome(status="failed", error="no URL on audit row")

    download_url = _normalize_download_url(url)
    is_text_url = _url_looks_text(download_url)

    try:
        # Call the module-level helpers so callers that monkeypatch
        # ``download_pdf`` (existing unit tests) still hit the mock.
        body = (
            download_text(download_url, session=session) if is_text_url else download_pdf(download_url, session=session)
        )
    except PdfTooLargeError as exc:
        return ExtractionOutcome(status="skipped", error=f"pdf too large: {exc}")
    except PdfDownloadError as exc:
        return ExtractionOutcome(status="failed", error=f"download: {exc}")
    except Exception as exc:
        # pypdf can raise unbounded types on malformed input; don't let one
        # broken PDF kill the worker loop.
        logger.warning(
            "unexpected download error for %s: %s",
            url,
            exc,
            extra={"exc_type": type(exc).__name__},
        )
        return ExtractionOutcome(status="failed", error=f"download: {exc!r}")

    if is_text_url:
        # Markdown / plain-text reports go straight through — no pypdf.
        # Bytes → UTF-8 with replacement so a stray non-UTF8 byte in an
        # otherwise-valid markdown file doesn't wedge the pipeline.
        text = body.decode("utf-8", errors="replace")
    else:
        try:
            text = extract_text_from_pdf(body)
        except PdfParseError as exc:
            return ExtractionOutcome(status="failed", error=f"parse: {exc}")
        except Exception as exc:
            logger.warning(
                "unexpected parse error for %s: %s",
                url,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
            return ExtractionOutcome(status="failed", error=f"parse: {exc!r}")

    if len(text) < _MIN_USEFUL_TEXT_LENGTH:
        return ExtractionOutcome(
            status="skipped",
            error=(
                f"extracted text is {len(text)} chars (< {_MIN_USEFUL_TEXT_LENGTH}) — "
                f"likely image-only PDF, OCR required"
            ),
        )

    try:
        key, size, digest = store_audit_text(audit_report_id, text)
    except StorageWriteError as exc:
        return ExtractionOutcome(status="failed", error=f"store: {exc}")
    except Exception as exc:
        logger.warning(
            "unexpected store error for audit %s: %s",
            audit_report_id,
            exc,
            extra={"exc_type": type(exc).__name__},
        )
        return ExtractionOutcome(status="failed", error=f"store: {exc!r}")

    return ExtractionOutcome(
        status="success",
        storage_key=key,
        text_size_bytes=size,
        text_sha256=digest,
    )
