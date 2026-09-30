"""Download audit PDFs/text, extract, store in object storage.

I/O only; orchestration is in ``workers.audit_text_extraction``.
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

# >50MB is almost always scanned images; also OOM protection.
_MAX_PDF_BYTES: Final[int] = 50 * 1024 * 1024
_CONNECT_TIMEOUT: Final[float] = 10.0
_READ_TIMEOUT: Final[float] = 60.0
_MIN_USEFUL_TEXT_LENGTH: Final[int] = 500

# CDNs often serve PDFs as octet-stream. Anything else is likely an HTML error page.
_ACCEPTED_CONTENT_TYPES: Final[frozenset[str]] = frozenset(
    {
        "application/pdf",
        "application/octet-stream",
        "binary/octet-stream",
        "application/x-pdf",
    }
)

# ``text/html`` excluded: GitHub /blob/ URLs return code-view pages.
_ACCEPTED_TEXT_CONTENT_TYPES: Final[frozenset[str]] = frozenset(
    {
        "text/plain",
        "text/markdown",
        "text/x-markdown",
        "text/x-rst",
    }
)

_TEXT_URL_SUFFIXES: Final[tuple[str, ...]] = (".md", ".markdown", ".txt", ".rst")

AUDIT_TEXT_CONTENT_TYPE: Final[str] = "text/plain; charset=utf-8"

# Auditor CDNs RST every connection in brief bursts; bounded so a dead host fails fast.
_RETRY_ATTEMPTS: Final[int] = 3
_RETRY_INITIAL_BACKOFF: Final[float] = 0.5
_RETRY_BACKOFF_CAP: Final[float] = 10.0
# Other 4xx are terminal.
_TRANSIENT_HTTP_STATUS: Final[frozenset[int]] = frozenset({408, 429, 500, 502, 503, 504})


def _retry_sleep(seconds: float) -> None:
    """±50% jitter; separate so tests can stub the wait."""
    time.sleep(random.uniform(seconds * 0.5, seconds * 1.5))


class TextExtractionError(RuntimeError): ...


class PdfDownloadError(TextExtractionError): ...


class PdfTooLargeError(TextExtractionError): ...


class PdfParseError(TextExtractionError): ...


class StorageWriteError(TextExtractionError): ...


@dataclass(frozen=True)
class ExtractionOutcome:
    """Exactly one of ``storage_key`` / ``error`` is set."""

    status: str  # "success" | "failed" | "skipped"
    storage_key: str | None = None
    text_size_bytes: int | None = None
    text_sha256: str | None = None
    error: str | None = None


def audit_text_key(audit_report_id: int) -> str:
    return f"audits/text/{int(audit_report_id)}.txt"


def _url_looks_text(url: str) -> bool:
    """By extension, decided before the request so content-type can reject mismatches."""
    try:
        path = urlparse(url).path.lower()
    except Exception:
        return False
    return path.endswith(_TEXT_URL_SUFFIXES)


def _normalize_download_url(url: str) -> str:
    """Keeps already-stored blob URLs retriable."""
    return github_blob_to_raw(url)


def download_audit_body(
    url: str,
    session: requests.Session | None = None,
    *,
    kind: Literal["pdf", "text"] = "pdf",
) -> bytes:
    """Fetch an audit body with a hard size cap.

    ``text/html`` is rejected in both modes: it means discovery captured a code-view URL. Transient failures retry with
    backoff; other 4xx and content-type mismatches are fatal.
    """
    backoff = _RETRY_INITIAL_BACKOFF

    for attempt in range(_RETRY_ATTEMPTS):
        last_attempt = attempt == _RETRY_ATTEMPTS - 1
        try:
            # SSRF guard re-validates every redirect hop. Fatal: won't improve on retry.
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
            # Not a transport flake; fail fast.
            raise PdfDownloadError(f"fetch error: {exc}") from exc

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
            if content_type and content_type not in accepted:
                raise PdfDownloadError(f"unexpected content-type {content_type!r}")

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

    raise PdfDownloadError("retry budget exhausted")  # pragma: no cover


def download_pdf(url: str, session: requests.Session | None = None) -> bytes:
    """Kept for callers and tests that monkeypatch this symbol."""
    return download_audit_body(url, session=session, kind="pdf")


def download_text(url: str, session: requests.Session | None = None) -> bytes:
    return download_audit_body(url, session=session, kind="text")


def _extract_link_annotation_uris(page) -> list[str]:
    """``/URI`` values from a page's ``/Link`` annotations.

    Modern PDFs hyperlink the word "commit" instead of printing the SHA, which left source-equivalence dark. Every
    access is guarded: a broken annotation should lose one URI, not crash the extractor.
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
            continue
    return uris


def extract_text_from_pdf(pdf_bytes: bytes) -> str:
    """Parse page-by-page with ``\\f\\n--- page {n} ---\\n\\f`` separators so scope extraction can recover pages.

    Each page ends with its link URIs under ``[links]`` so commit SHAs in URLs are picked up.
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
        # Empty-password decrypt covers legacy print-protection.
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
            logger.debug("pypdf page %d extract_text raised: %s", idx, exc)
            text = ""
        link_uris = _extract_link_annotation_uris(page)
        body = text
        if link_uris:
            body = f"{text}\n[links]\n" + "\n".join(link_uris)
        parts.append(f"\f\n--- page {idx} ---\n\f\n{body}")

    return "".join(parts).strip()


def store_audit_text(
    audit_report_id: int,
    text: str,
) -> tuple[str, int, str]:
    """Returns ``(storage_key, size_bytes, sha256_hex)``."""
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


def process_audit_report(
    audit_report_id: int,
    url: str,
    session: requests.Session | None = None,
) -> ExtractionOutcome:
    """Download, parse, store for one audit. Never raises; failures become an ``ExtractionOutcome`` status."""
    if not url:
        return ExtractionOutcome(status="failed", error="no URL on audit row")

    download_url = _normalize_download_url(url)
    is_text_url = _url_looks_text(download_url)

    try:
        # Module-level lookup so tests that monkeypatch ``download_pdf`` hit the mock.
        body = (
            download_text(download_url, session=session) if is_text_url else download_pdf(download_url, session=session)
        )
    except PdfTooLargeError as exc:
        return ExtractionOutcome(status="skipped", error=f"pdf too large: {exc}")
    except PdfDownloadError as exc:
        return ExtractionOutcome(status="failed", error=f"download: {exc}")
    except Exception as exc:
        # pypdf raises unbounded types on malformed input.
        logger.warning(
            "unexpected download error for %s: %s",
            url,
            exc,
            extra={"exc_type": type(exc).__name__},
        )
        return ExtractionOutcome(status="failed", error=f"download: {exc!r}")

    if is_text_url:
        # Replacement decoding so one stray byte doesn't wedge the pipeline.
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
