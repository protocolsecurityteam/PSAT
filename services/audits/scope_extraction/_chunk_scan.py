"""Fallback walking the first ~20 pages in N-page windows when no header matches.

4 chunks × ~$0.0003 covers ~95% of such reports.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Final

from ._errors import LLMUnavailableError
from ._llm import extract_scope_with_llm
from ._locate import ScopeSection
from ._utils import _page_offsets

logger = logging.getLogger(__name__)

_CHUNK_SCAN_PAGES_PER_CHUNK: Final[int] = 5
_CHUNK_SCAN_MAX_CHUNKS: Final[int] = 4
_CHUNK_SCAN_MAX_CHARS: Final[int] = 12_000


# Without this gate, finding-title mentions were accepted as scope.
_SCOPE_HEADER_SIGNAL: Final[re.Pattern[str]] = re.compile(
    r"\b(?:smart\s+contracts?\s+in\s+scope|"
    r"contracts?\s+in\s+scope|"
    r"files?\s+in\s+scope|"
    r"items?\s+in\s+scope|"
    r"audited\s+files?|"
    r"audited\s+contracts?|"
    r"assessment\s+scope|"
    r"audit\s+scope|"
    r"project\s+scope|"
    r"project\s+targets?|"
    r"code\s+repository|"
    r"the\s+following\s+(?:smart\s+)?(?:files?|contracts?)|"
    r"(?:audited|reviewed|assessed)\s+the\s+following|"
    r"\b(?:Program|Target)\s*[:\n])",
    re.IGNORECASE,
)


def _split_text_into_chunks(text: str) -> list[ScopeSection]:
    pages = _page_offsets(text)
    real_pages = pages[:-1]
    chunks: list[ScopeSection] = []
    for i in range(0, len(real_pages), _CHUNK_SCAN_PAGES_PER_CHUNK):
        if len(chunks) >= _CHUNK_SCAN_MAX_CHUNKS:
            break
        start_page, start_off = real_pages[i]
        end_idx = min(i + _CHUNK_SCAN_PAGES_PER_CHUNK, len(real_pages))
        if end_idx < len(real_pages):
            end_off = real_pages[end_idx][1]
            end_page = real_pages[end_idx][0] - 1
        else:
            end_off = len(text)
            end_page = real_pages[-1][0]
        slice_text = text[start_off:end_off][:_CHUNK_SCAN_MAX_CHARS]
        if not slice_text.strip():
            continue
        chunks.append(
            ScopeSection(
                start_page=start_page,
                end_page=end_page,
                header=f"chunk-scan:p{start_page}-{end_page}",
                text_slice=slice_text,
            )
        )
    return chunks


def _has_scope_signal(text: str, extracted_names: list[str]) -> bool:
    """Accept a chunk only with a scope signal: a scope header, a ``<Name>.sol``/``.vy`` mention, or repetition.

    Multi-name extractions need two distinct repeaters (one is often coincidental); single-name extractions need one.
    """
    if _SCOPE_HEADER_SIGNAL.search(text):
        return True
    lower_text = text.lower()
    for name in extracted_names:
        if not name:
            continue
        n = name.lower()
        if f"{n}.sol" in lower_text or f"{n}.vy" in lower_text:
            return True
    non_empty = [n for n in extracted_names if n]
    freq_hits = sum(1 for n in non_empty if lower_text.count(n.lower()) >= 2)
    if len(non_empty) == 1 and freq_hits == 1:
        return True
    return freq_hits >= 2


def extract_scope_via_chunk_scan(
    text: str, title: str, auditor: str
) -> tuple[list[str], list[dict[str, Any]], list[dict[str, Any]], str, str, int, ScopeSection | None]:
    """Walk chunks and merge accepted results (short audits list one contract on the title page and full scope
    later).

    Returns ``(names, scope_entries, classified_commits, raw_response, model, chunks_consumed, winning_chunk)``. Raises
    ``LLMUnavailableError`` only if every chunk call fails.
    """
    chunks = _split_text_into_chunks(text)
    if not chunks:
        raise LLMUnavailableError("chunk-scan: text is empty")

    merged_names: list[str] = []
    seen: set[str] = set()
    merged_entries: list[dict[str, Any]] = []
    seen_entries: set[tuple[str, str]] = set()
    merged_commits_by_sha: dict[str, dict[str, Any]] = {}
    label_rank = {"reviewed": 3, "fix": 2, "cited": 1, "unclear": 0}
    first_winning_chunk: ScopeSection | None = None
    first_response: str = ""
    first_model: str = ""
    accepted_count = 0
    last_error: Exception | None = None
    failure_count = 0

    for idx, chunk in enumerate(chunks, start=1):
        try:
            names, scope_entries, classified_commits, response, model = extract_scope_with_llm([chunk], title, auditor)
        except LLMUnavailableError as exc:
            last_error = exc
            failure_count += 1
            continue
        if not names and not scope_entries and not classified_commits:
            continue
        if not _has_scope_signal(chunk.text_slice, names):
            logger.info(
                "scope: chunk-scan rejecting %d name(s) from chunk %d/%d (pages %d-%d) — no scope signal",
                len(names),
                idx,
                len(chunks),
                chunk.start_page,
                chunk.end_page,
            )
            continue
        logger.info(
            "scope: chunk-scan accepting %d name(s) + %d entry(ies) + %d commit(s) from chunk %d/%d (pages %d-%d)",
            len(names),
            len(scope_entries),
            len(classified_commits),
            idx,
            len(chunks),
            chunk.start_page,
            chunk.end_page,
        )
        if first_winning_chunk is None:
            first_winning_chunk = chunk
            first_response = response
            first_model = model
        accepted_count += 1
        for n in names:
            key = n.lower()
            if key in seen:
                continue
            seen.add(key)
            merged_names.append(n)
        for entry in scope_entries:
            entry_key = (entry["name"].lower(), entry["address"])
            if entry_key in seen_entries:
                continue
            seen_entries.add(entry_key)
            merged_entries.append(entry)
        for commit_entry in classified_commits:
            existing = merged_commits_by_sha.get(commit_entry["sha"])
            if existing is None or label_rank[commit_entry["label"]] > label_rank[existing["label"]]:
                merged_commits_by_sha[commit_entry["sha"]] = commit_entry

    merged_commits = list(merged_commits_by_sha.values())

    if not merged_names and not merged_entries and not merged_commits:
        if failure_count == len(chunks) and last_error is not None:
            raise LLMUnavailableError(f"chunk-scan: all {len(chunks)} chunks failed; last: {last_error}")
        return [], [], [], "", "", len(chunks), None

    logger.info(
        "scope: chunk-scan merged %d name(s) + %d entry(ies) + %d commit(s) across %d accepted chunk(s)",
        len(merged_names),
        len(merged_entries),
        len(merged_commits),
        accepted_count,
    )
    return merged_names, merged_entries, merged_commits, first_response, first_model, len(chunks), first_winning_chunk
