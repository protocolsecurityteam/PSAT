from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from ._utils import _normalize_ligatures, _page_of_offset, _page_offsets

# Longer phrases first so "Files in scope" beats "Scope".
_SCOPE_HEADERS: Final[tuple[str, ...]] = (
    "smart contracts in scope",
    "contracts in scope",
    "files in scope",
    "items in scope",
    "audited files",
    "audited contracts",
    "in-scope contracts",
    "in scope contracts",
    "assessment scope",
    "audit scope",
    "project scope",
    "project targets",
    "code repository",
    "scope",
)

# Second pass for reports that introduce scope inline without a heading (Certora).
_SCOPE_CONTENT_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(
        r"the\s+following\s+(?:contract\s+list|file\s+list|list\s+of\s+\w+)\s+"
        r"(?:is|are|was|were)\s+(?:included|listed)\s+in\s+(?:the\s+)?scope",
        re.IGNORECASE,
    ),
    re.compile(
        r"the\s+following\s+(?:smart\s+)?(?:files?|contracts?)\s+"
        r"(?:are|were|is|was|are\s+in\s+scope|were\s+in\s+scope|"
        r"reviewed|audited|assessed|included)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:audited|reviewed|assessed)\s+the\s+following\s+(?:files?|contracts?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:files?|contracts?|targets?)\s+(?:reviewed|audited|assessed|in\s+scope)\s*:",
        re.IGNORECASE,
    ),
)

# Line-anchored so body prose doesn't match.
_NUMBERED_PREFIX = r"(?:\d+(?:\.\d+)*\.?[ \t]+)?"


@dataclass(frozen=True)
class ScopeSection:
    start_page: int
    end_page: int
    header: str
    text_slice: str


def locate_scope_section(text: str) -> list[ScopeSection]:
    """Find scope sections: line-start headers (~3 pages of context), then content patterns; overlaps merge.

    [] becomes ``status='skipped'``.
    """
    text = _normalize_ligatures(text)
    pages = _page_offsets(text)
    lower = text.lower()

    candidates: list[tuple[int, int, int, int, str]] = []
    seen_offsets: set[int] = set()

    for header in _SCOPE_HEADERS:
        # Tolerate pypdf double-spacing, but never across newlines or the match can land on the wrong page.
        header_words = r"[ \t]+".join(re.escape(w) for w in header.split())
        pattern = re.compile(
            rf"^[ \t]*{_NUMBERED_PREFIX}{header_words}\b[ \t:]*$",
            re.MULTILINE,
        )
        # A TOC entry and the real section both match.
        for m in pattern.finditer(lower):
            start = m.start()
            if start in seen_offsets:
                continue
            seen_offsets.add(start)
            start_page = _page_of_offset(pages, start)
            end_page = min(start_page + 2, pages[-2][0])
            end_offset = next(
                (off for (p, off) in pages if p > end_page),
                len(text),
            )
            candidates.append((start, end_offset, start_page, end_page, header))

    for pattern in _SCOPE_CONTENT_PATTERNS:
        for m in pattern.finditer(text):
            start = m.start()
            if start in seen_offsets:
                continue
            seen_offsets.add(start)
            start_page = _page_of_offset(pages, start)
            end_page = min(start_page + 1, pages[-2][0])
            end_offset = next(
                (off for (p, off) in pages if p > end_page),
                len(text),
            )
            candidates.append((start, end_offset, start_page, end_page, f"content:{m.group(0)[:40].strip()}"))

    # The slice spans the full merged range; keeping only the first slice once dropped later sub-scopes.
    candidates.sort(key=lambda c: c[0])
    merged: list[tuple[int, int, int, int, str]] = []
    for c in candidates:
        start, end, sp, ep, hdr = c
        if merged and start <= merged[-1][1]:
            pstart, pend, psp, pep, phdr = merged[-1]
            merged[-1] = (pstart, max(pend, end), psp, max(pep, ep), phdr)
        else:
            merged.append(c)

    return [
        ScopeSection(
            start_page=sp,
            end_page=ep,
            header=hdr,
            text_slice=text[start:end],
        )
        for (start, end, sp, ep, hdr) in merged
    ]
