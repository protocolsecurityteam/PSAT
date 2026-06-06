"""Header + content-pattern matching that finds scope sections in PDF text."""

from __future__ import annotations

import re
from typing import Final

from services.audits.types import ScopeSection

from ._utils import _normalize_ligatures, _page_of_offset, _page_offsets

# Ordered so longer phrases win when multiple match on the same line
# (e.g. "Files in scope" beats "Scope"). Covers Spearbit / Cantina /
# Certora / Halborn / Nethermind / Trail-of-Bits formats.
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

# Body-prose scope-introduction phrases. Second pass — catches
# multi-sub-audit reports (Certora) that list scope inline without a
# structural heading. Each pattern is a phrase that *introduces* a
# scope listing, not a passing mention of "scope".
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

# Optional numbered-section prefix real audits use ("5. Scope", "5.1 Files
# in scope"). Anchored to line start so body prose doesn't match.
_NUMBERED_PREFIX = r"(?:\d+(?:\.\d+)*\.?[ \t]+)?"


def locate_scope_section(text: str) -> list[ScopeSection]:
    """Find the scope section(s) in an audit's PDF text.

    Matches any of ``_SCOPE_HEADERS`` case-insensitively at line start, then
    captures ~3 pages of context. A second pass runs the body-prose content
    patterns. Overlapping slices merge. Returns [] when nothing is found,
    which the worker translates into ``status='skipped'``.
    """
    text = _normalize_ligatures(text)
    pages = _page_offsets(text)
    lower = text.lower()

    # (start_offset, end_offset, start_page, end_page, header)
    candidates: list[tuple[int, int, int, int, str]] = []
    seen_offsets: set[int] = set()

    for header in _SCOPE_HEADERS:
        # Tolerate pypdf double-spacing within the header phrase; keep
        # whitespace classes non-newline so the match can't slurp a
        # preceding page-marker line and land on the wrong page.
        header_words = r"[ \t]+".join(re.escape(w) for w in header.split())
        pattern = re.compile(
            rf"^[ \t]*{_NUMBERED_PREFIX}{header_words}\b[ \t:]*$",
            re.MULTILINE,
        )
        # Capture ALL matches per header — a TOC entry and the actual
        # section often both match; we want the LLM to see the real one.
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
            # Content matches land right before the listing; 2 pages suffice.
            end_page = min(start_page + 1, pages[-2][0])
            end_offset = next(
                (off for (p, off) in pages if p > end_page),
                len(text),
            )
            candidates.append((start, end_offset, start_page, end_page, f"content:{m.group(0)[:40].strip()}"))

    # Merge by offset range. text_slice spans the FULL merged range —
    # an earlier version kept only the first candidate's slice and
    # silently dropped sub-scope listings from later matches.
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
