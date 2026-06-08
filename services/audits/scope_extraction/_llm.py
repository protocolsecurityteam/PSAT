"""Prompt building and LLM call for scope extraction.

``_call_llm`` is the single swap point — tests patch
``services.audits.scope_extraction._llm._call_llm`` to intercept calls.

Two output shapes are accepted on the response side:

- **Legacy**: flat JSON array of contract name strings. Used by audits
  whose scope section is prose or flat name lists.
- **Structured**: JSON object ``{contracts: [...], scope_entries: [...]}``.
  Used by audits whose scope section contains a name/address/commit
  table. Unlocks address-anchored matching
  (``match_type='reviewed_address'``) in the coverage matcher.

Both shapes return ``(names, scope_entries, raw_response, model)``.
``scope_entries`` is empty for legacy responses.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from pathlib import Path
from typing import Any, Final

from utils.rpc import require_supported_chain_id

from ._errors import LLMUnavailableError
from ._locate import ScopeSection

logger = logging.getLogger(__name__)

PROMPT_VERSION: Final[str] = "scope-v3"

# Cap on prompt payload. Scope sections are ~10 KB normally; 40 KB
# protects against a degenerate slice.
_MAX_SCOPE_TEXT_CHARS: Final[int] = 40_000


_SCOPE_PROMPT_TEMPLATE = """\
You are extracting the list of contracts that were in scope for a smart-contract security audit.

Audit title: {title}
Auditor: {auditor}

Below is the scope section(s) from the audit report PDF. Different auditors \
use different formats (markdown tables, bulleted URL lists, line-count \
tables, flat src/ trees, prose enumeration) — extract every contract \
regardless of format.

Return a JSON **object** with three keys: ``contracts``, ``scope_entries``, \
and ``classified_commits``.

### ``contracts``

A JSON array of contract name strings. This is the primary output.

Rules:
- Contract names are the basenames of .sol / .vy files WITHOUT the extension, \
e.g. "MorphoBlue", "Pool", "BundlerV3".
- Deduplicate names. If the same contract appears in multiple repos or \
across audit phases, include it once.
- EXCLUDE test files (Test*, *Test, *.t.sol), mocks (Mock*, *Mock), \
deployment scripts (Deploy*, *.s.sol), and anything explicitly marked \
"out of scope" or "reference only".

Avoid these specific false positives that trip up extraction:
- Do NOT treat project names, product names, or section headers as \
contract names. "EtherFi RewardsManager" as a section title is not the \
same as a RewardsManager.sol file being audited.
- Do NOT include EXTERNAL dependencies described in a "System Overview" \
or architecture-background section — these are typically contracts the \
protocol INTEGRATES with (e.g. "Hyperliquid's CoreWriter at 0x3333..."), \
not audit targets.
- If a contract is mentioned ONLY in a single finding (e.g. \
"Issue L-01: BeaconFactory is vulnerable") without also appearing in a \
scope list or tree, it's probably not in scope — but if it IS in a scope \
list AND discussed in findings, include it normally.

Include these as in-scope when they appear:
- Contracts listed in an explicit scope section, audited-files table, \
"Program:" declaration, "Target:" field, flat src/ tree printout, or \
a bulleted contract list.
- Contracts the audit clearly reviewed even if the structural header is \
missing — a flat listing of .sol filenames IS a scope signal.

### ``scope_entries``

A JSON array of structured entries, one per scope contract that has an \
explicit Ethereum-style address listed next to it. Each entry:

    {{
      "name": "<ContractName>",
      "address": "0x<40 hex chars lowercase>",
      "commit": "<7-40 hex chars lowercase>" | null,
      "chain_id": <numeric EVM chain id> | null
    }}

Rules:
- Emit a scope_entry ONLY when the scope section explicitly pairs a \
contract name with an address. Never guess, never invent an address.
- If the scope section lists a reviewed commit SHA adjacent to the \
contract (e.g. in a "commit" column of the scope table, or in a single \
"reviewed at commit abc1234" line that applies to all entries), put it \
in ``commit``. Otherwise set commit to null.
- If the scope section indicates a chain for the entry (e.g. "Ethereum \
mainnet", "Arbitrum", "Scroll"), emit the numeric EVM chain_id. Default \
to null when unspecified; never guess a chain id from the address alone.
- If no addresses are present in the scope section, return an empty \
array for ``scope_entries``. This is the normal case for audits whose \
scope is prose or a flat name list.
- Every scope_entry's ``name`` MUST also appear in ``contracts``.

### ``classified_commits``

A JSON array of every git commit SHA you can identify in the scope \
section text, labeled with how the audit text uses it. Each entry:

    {{
      "sha": "<7-40 hex chars lowercase>",
      "label": "reviewed" | "fix" | "cited" | "unclear",
      "context": "<one-line quote or summary of how the commit was used>"
    }}

Label definitions (CRITICAL — these drive the `proof_kind` column on \
coverage rows):

- ``reviewed`` — the commit the audit actually examined. Phrasing like \
"audited at commit X", "reviewed at hash X", "scope: commit X", \
"codebase at X", "commit X was the subject of this assessment". There is \
often ONE such commit per audit, though some phased audits name several.

- ``fix`` — a commit the audit identifies as containing a fix for an \
issue the audit found. Phrasing like "fixed in commit X", "addressed at \
commit X", "remediation commit X", "issue L-01 resolved by commit X", \
or a commit listed in a ``Fixes:`` / ``Resolution:`` column next to a \
finding. These are distinct from reviewed commits — the audit saw the \
pre-fix code and later cites these commits as where the fix landed.

- ``cited`` — a commit mentioned for context but NOT the reviewed \
revision OR a fix. Includes "the bug originally landed in commit X", \
"baseline was commit X", "see also commit X", historical references, \
unrelated upstream commits quoted in a URL.

- ``unclear`` — commit SHA appears in text (link, table, footnote) but \
the context is too ambiguous to classify with confidence. Better than \
guessing wrong.

Extract ONLY commit-SHA-shaped tokens (7-40 hex chars). Drop pure-digit \
tokens, all-same-char tokens, and anything that isn't clearly a commit \
reference. Deduplicate by sha.

If no commit SHAs appear in the text, return an empty array.

If no contracts can be identified, return \
``{{"contracts": [], "scope_entries": [], "classified_commits": []}}``.

Scope section text:
---
{scope_text}
---

Respond with the JSON object only."""


_ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")
_COMMIT_LABELS: Final[frozenset[str]] = frozenset({"reviewed", "fix", "cited", "unclear"})


def _build_prompt(sections: list[ScopeSection], title: str, auditor: str) -> str:
    joined = "\n\n===\n\n".join(s.text_slice for s in sections)
    if len(joined) > _MAX_SCOPE_TEXT_CHARS:
        joined = joined[:_MAX_SCOPE_TEXT_CHARS]
    return _SCOPE_PROMPT_TEMPLATE.format(
        title=title or "(unknown)",
        auditor=auditor or "(unknown)",
        scope_text=joined,
    )


def _call_llm(prompt: str) -> tuple[str, str]:
    """Call the LLM, returning ``(response_text, model_identifier)``.

    When ``PSAT_LLM_STUB_DIR`` is set, routes to fixture files keyed by the
    SHA-256 of the prompt, falling back to ``_default.json``. Lets
    integration tests run deterministically without OpenRouter.
    """
    stub_dir = os.environ.get("PSAT_LLM_STUB_DIR")
    if stub_dir:
        digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        base = Path(stub_dir)
        specific = base / f"{digest}.json"
        if specific.exists():
            return specific.read_text(), f"stub:{digest[:12]}"
        default = base / "_default.json"
        if default.exists():
            return default.read_text(), "stub:_default"
        raise LLMUnavailableError(f"no LLM stub for prompt digest {digest} in {stub_dir}")

    try:
        from utils.llm import openrouter
    except Exception as exc:  # pragma: no cover - dep configured in pyproject
        raise LLMUnavailableError(f"openrouter client unavailable: {exc}") from exc

    model = os.environ.get("PSAT_SCOPE_LLM_MODEL", "google/gemini-2.5-flash-lite")
    try:
        response = openrouter.chat(
            [{"role": "user", "content": prompt}],
            model=model,
            max_tokens=4096,
            temperature=0.0,
        )
    except Exception as exc:
        raise LLMUnavailableError(f"LLM call failed: {exc}") from exc
    return response, model


def _clean_name(candidate: Any) -> str:
    """Normalize one raw LLM-output name: strip, drop .sol/.vy, leave casing."""
    if isinstance(candidate, str):
        text = candidate.strip()
    elif isinstance(candidate, dict):
        raw = candidate.get("contract_name") or candidate.get("name") or candidate.get("file")
        text = str(raw).strip() if raw else ""
    else:
        text = ""
    if not text:
        return ""
    return re.sub(r"\.(?:sol|vy)$", "", text, flags=re.IGNORECASE)


def _parse_scope_entry(raw: Any) -> dict[str, Any] | None:
    """Validate + normalize one scope_entries element from LLM output.

    Returns the cleaned entry or ``None`` when the entry doesn't pass
    address-format / name-required checks. The full PDF-text hallucination
    filter is applied separately in ``_validate.py`` — this function only
    handles shape + format.
    """
    if not isinstance(raw, dict):
        return None
    name = _clean_name(raw.get("name") or raw.get("contract_name") or raw.get("file"))
    if not name:
        return None
    address_raw = raw.get("address")
    address = None
    if isinstance(address_raw, str):
        addr_clean = address_raw.strip().lower()
        if _ADDRESS_RE.match(addr_clean):
            address = addr_clean
    # Require an address — the whole point of scope_entries is address-anchored
    # matching. Drop entries without one; the caller's ``contracts`` list
    # will still capture the name.
    if address is None:
        return None
    commit_raw = raw.get("commit")
    commit = None
    if isinstance(commit_raw, str):
        commit_clean = commit_raw.strip().lower()
        if _COMMIT_RE.match(commit_clean):
            commit = commit_clean
    chain_id = None
    if raw.get("chain_id") is not None:
        chain_id = require_supported_chain_id(
            chain_id=raw.get("chain_id"),
            context=f"audit scope entry {name} {address}",
        )
    elif isinstance(raw.get("chain"), str) and raw["chain"].strip():
        raw_chain_label = raw["chain"].strip().lower()
        logger.error("Audit scope entry returned legacy chain label instead of chain_id: %r", raw_chain_label)
        raise RuntimeError(f"Audit scope entry requires chain_id, got legacy chain label {raw_chain_label!r}")
    return {
        "name": name,
        "address": address,
        "commit": commit,
        "chain_id": chain_id,
    }


def _dedupe_names(raw_list: Any) -> list[str]:
    """Dedupe + normalize a list of LLM-output names."""
    names: list[str] = []
    seen: set[str] = set()
    if not isinstance(raw_list, list):
        return names
    for item in raw_list:
        stem = _clean_name(item)
        if not stem:
            continue
        key = stem.lower()
        if key in seen:
            continue
        seen.add(key)
        names.append(stem)
    return names


def _parse_classified_commit(raw: Any) -> dict[str, Any] | None:
    """Validate one ``classified_commits`` entry — shape + SHA + label."""
    if not isinstance(raw, dict):
        return None
    sha_raw = raw.get("sha")
    if not isinstance(sha_raw, str):
        return None
    sha = sha_raw.strip().lower()
    if not _COMMIT_RE.match(sha):
        return None
    # All-same-char tokens (0000000, ffffffff) = padding, not a real SHA.
    if len(set(sha)) < 3:
        return None
    label_raw = raw.get("label")
    label = label_raw.strip().lower() if isinstance(label_raw, str) else ""
    if label not in _COMMIT_LABELS:
        label = "unclear"
    context_raw = raw.get("context")
    context = str(context_raw).strip() if context_raw else ""
    # Cap context to keep the JSONB payload bounded.
    if len(context) > 400:
        context = context[:400]
    return {"sha": sha, "label": label, "context": context}


def _dedupe_classified_commits(raw_commits: Any) -> list[dict[str, Any]]:
    """Dedupe classified commits by SHA, preferring stronger labels.

    When the same SHA appears multiple times with different labels,
    rank ``reviewed > fix > cited > unclear`` so a strong label isn't
    silently overwritten by a weaker one.
    """
    rank = {"reviewed": 3, "fix": 2, "cited": 1, "unclear": 0}
    by_sha: dict[str, dict[str, Any]] = {}
    if not isinstance(raw_commits, list):
        return []
    for raw in raw_commits:
        entry = _parse_classified_commit(raw)
        if entry is None:
            continue
        existing = by_sha.get(entry["sha"])
        if existing is None or rank[entry["label"]] > rank[existing["label"]]:
            by_sha[entry["sha"]] = entry
    return list(by_sha.values())


def _dedupe_entries(raw_entries: Any) -> list[dict[str, Any]]:
    """Dedupe scope_entries by (name_lower, address_lower)."""
    entries: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    if not isinstance(raw_entries, list):
        return entries
    for raw in raw_entries:
        entry = _parse_scope_entry(raw)
        if entry is None:
            continue
        key = (entry["name"].lower(), entry["address"])
        if key in seen:
            continue
        seen.add(key)
        entries.append(entry)
    return entries


def extract_scope_with_llm(
    sections: list[ScopeSection], title: str, auditor: str
) -> tuple[list[str], list[dict[str, Any]], list[dict[str, Any]], str, str]:
    """Call the LLM for the scope list + structured entries + commit labels.

    Returns ``(names, scope_entries, classified_commits, raw_response, model)``.

    - ``scope_entries`` — list of ``{name, address, commit, chain_id}`` dicts
      for audits whose scope section had an explicit address column;
      empty list for legacy prose-style scope sections (Phase F).
    - ``classified_commits`` — list of ``{sha, label, context}`` where
      ``label ∈ {reviewed, fix, cited, unclear}``. Empty when no SHAs
      appear in the text (Phase C).

    Accepts the legacy array form (list of name strings) and the object
    forms from scope-v2 (``{contracts, scope_entries}``) and scope-v3
    (``{contracts, scope_entries, classified_commits}``). Missing keys
    default to empty lists so the function never raises on shape drift.

    Raises ``LLMUnavailableError`` on call failure or unparseable output.
    Hallucination filtering happens later in ``validate_contracts``.
    """
    from services.discovery.audit_reports_llm import _parse_json_array, _parse_json_object

    prompt = _build_prompt(sections, title, auditor)
    response, model = _call_llm(prompt)

    # Try the new object form first — it carries more information.
    parsed_obj = _parse_json_object(response)
    if parsed_obj is not None and (
        "contracts" in parsed_obj or "scope_entries" in parsed_obj or "classified_commits" in parsed_obj
    ):
        names = _dedupe_names(parsed_obj.get("contracts"))
        scope_entries = _dedupe_entries(parsed_obj.get("scope_entries"))
        classified_commits = _dedupe_classified_commits(parsed_obj.get("classified_commits"))
        # Ensure every scope_entry's name is also in contracts — the prompt
        # requires this but LLMs drift. Silently add missing ones.
        known = {n.lower() for n in names}
        for e in scope_entries:
            if e["name"].lower() not in known:
                names.append(e["name"])
                known.add(e["name"].lower())
        return names, scope_entries, classified_commits, response, model

    # Fall back to legacy array form.
    parsed = _parse_json_array(response)
    if parsed is None:
        raise LLMUnavailableError(f"LLM returned unparseable output: {response[:200]!r}")
    return _dedupe_names(parsed), [], [], response, model
