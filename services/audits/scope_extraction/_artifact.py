"""Scope artifact payload assembly + object-storage write."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Final

from db.storage import StorageUnavailable, get_storage_client

from ._llm import PROMPT_VERSION
from ._utils import scope_artifact_key

logger = logging.getLogger(__name__)

SCOPE_ARTIFACT_CONTENT_TYPE: Final[str] = "application/json"


def build_artifact_payload(
    contracts: list[str],
    *,
    method: str,
    model: str | None,
    extracted_date: str | None,
    raw_response: str | None,
    scope_section_text: str | None = None,
    scope_entries: list[dict] | None = None,
    classified_commits: list[dict] | None = None,
) -> dict[str, object]:
    """Build the JSON body stored at ``scope_artifact_key``.

    ``scope_section_text`` is what the LLM actually saw — the merged
    header/content-pattern slice, or the winning chunk for chunk-scan.
    Capped at 20k chars. ``scope_entries`` (Phase F) is the structured
    per-entry (name, address, commit, chain_id) list when the PDF had a
    scope table with addresses; empty otherwise. ``classified_commits``
    (Phase C) is the LLM-labeled commit list with roles.
    """
    sliced = scope_section_text[:20_000] if scope_section_text else None
    return {
        "contracts": list(contracts),
        "scope_entries": list(scope_entries or []),
        "classified_commits": list(classified_commits or []),
        "extracted_date": extracted_date,
        "method": method,
        "model": model,
        "prompt_version": PROMPT_VERSION,
        "extracted_at": datetime.now(timezone.utc).isoformat(),
        "raw_llm_response": raw_response,
        "scope_section_text": sliced,
    }


def _store_artifact(audit_id: int, payload: dict[str, object]) -> str | None:
    """Write the payload to object storage, returning the key or ``None``.

    Returns None when storage isn't configured — the contracts still reach
    ``scope_contracts`` on the row; the blob is a debug nice-to-have.
    """
    client = get_storage_client()
    if client is None:
        logger.warning(
            "scope: storage client unavailable; skipping artifact write for audit %s",
            audit_id,
        )
        return None
    key = scope_artifact_key(audit_id)
    body = json.dumps(payload, sort_keys=False).encode("utf-8")
    try:
        client.put(
            key,
            body,
            SCOPE_ARTIFACT_CONTENT_TYPE,
            metadata={
                "audit_report_id": str(audit_id),
                "method": str(payload.get("method") or ""),
            },
        )
    except StorageUnavailable as exc:
        logger.warning("scope: storage put failed for %s: %s", audit_id, exc)
        return None
    return key
