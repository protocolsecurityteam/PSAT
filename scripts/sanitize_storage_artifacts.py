#!/usr/bin/env python3
"""Apply ``utils.secrets.sanitize_obj`` to storage-backed artifact bodies.

Companion to alembic migration ``67bd81b64faa``, which sanitizes the
DB-resident rows. This script handles artifact bodies whose
``storage_key`` points into object storage. Targets the
``dependencies`` / ``dynamic_dependencies`` / ``stage_errors`` names.
Idempotent.

Usage::

    uv run python scripts/sanitize_storage_artifacts.py --dry-run
    uv run python scripts/sanitize_storage_artifacts.py

Requires the same ``ARTIFACT_STORAGE_*`` env vars as the API/workers.
Exit code 0 on success, 1 on any per-row error.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# Project root on sys.path so the script runs from anywhere.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from sqlalchemy import select  # noqa: E402

from db.models import Artifact, SessionLocal  # noqa: E402
from db.storage import (  # noqa: E402
    JSON_CONTENT_TYPE,
    StorageError,
    StorageKeyMissing,
    deserialize_artifact,
    get_storage_client,
)
from utils.secrets import sanitize_obj  # noqa: E402

logger = logging.getLogger("sanitize_storage_artifacts")

_TARGET_NAMES = (
    "dependencies",
    "static_dependencies",
    "dynamic_dependencies",
    "classifications",
    "contract_flags",
    "dependency_errors",
    "stage_errors",
)

_DROP_RPC_KEY_NAMES = frozenset({"dependencies", "static_dependencies", "dynamic_dependencies", "classifications"})


def _clean_body(name: str, body: object) -> tuple[object, bool]:
    """Return (cleaned, changed). ``changed`` is False on a no-op pass."""
    cleaned = sanitize_obj(body)
    if isinstance(cleaned, dict) and name in _DROP_RPC_KEY_NAMES:
        cleaned.pop("rpc", None)
    return cleaned, cleaned != body


def _process_one(client, artifact: Artifact, dry_run: bool) -> str:
    if not artifact.storage_key:
        return "skipped (no storage_key)"
    try:
        raw = client.get(artifact.storage_key)
    except StorageKeyMissing:
        return "skipped (key missing)"
    except StorageError as exc:
        raise RuntimeError(f"storage get failed for {artifact.storage_key}: {exc}") from exc

    try:
        body = deserialize_artifact(raw, artifact.content_type)
    except Exception as exc:
        return f"skipped (deserialize failed: {exc})"

    if not isinstance(body, (dict, list)):
        return "skipped (non-JSON body)"

    cleaned, changed = _clean_body(artifact.name, body)
    if not changed:
        return "unchanged"

    if dry_run:
        return "would-rewrite"

    new_bytes = json.dumps(cleaned, default=str).encode("utf-8")
    client.put(
        artifact.storage_key,
        new_bytes,
        artifact.content_type or JSON_CONTENT_TYPE,
    )
    return "rewrote"


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    parser.add_argument("--dry-run", action="store_true", help="Print actions without writing.")
    parser.add_argument(
        "--names",
        nargs="+",
        default=list(_TARGET_NAMES),
        help=f"Artifact names to process (default: {' '.join(_TARGET_NAMES)})",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    client = get_storage_client()
    if client is None:
        logger.error("No storage client configured (ARTIFACT_STORAGE_* unset). Nothing to do.")
        return 1

    counts: dict[str, int] = {"unchanged": 0, "rewrote": 0, "would-rewrite": 0, "errors": 0}
    skipped = 0

    with SessionLocal() as session:
        rows = (
            session.execute(
                select(Artifact).where(
                    Artifact.storage_key.is_not(None),
                    Artifact.name.in_(args.names),
                )
            )
            .scalars()
            .all()
        )

    logger.info("scanning %d storage-backed artifact row(s)", len(rows))
    for artifact in rows:
        try:
            outcome = _process_one(client, artifact, args.dry_run)
        except Exception as exc:
            logger.error("artifact %s (%s): %s", artifact.id, artifact.name, exc)
            counts["errors"] += 1
            continue
        if outcome.startswith("skipped"):
            skipped += 1
            logger.debug("artifact %s (%s) %s", artifact.id, artifact.name, outcome)
            continue
        counts[outcome] = counts.get(outcome, 0) + 1
        if outcome in {"rewrote", "would-rewrite"}:
            logger.info("artifact %s (%s) %s", artifact.id, artifact.name, outcome)

    logger.info(
        "done: rewrote=%d would-rewrite=%d unchanged=%d skipped=%d errors=%d",
        counts.get("rewrote", 0),
        counts.get("would-rewrite", 0),
        counts.get("unchanged", 0),
        skipped,
        counts.get("errors", 0),
    )
    return 1 if counts.get("errors", 0) else 0


if __name__ == "__main__":
    raise SystemExit(main())
