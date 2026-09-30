"""One-shot backfill: move contract_materializations.{analysis,tracking_plan} JSONB into object storage and populate
``*_blob_key``.

Bundles are 5-20MB per row and JSONB is detoasted on every read, bloating page cache and dumps. The row stays the source
of truth for which keccak was built; only the payload moves.

Idempotent (rows with ``analysis_blob_key`` are skipped); exits non-zero if any row fails.

    uv run python -m scripts.backfill_contract_materializations_to_blob --dry-run
    uv run python -m scripts.backfill_contract_materializations_to_blob
    uv run python -m scripts.backfill_contract_materializations_to_blob \
        --chunk-size 25 --chain ethereum

Inline JSONB is kept unless ``--clear-jsonb``. Sequence:

  1. Deploy the blob-only writer.
  2. Run without --clear-jsonb (old rows keep both for one TTL cycle).
  3. Verify reads via ``hydrate_*``.
  4. Re-run with --clear-jsonb.
  5. Optionally drop the ``analysis`` / ``tracking_plan`` columns.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from db.contract_materializations import _blob_key
from db.models import ContractMaterialization, SessionLocal
from db.storage import JSON_CONTENT_TYPE, StorageError, get_storage_client
from utils.logging import configure_logging

logger = logging.getLogger(__name__)


def _serialize(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, default=str).encode("utf-8")


def _backfill_row(
    session: Session,
    row: ContractMaterialization,
    *,
    client,
    dry_run: bool,
    clear_jsonb: bool,
) -> tuple[int, int]:
    """Returns ``(blobs_written, bytes_uploaded)``; skips payloads already keyed or absent."""
    blobs_written = 0
    bytes_uploaded = 0

    updates: dict[str, Any] = {}

    if row.analysis_blob_key is None and row.analysis is not None:
        key = _blob_key(row.chain, row.bytecode_keccak, "analysis")
        body = _serialize(row.analysis)
        if not dry_run:
            client.put(key, body, JSON_CONTENT_TYPE)
        updates["analysis_blob_key"] = key
        if clear_jsonb:
            updates["analysis"] = None
        blobs_written += 1
        bytes_uploaded += len(body)

    if row.tracking_plan_blob_key is None and row.tracking_plan is not None:
        key = _blob_key(row.chain, row.bytecode_keccak, "tracking_plan")
        body = _serialize(row.tracking_plan)
        if not dry_run:
            client.put(key, body, JSON_CONTENT_TYPE)
        updates["tracking_plan_blob_key"] = key
        if clear_jsonb:
            updates["tracking_plan"] = None
        blobs_written += 1
        bytes_uploaded += len(body)

    if updates and not dry_run:
        session.execute(
            update(ContractMaterialization)
            .where(
                ContractMaterialization.chain == row.chain,
                ContractMaterialization.bytecode_keccak == row.bytecode_keccak,
            )
            .values(**updates)
        )
        session.commit()

    return blobs_written, bytes_uploaded


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="Report what would be written; no Tigris/DB writes.")
    ap.add_argument("--chunk-size", type=int, default=50, help="Rows per DB query batch (default 50).")
    ap.add_argument("--chain", default=None, help="Restrict to one chain (default: all chains).")
    ap.add_argument(
        "--clear-jsonb",
        action="store_true",
        help="Set analysis/tracking_plan JSONB to NULL after blob upload. Off by default — run twice "
        "(once without to populate blob_key, once with to reclaim JSONB space) so a rollback in "
        "between is safe.",
    )
    args = ap.parse_args(argv)

    configure_logging()

    client = get_storage_client()
    if client is None and not args.dry_run:
        logger.error(
            "ARTIFACT_STORAGE_* env vars not set — refusing to backfill without object storage. "
            "Set ARTIFACT_STORAGE_ENDPOINT, _BUCKET, _ACCESS_KEY, _SECRET_KEY (and PREFIX for previews).",
        )
        return 2

    total_rows = 0
    total_blobs = 0
    total_bytes = 0
    failed_rows: list[str] = []

    session = SessionLocal()
    try:
        # Keyset by last-seen keccak so no cursor is held open across slow uploads.
        last_chain: str | None = None
        last_keccak: str | None = None
        while True:
            stmt = select(ContractMaterialization).where(
                ContractMaterialization.status == "ready",
            )
            if args.chain:
                # Rows use the decimal-id chain token (inv. 11).
                from utils.chains import chain_cache_token

                stmt = stmt.where(ContractMaterialization.chain == chain_cache_token(args.chain))
            if last_chain is not None and last_keccak is not None:
                stmt = stmt.where(
                    (ContractMaterialization.chain > last_chain)
                    | (
                        (ContractMaterialization.chain == last_chain)
                        & (ContractMaterialization.bytecode_keccak > last_keccak)
                    )
                )
            stmt = stmt.order_by(
                ContractMaterialization.chain,
                ContractMaterialization.bytecode_keccak,
            ).limit(args.chunk_size)

            rows = list(session.execute(stmt).scalars())
            if not rows:
                break

            for row in rows:
                total_rows += 1
                last_chain = row.chain
                last_keccak = row.bytecode_keccak
                row_id = f"{row.chain}:{row.bytecode_keccak[:18]}"

                if (row.analysis_blob_key is not None or row.analysis is None) and (
                    row.tracking_plan_blob_key is not None or row.tracking_plan is None
                ):
                    continue

                try:
                    written, uploaded = _backfill_row(
                        session,
                        row,
                        client=client,
                        dry_run=args.dry_run,
                        clear_jsonb=args.clear_jsonb,
                    )
                except StorageError as exc:
                    logger.warning(
                        "backfill: row %s upload failed",
                        row_id,
                        extra={"exc_type": type(exc).__name__, "row_id": row_id},
                    )
                    failed_rows.append(row_id)
                    session.rollback()
                    continue
                except Exception as exc:
                    # Unknown shape, so keep the traceback; WARNING because the run continues and the summary fails it.
                    logger.warning(
                        "backfill: row %s unexpected error",
                        row_id,
                        exc_info=exc,
                        extra={"exc_type": type(exc).__name__, "row_id": row_id},
                    )
                    failed_rows.append(row_id)
                    session.rollback()
                    continue

                if written:
                    total_blobs += written
                    total_bytes += uploaded
                    logger.info(
                        "backfill: %s wrote %d blob(s) totaling %.1f KB (dry_run=%s, clear_jsonb=%s)",
                        row_id,
                        written,
                        uploaded / 1024,
                        args.dry_run,
                        args.clear_jsonb,
                    )
    finally:
        session.close()

    summary = (
        f"backfill complete: rows_scanned={total_rows} blobs_written={total_blobs} "
        f"bytes_uploaded={total_bytes} failed_rows={len(failed_rows)} "
        f"dry_run={args.dry_run} clear_jsonb={args.clear_jsonb}"
    )
    if failed_rows:
        logger.error("%s; failed: %s", summary, ", ".join(failed_rows[:10]))
        return 1
    logger.info(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
