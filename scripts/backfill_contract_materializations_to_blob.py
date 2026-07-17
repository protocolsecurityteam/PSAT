"""One-shot backfill: move contract_materializations.{analysis,tracking_plan}
out of Postgres JSONB into object storage, populating the
``*_blob_key`` columns and clearing the inline JSONB.

Why: JSONB is fine for storage but gets detoasted on every read,
inflates page-cache pressure on this hot table, and slows backup /
dump / restore — a Compound-v3-class analysis bundle is 5-20MB per
row and the cache can grow to thousands of rows. Moving the bytes to
Tigris lets the table itself stay tiny while keeping the dedup
semantics (the row continues to be the source of truth for which
keccak has been built; only the payload moves).

Idempotent: rows that already have ``analysis_blob_key`` set are
skipped. Safe to re-run after a partial completion. Exits non-zero
if any row fails so the operator can re-run targeted at the
remaining set.

Usage::

    # dry-run: report what would be written, no Tigris writes, no DB writes
    uv run python -m scripts.backfill_contract_materializations_to_blob --dry-run

    # actual backfill, default chunk size 50
    uv run python -m scripts.backfill_contract_materializations_to_blob

    # tune chunk size / scope to one chain
    uv run python -m scripts.backfill_contract_materializations_to_blob \
        --chunk-size 25 --chain ethereum

The script does NOT clear the inline JSONB columns by default —
``--clear-jsonb`` opts in. Recommended sequence:

  1. Deploy the new code (writes blob-only for fresh entries).
  2. Run this without --clear-jsonb. New rows have blob_key + NULL
     JSONB; old rows now have BOTH blob_key + JSONB (belt and
     suspenders for one TTL cycle).
  3. Verify reads are working via the blob path (``hydrate_*``).
  4. Re-run with --clear-jsonb to reclaim the JSONB space.
  5. Optional follow-up migration: drop the ``analysis`` /
     ``tracking_plan`` columns entirely.
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
    """Backfill one row. Returns ``(blobs_written, bytes_uploaded)``.

    Skips per-payload if the corresponding blob_key is already set
    (idempotent re-run) or the inline JSONB is None (nothing to move).
    """
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

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

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
        # Iterate by primary key with LIMIT/OFFSET-style chunking via
        # last-seen-keccak — avoids holding a server-side cursor open
        # across slow blob uploads.
        last_chain: str | None = None
        last_keccak: str | None = None
        while True:
            stmt = select(ContractMaterialization).where(
                ContractMaterialization.status == "ready",
            )
            if args.chain:
                # Rows are keyed by the canonical decimal-id chain token (inv. 11),
                # so normalize a name/alias/id filter through the same function.
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

                # Skip rows that have nothing to move.
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
                    logger.error("backfill: row %s upload failed: %s", row_id, exc)
                    failed_rows.append(row_id)
                    session.rollback()
                    continue
                except Exception:
                    logger.exception("backfill: row %s unexpected error", row_id)
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
