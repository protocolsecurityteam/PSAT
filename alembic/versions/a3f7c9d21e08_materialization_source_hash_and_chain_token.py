"""code-plane reuse: source_content_hash + inv-11 chain-token on contract_materializations

Revision ID: a3f7c9d21e08
Revises: f3a9c1d47b02
Create Date: 2026-07-17 12:00:00.000000

Two independent, populated-prod-safe changes to ``contract_materializations``
(expand-contract, invariant 9):

1. **source_content_hash (invariant 1 — code-plane reuse).** A nullable content
   hash of the normalized verified-source set. The ``(chain, bytecode_keccak)``
   key only reuses a bundle across byte-identical deployments; per-chain
   immutables make the same source compile to different bytecode, so keccak
   misses for real cross-chain deployments. The source hash is chain- and
   address-independent, so a bundle analyzed on one chain can be reused for the
   same source on another. **No backfill:** the hash is only computable from the
   verified source (not stored on the row), and legacy rows are simply never a
   hash-lookup donor — they fall through to a normal build and get a hash on
   their next (re)materialization. A nullable column add is metadata-only in
   Postgres 11+, so this is safe inside the default ``lock_timeout``.

2. **chain token normalization (invariant 11).** The ``chain`` key becomes the
   canonical decimal-string chain id (``"1"``, ``"8453"``) so a name-keyed
   writer and an id-keyed reader hit the same row, matching
   ``mapping_enumeration_cache``. Existing rows keyed by name (``"ethereum"``)
   are normalized to the id token. **Collision-safe:** a row is only re-keyed
   when no row already occupies the target ``(id, keccak)`` PK or ``(id,
   address)`` unique key; a would-be collision is left on its old (stale) key —
   per inv-11 a stale cache key is a miss, not corruption. ``*_blob_key`` columns
   are NOT rewritten: materialization blobs are content-addressed by the old
   ``{chain}/{keccak}`` path, never moved, and reads dereference the stored key
   column directly, so the pointer stays valid.

Downgrade drops the index and column. The chain-token normalization is a data
migration and is deliberately NOT reversed — id tokens are valid keys either
way, and pre-normalization code read through the same normalizer path once it is
in place; a rolled-back binary simply treats any unmatched row as a cache miss.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# Ensure the project root is importable when alembic runs from a differing CI
# working directory (mirrors f3a9c1d47b02).
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from utils.chains import chain_cache_token  # noqa: E402

revision: str = "a3f7c9d21e08"
down_revision: Union[str, Sequence[str], None] = "f3a9c1d47b02"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.runtime.migration")

_INDEX = "ix_contract_materializations_source_content_hash"


def upgrade() -> None:
    bind = op.get_bind()

    op.add_column(
        "contract_materializations",
        sa.Column("source_content_hash", sa.String(length=66), nullable=True),
    )
    op.create_index(_INDEX, "contract_materializations", ["source_content_hash"])

    _normalize_chain_tokens(bind)


def _normalize_chain_tokens(bind: sa.engine.Connection) -> None:
    """Re-key each distinct ``chain`` value to its decimal-id token, skipping any
    row whose target key is already occupied (left as a stale-key cache miss)."""
    distinct = bind.execute(sa.text("SELECT DISTINCT chain FROM contract_materializations")).fetchall()
    for row in distinct:
        raw = row.chain
        if raw is None:
            continue
        token = chain_cache_token(raw)
        if token == raw:
            continue
        # Only move rows that will not collide on either the PK (chain,
        # bytecode_keccak) or the (chain, address) unique constraint.
        result = bind.execute(
            sa.text(
                "UPDATE contract_materializations m SET chain = :token "
                "WHERE m.chain = :raw "
                "  AND NOT EXISTS ("
                "    SELECT 1 FROM contract_materializations o "
                "    WHERE o.chain = :token AND o.bytecode_keccak = m.bytecode_keccak) "
                "  AND NOT EXISTS ("
                "    SELECT 1 FROM contract_materializations o2 "
                "    WHERE o2.chain = :token AND o2.address = m.address)"
            ),
            {"token": token, "raw": raw},
        )
        moved = result.rowcount or 0
        skipped_res = bind.execute(
            sa.text("SELECT COUNT(*) FROM contract_materializations WHERE chain = :raw"),
            {"raw": raw},
        )
        skipped = skipped_res.scalar() or 0
        logger.info(
            "normalize contract_materializations.chain: %r -> %r, %d moved, %d left (collision→stale key)",
            raw,
            token,
            moved,
            skipped,
        )


def downgrade() -> None:
    op.drop_index(_INDEX, table_name="contract_materializations")
    op.drop_column("contract_materializations", "source_content_hash")
