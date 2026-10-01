"""Declarative base, job vocab enums, chain-id derivation, and the alembic autogenerate filter."""

from __future__ import annotations

import enum
import logging
from typing import Any

from sqlalchemy.orm import DeclarativeBase

from utils.chains import UnknownChainError, chain_by_name


def _sql_tuple(values: tuple[str, ...]) -> str:
    """A SQL ``IN`` list from the vocabulary module, so the constraint and the producer name the same strings."""
    return "(" + ", ".join(f"'{value}'" for value in values) + ")"


logger = logging.getLogger("db.models")


class Base(DeclarativeBase):
    pass


class JobStatus(str, enum.Enum):
    queued = "queued"
    processing = "processing"
    completed = "completed"
    # Transient; ``BaseWorker`` requeues with backoff until retries run out.
    failed = "failed"
    # Deterministic failure or exhausted retries; the stale-job sweep never resurrects these.
    failed_terminal = "failed_terminal"


class JobStage(str, enum.Enum):
    discovery = "discovery"
    dapp_crawl = "dapp_crawl"
    defillama_scan = "defillama_scan"
    selection = "selection"
    static = "static"
    resolution = "resolution"
    policy = "policy"
    # Between policy and coverage; enum order is the progression (``_satisfy_dependencies``). Gated by
    # PSAT_EFFECTS_STAGE; off, policy goes straight to coverage.
    effects = "effects"
    coverage = "coverage"
    done = "done"


def derive_job_chain_id(chain_value: Any, address: str | None) -> int | None:
    """Resolve a job's ``chain_id`` from ``request["chain"]``.

    Address-less company/root jobs return None (allowed by the CHECK). Missing chain means mainnet; unrecognized values
    fall back to mainnet with a warning. Mirrors the M0.2 backfill.
    """
    if address is None:
        return None
    if chain_value is None or (isinstance(chain_value, str) and not chain_value.strip()):
        return 1
    try:
        return chain_by_name(chain_value).chain_id
    except UnknownChainError:
        logger.warning(
            "derive_job_chain_id: unrecognized chain %r for address %s; defaulting chain_id=1",
            chain_value,
            address,
        )
        return 1


def _job_chain_id_insert_default(context: Any) -> int | None:
    """Insert default for ``jobs.chain_id`` when none is given.

    ``create_job`` always sets it; this protects direct ``Job(...)`` construction (tests) from violating the CHECK.
    """
    params = context.get_current_parameters()
    request = params.get("request")
    chain = request.get("chain") if isinstance(request, dict) else None
    return derive_job_chain_id(chain, params.get("address"))


def include_object(obj, name, type_, reflected, compare_to) -> bool:
    """Alembic autogenerate filter that hides mapped views.

    Alembic can't tell a mapped view from a table and would emit a shadowing ``CREATE TABLE``. Keyed on
    ``info={"is_view": True}``, not names. Lives here because ``alembic/env.py`` runs migrations on import and can't be
    imported by the drift test.
    """
    if type_ == "table" and (obj.info or {}).get("is_view"):
        return False
    return True
