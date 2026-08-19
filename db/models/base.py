"""Declarative base, job vocab enums, chain-id derivation, and the alembic autogenerate filter."""

from __future__ import annotations

import enum
import logging
from typing import Any

from sqlalchemy.orm import DeclarativeBase

from utils.chains import UnknownChainError, chain_by_name


def _sql_tuple(values: tuple[str, ...]) -> str:
    """A SQL ``IN`` list built from the vocabulary module.

    The constraint text and the producer must name the same strings; spelling
    them twice is how a domain check drifts into permitting a value the writer
    can no longer produce (or refusing one it can).
    """
    return "(" + ", ".join(f"'{value}'" for value in values) + ")"


logger = logging.getLogger("db.models")


class Base(DeclarativeBase):
    pass


class JobStatus(str, enum.Enum):
    queued = "queued"
    processing = "processing"
    completed = "completed"
    # Transient/retryable failure. ``BaseWorker`` requeues the row with a
    # backoff-set ``next_attempt_at`` after the first transient exception;
    # only after retries are exhausted does the row move to ``failed_terminal``.
    failed = "failed"
    # Terminal failure: deterministic-from-the-start (e.g. ValueError on bad
    # input, missing Etherscan source) or transient retries exhausted. The
    # stale-job sweep never resurrects ``failed_terminal`` rows.
    failed_terminal = "failed_terminal"


class JobStage(str, enum.Enum):
    discovery = "discovery"
    dapp_crawl = "dapp_crawl"
    defillama_scan = "defillama_scan"
    selection = "selection"
    static = "static"
    resolution = "resolution"
    policy = "policy"
    # Behavioral effect simulation. Inserted between policy
    # and coverage; source order IS the progression, so this position makes
    # ``_satisfy_dependencies`` (relative enum order) route it correctly. The
    # policy->effects transition is feature-flagged (PSAT_EFFECTS_STAGE); with
    # the flag off, policy advances straight to coverage and this stage is inert.
    effects = "effects"
    coverage = "coverage"
    done = "done"


def derive_job_chain_id(chain_value: Any, address: str | None) -> int | None:
    """Resolve a job's first-class ``chain_id`` from its ``request["chain"]``.

    Single source of derivation truth for the ``jobs.chain_id`` dual-write
    (invariant 1). Address-less company/root jobs carry no chain identity
    (a deployment concept) and return None; the CHECK constraint permits that.
    For address-scoped jobs the chain string resolves through the canonical
    registry; missing/empty is the mainnet edge default, and an unrecognized
    value (typo, the ``"unknown"`` sentinel, or a non-string) falls back to
    mainnet with a warning so a misconfiguration is visible without changing
    mainnet behaviour. Mirrors the M0.2 migration backfill so dual-written and
    legacy rows agree.
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
    """Column ``default`` for ``jobs.chain_id`` — fires only when a row is
    inserted without an explicit chain_id.

    ``db.queue.create_job`` sets chain_id explicitly (the enqueue-path
    dual-write), so this never runs on the production path. It is a
    defense-in-depth net: any direct ``Job(...)`` construction (only tests
    today) still gets a derived chain_id from its own ``request["chain"]`` and
    can't violate the CHECK constraint. Never a constant default — always the
    same registry-backed derivation."""
    params = context.get_current_parameters()
    request = params.get("request")
    chain = request.get("chain") if isinstance(request, dict) else None
    return derive_job_chain_id(chain, params.get("address"))


def include_object(obj, name, type_, reflected, compare_to) -> bool:
    """Alembic autogenerate filter: keep mapped VIEWs out.

    ``ContractBalanceLatest`` maps the ``contract_balances_latest`` view so ORM
    readers can swap entity without hand-written SQL. Alembic cannot tell a
    mapped view from a mapped table, so without this it would report the view as
    a missing TABLE and a later autogenerate would emit a ``CREATE TABLE`` that
    shadows it. Keyed on the ``info={"is_view": True}`` marker the model carries,
    not on a name list, so a future view is covered by declaring the marker.

    Lives here rather than in ``alembic/env.py`` because that module runs
    migrations at import time and cannot be imported by the drift test that
    proves this filter works.
    """
    if type_ == "table" and (obj.info or {}).get("is_view"):
        return False
    return True
