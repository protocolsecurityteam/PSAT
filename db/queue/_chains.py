"""Chain-name helpers shared by the queue submodules."""

from __future__ import annotations

from db.models import Job
from utils.chains import UnknownChainError, canonical_chain, chain_by_id


def _job_chain_name(job: Job) -> str:
    """Canonical chain name of *job*, from the first-class ``chain_id`` column
    (falling back to the request chain; mainnet when underivable). Used to
    chain-qualify Contract lookups tied to a specific job so a same-address
    deployment on another chain can never stand in."""
    chain_id = getattr(job, "chain_id", None)
    if isinstance(chain_id, int):
        try:
            return chain_by_id(chain_id).name
        except UnknownChainError:
            return "ethereum"
    request = job.request if isinstance(job.request, dict) else {}
    return canonical_chain(request.get("chain")) or "ethereum"


def _mainnet_coalesced_chain(chain: str | None) -> str:
    """Mainnet-coalesced dedup key.

    Legacy rows persisted ``chain=NULL`` for mainnet, so coalescing
    ``NULL``→``'ethereum'`` lets a mainnet write dedup against them while a
    non-mainnet write (its own name ≠ ``'ethereum'``) stays isolated, and the
    ``'unknown'`` resolve-later bucket keeps its own identity. Mirrors the
    ``coalesce(chain,'ethereum')`` predicate in ``workers/discovery.py``'s
    single-row path so both writers match each other's rows regardless of
    historical NULLs.
    """
    return (chain or "ethereum").lower()
