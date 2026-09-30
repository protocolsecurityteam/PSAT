"""Chain-name helpers shared by the queue submodules."""

from __future__ import annotations

from db.models import Job
from utils.chains import UnknownChainError, canonical_chain, chain_by_id


def _job_chain_name(job: Job) -> str:
    """Canonical chain name of *job* from ``chain_id`` (else the request chain, else mainnet), so job-scoped contract
    lookups never match another chain.
    """
    chain_id = getattr(job, "chain_id", None)
    if isinstance(chain_id, int):
        try:
            return chain_by_id(chain_id).name
        except UnknownChainError:
            return "ethereum"
    request = job.request if isinstance(job.request, dict) else {}
    return canonical_chain(request.get("chain")) or "ethereum"


def _mainnet_coalesced_chain(chain: str | None) -> str:
    """Mainnet-coalesced dedup key: legacy mainnet rows have ``chain=NULL``, so NULL is treated as ``'ethereum'``;
    other chains and the ``'unknown'`` bucket stay distinct. Mirrors ``workers/discovery.py``.
    """
    return (chain or "ethereum").lower()
