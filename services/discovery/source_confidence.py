"""Tier discovery evidence by whether it asserts protocol ownership.

Two distinct kinds of evidence can justify stamping ``Contract.protocol_id``:

1. **Direct evidence** — an authoritative source named the address.
   Examples: the protocol's deployer + CREATE/CREATE2 lineage, a curated
   DefiLlama entry, LLM extraction from the protocol's own docs.
   Encoded as ``HIGH_CONFIDENCE_SOURCES``.

2. **Structural evidence** — the contract is a same-protocol structural
   component of a directly-confirmed parent. Examples: the implementation
   wrapped by a confirmed proxy, the proxy shell fronting a confirmed
   impl, the beacon used by a confirmed UpgradeableBeacon family.
   Encoded as ``STRUCTURAL_OWNERSHIP_RELATIONSHIPS`` plus the
   ``parent_owns`` flag at the gate site.

Everything else — DApp UI scrapes, plain runtime CALL edges, controller
relationships — is *associative* evidence at best. The contract was seen
alongside the protocol but that doesn't make it part of the protocol.
WETH, stETH, OP-Stack predeploys and similar widely-held infrastructure
all show up here, which is how they used to leak into protocol
inventories.

The gate ``asserts_ownership()`` returns True iff either evidence branch
fires. Low/no evidence still creates Contract rows so the audit trail of
"who saw this" survives, but the row stays orphan (``protocol_id=NULL``)
until a future write promotes it via either branch.

Adding a new source: default to LOW_CONFIDENCE and only promote it after
confirming, on real data, that it doesn't pull in third-party
infrastructure. Sources not listed in either set are treated as low-
confidence — safer to require an explicit promotion than to opt new
sources in by default.

Adding a new structural relationship: classifier-derived; only add if a
``relationship_type`` value reliably means "same protocol component"
across the protocols we ingest. ``library`` is intentionally excluded
because the bucket is *heterogeneous*: the classifier's DELEGATECALL-only
heuristic correctly identifies real libraries (verified — it does NOT
mis-tag the primary proxy→impl edge), but the *targets* mix protocol-
internal helpers with shared infrastructure. In a single sample dataset
``BucketLimiter`` (etherfi-internal rate limiter) and ``SignatureChecker``
(Circle's USDC helper, shared across protocols) both land in the
``library`` bucket. Adopting either way would be wrong for the other.
Until there's a downstream signal that splits "internal helper" from
"shared lib," structural propagation skips this relationship type and
those rows stay orphan. Same-name address pairs (e.g. two different
contracts both called ``EtherFiOracle``) are common — never assume the
``dependency_name`` string equals the parent's identity without checking
addresses.
"""

from __future__ import annotations

# Sources that prove the address is deployed or controlled by the
# protocol — deployer-verified addresses, curated lists, or LLM-extracted
# entries from the protocol's own docs. These may stamp
# ``Contract.protocol_id``.
HIGH_CONFIDENCE_SOURCES: frozenset[str] = frozenset(
    {
        "deployer_expansion",  # known deployer + CREATE/CREATE2 lineage
        "defillama",  # curated public list of protocol contracts
        "ai_inventory",  # LLM extraction from official docs
        "exa_deep_research",  # research scan over official sources
        "inventory",  # admin/discovery-pipeline curated entry
        "spa_override",  # admin override entry
        "dependency_two_pass",  # static dependency from a confirmed contract
    }
)

# Sources that only prove the address was encountered while looking at
# the protocol — scraping every 0x... on a DApp UI, or walking a proxy's
# upgrade history when the proxy itself isn't confirmed-owned. They
# populate ``Contract.discovery_sources`` but must not stamp
# ``Contract.protocol_id`` on their own.
LOW_CONFIDENCE_SOURCES: frozenset[str] = frozenset(
    {
        "dapp_crawl",  # UI scrape — picks up every collateral / router / bridge
        "upgrade_history",  # only as strong as the parent proxy's own confirmation
        "structural_adoption",  # bookkeeping tag for adopted-via-structure rows
    }
)

# ``contract_dependencies.relationship_type`` values that mean the dep is
# the same protocol component as the parent — not a third-party callee.
# When the parent is HIGH-confidence-owned and the edge to a candidate
# contract has one of these labels, the candidate inherits ownership.
# ``library`` is omitted because the bucket mixes protocol-internal
# helpers (e.g. etherfi's BucketLimiter) with shared infrastructure
# (e.g. Circle's SignatureChecker) and the classifier can't tell them
# apart structurally. See module docstring for the data justification.
STRUCTURAL_OWNERSHIP_RELATIONSHIPS: frozenset[str] = frozenset(
    {
        "implementation",  # impl wrapped by a parent proxy
        "proxy",  # proxy shell fronting a parent impl
        "beacon",  # beacon authority used by a parent (OZ UpgradeableBeacon)
    }
)


def asserts_ownership(
    sources: list[str] | None,
    *,
    parent_owns: bool = False,
    parent_relationship: str | None = None,
) -> bool:
    """True iff we have evidence the contract is protocol-owned.

    Either branch may grant ownership:

    - **Direct**: ``sources`` contains a HIGH_CONFIDENCE tag.
    - **Structural**: ``parent_owns`` is True AND ``parent_relationship``
      is a structural same-protocol edge type. The cascade-spawn sites
      (resolution worker, static-worker proxy-impl cascade, upgrade-
      history backfill) compute these from the parent's own ownership
      check and the classifier-derived edge type.

    Empty / None counts as no evidence on the direct branch. An unknown
    source also counts as no evidence — see module docstring for why
    we don't opt new sources in by default.
    """
    if sources and any(s in HIGH_CONFIDENCE_SOURCES for s in sources):
        return True
    if parent_owns and parent_relationship in STRUCTURAL_OWNERSHIP_RELATIONSHIPS:
        return True
    return False
