"""Adopt the two remaining orphan classes left after 3a8f4d1c9b07.

Revision ID: 4d72e9b1f035
Revises: 3a8f4d1c9b07
Create Date: 2026-05-20 00:00:00.000000

The fifth + sixth structural-adoption branches (companion to
``3a8f4d1c9b07`` which covers current-impl, current-proxy,
current-beacon edges). Closes two false-negative classes surfaced when
investigating PR-87's etherfi orphans:

**Branch A: deployer-cascade.** An orphan landed in the DB via the
resolution worker's dependency-cascade spawn
(``workers/resolution_worker.py:499-513``), which only propagates
``discovery_relationship`` for impl / beacon edges. Plain-function-call
deps arrive with NULL ``discovery_sources`` and no structural signal —
even when their Etherscan-recorded deployer is one of the protocol's
qualified deployer EOAs. Rescue criterion: the orphan's ``deployer``
matches the deployer of some HIGH-sourced contract already attributed
to a protocol. Empirically (PR-87): adopts the 6 known etherfi
orphans (EtherFiNode, EtherFiRateLimiter, EtherfiL1SyncPoolETH plus
their three proxy parents) plus 9 BoringVault-stack contracts
(Accountant, LayerZeroTeller, RolesAuthority, TimelockController,
PriorityWithdrawalQueue, an extra UUPSProxy). Zero shared-infra leaks
observed.

**Branch B: historical-impl behind a HIGH-impl proxy.** A row created
by ``backfill_historical_impl_contracts`` for a past implementation
behind an upgradeable proxy whose CURRENT implementation is HIGH-
sourced. Mirrors ``3a8f4d1c9b07``'s fourth branch (proxy-of-HIGH-impl)
— the proxy itself can be LOW-sourced (e.g. a UUPSProxy adopted via
``structural_adoption`` from its HIGH impl); the authoritative anchor
is the CURRENT impl, not the proxy. Walking the proxy's full upgrade
history via ``UpgradeEvent.new_impl`` then sweeps the prior impl rows
into the same protocol. Empirically (PR-87): adopts 5 LRTSquare*
historical impls behind the LRTSquaredCore-impl + UUPSProxy chain
where UUPSProxy carries only ``structural_adoption`` (LOW) but its
``Contract.implementation`` resolves to HIGH-sourced LRTSquaredCore.

Both branches require HIGH evidence anchoring the chain — Branch A on
the sibling, Branch B on the proxy's current impl. A foreign proxy
imported via ``dapp_crawl`` whose current impl is ALSO LOW-sourced (or
orphan) has no HIGH evidence anywhere in the chain and adopts zero
historical impls. The EigenLayer leak shape the original gate closed
stays closed.

Cross-protocol collisions — an orphan whose evidence resolves to
multiple distinct protocols — are skipped + logged for manual review.
Same convention as ``3a8f4d1c9b07``.

The HIGH source list is inlined as a literal because migrations are
deploy-time snapshots; the values are a frozen legacy copy of the
retired source-confidence tiers (superseded by the membership gate).
"""

from __future__ import annotations

import logging
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "4d72e9b1f035"
down_revision: Union[str, Sequence[str], None] = "3a8f4d1c9b07"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


logger = logging.getLogger("alembic.runtime.migration")


# Resolves each orphan's matching protocols via either branch:
#
#   A. deployer-cascade — orphan.deployer matches the deployer of a
#      HIGH-sourced contract attributed to protocol P.
#   B. historical-impl — orphan.address appears in UpgradeEvent.new_impl
#      for a proxy whose CURRENT implementation is HIGH-sourced and
#      attributed to protocol P. (The proxy itself may be LOW-sourced —
#      e.g. a UUPSProxy adopted via ``structural_adoption`` — because
#      the authoritative anchor is the impl, not the proxy shell.)
#
# An orphan can match via either branch; if multiple distinct
# protocols match, the orphan is skipped for manual review (this
# mirrors the cross-protocol-collision skip in ``3a8f4d1c9b07``). The
# ``dominant_protocol`` is the protocol with the most matching
# evidence rows — used only when there is no cross-protocol ambiguity.
#
# HIGH set snapshot — frozen legacy copy of the retired source-confidence
# tiers; values deliberately not shared with live code.
_SELECT_REMAINING_ORPHANS = sa.text(
    """
    WITH high_sourced_deployer AS (
        SELECT
            lower(c.deployer) AS deployer_lc,
            c.protocol_id     AS protocol_id,
            COUNT(*)          AS n
        FROM contracts c
        WHERE c.protocol_id IS NOT NULL
          AND c.deployer IS NOT NULL
          AND c.discovery_sources && ARRAY[
            'deployer_expansion','defillama','ai_inventory',
            'exa_deep_research','inventory','spa_override','dependency_two_pass'
          ]::varchar[]
        GROUP BY lower(c.deployer), c.protocol_id
    ),
    -- Branch B map: every (historical impl address → owning protocol)
    -- pair where the proxy's CURRENT implementation is HIGH-sourced.
    -- The proxy is the ``contract_id`` on the UpgradeEvent row;
    -- ``new_impl`` is the impl the proxy delegated to at that point in
    -- time. We anchor on ``proxy.implementation``'s HIGH source rather
    -- than the proxy's own sources because the proxy is just a
    -- structural intermediary — in the LRTSquare* shape the proxy
    -- carries only ``structural_adoption`` (LOW) while LRTSquaredCore
    -- (the current impl) is HIGH-sourced via ``deployer_expansion``.
    -- This mirrors ``3a8f4d1c9b07``'s fourth branch (proxy-of-HIGH-
    -- impl) and respects the same one-hop-from-HIGH discipline.
    --
    -- The zero-address and NULL filters drop the synthetic "pre-init"
    -- event rows that some backfill paths emit.
    --
    -- Belt-and-suspenders guard: if the proxy has its own
    -- ``protocol_id`` set (the typical case post-3a8f4d1c9b07), it
    -- must agree with the impl's — otherwise a cross-protocol fork
    -- chain could leak historical impls in.
    high_sourced_historical_impl AS (
        SELECT
            lower(ue.new_impl) AS impl_addr_lc,
            impl.protocol_id   AS protocol_id,
            COUNT(*)           AS n
        FROM upgrade_events ue
        JOIN contracts proxy ON proxy.id = ue.contract_id
        JOIN contracts impl  ON lower(impl.address) = lower(proxy.implementation)
        WHERE impl.protocol_id IS NOT NULL
          AND impl.discovery_sources && ARRAY[
            'deployer_expansion','defillama','ai_inventory',
            'exa_deep_research','inventory','spa_override','dependency_two_pass'
          ]::varchar[]
          AND ue.new_impl IS NOT NULL
          AND lower(ue.new_impl) <> '0x0000000000000000000000000000000000000000'
          AND (proxy.protocol_id IS NULL OR proxy.protocol_id = impl.protocol_id)
        GROUP BY lower(ue.new_impl), impl.protocol_id
    ),
    -- Unify the two evidence streams. Each row is one
    -- (orphan, protocol_id, evidence_strength) tuple — duplicated
    -- across branches if an orphan matches both ways for the same
    -- protocol (additive — strengthens the dominant pick).
    orphan_to_protocols AS (
        SELECT
            orphan.id         AS orphan_id,
            hsd.protocol_id   AS protocol_id,
            hsd.n             AS strength
        FROM contracts orphan
        JOIN high_sourced_deployer hsd
          ON lower(orphan.deployer) = hsd.deployer_lc
        WHERE orphan.protocol_id IS NULL
          AND orphan.deployer IS NOT NULL
        UNION ALL
        SELECT
            orphan.id         AS orphan_id,
            hsi.protocol_id   AS protocol_id,
            hsi.n             AS strength
        FROM contracts orphan
        JOIN high_sourced_historical_impl hsi
          ON orphan.address = hsi.impl_addr_lc
        WHERE orphan.protocol_id IS NULL
    )
    SELECT
        orphan_id,
        ARRAY_AGG(DISTINCT protocol_id) AS protocols,
        (
            ARRAY_AGG(protocol_id ORDER BY strength DESC)
        )[1] AS dominant_protocol
    FROM orphan_to_protocols
    GROUP BY orphan_id
    """
)


_ADOPT_ORPHAN = sa.text(
    """
    UPDATE contracts
    SET protocol_id = :pid,
        discovery_sources = CASE
            WHEN discovery_sources IS NULL THEN ARRAY['structural_adoption']::varchar[]
            WHEN 'structural_adoption' = ANY(discovery_sources) THEN discovery_sources
            ELSE array_append(discovery_sources, 'structural_adoption')
        END
    WHERE id = :id
    """
)


# Lossy revert — matches the convention from ``3a8f4d1c9b07``. Any row
# tagged ``structural_adoption`` had its ``protocol_id`` granted via
# inferred ownership; stripping the tag and nulling the protocol_id
# returns the row to "discovered-but-not-attributed" state. This also
# reverts adoptions from the prior structural-edge migration and from
# the runtime cascade branches — accepted tradeoff for a one-way
# operational migration.
_REVERT_ADOPTIONS = sa.text(
    """
    UPDATE contracts
    SET protocol_id = NULL,
        discovery_sources = NULLIF(
            array_remove(discovery_sources, 'structural_adoption'),
            ARRAY[]::varchar[]
        )
    WHERE 'structural_adoption' = ANY(discovery_sources)
    """
)


def upgrade() -> None:
    bind = op.get_bind()
    rows = bind.execute(_SELECT_REMAINING_ORPHANS).fetchall()

    adopted = 0
    skipped_multi = 0
    for orphan_id, protocols, dominant_protocol in rows:
        unique = [pid for pid in (protocols or []) if pid is not None]
        if not unique:
            continue
        if len(unique) > 1:
            skipped_multi += 1
            logger.warning(
                "remaining-orphan adoption: contract_id=%s matches multiple "
                "protocols (%s) across deployer-cascade and historical-impl "
                "branches; leaving orphan for manual review",
                orphan_id,
                unique,
            )
            continue
        bind.execute(_ADOPT_ORPHAN, {"pid": dominant_protocol, "id": orphan_id})
        adopted += 1

    if adopted or skipped_multi:
        logger.info(
            "remaining-orphan adoption: adopted %d orphan contract(s); skipped %d cross-protocol case(s)",
            adopted,
            skipped_multi,
        )


def downgrade() -> None:
    op.get_bind().execute(_REVERT_ADOPTIONS)
