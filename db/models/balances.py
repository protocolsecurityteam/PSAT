"""Balance/restaking planes, TVL, dapp interactions, and the event indexer tables."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Numeric,
    String,
    Text,
    func,
    or_,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from utils.balance_status import (
    ASSET_SET_SOURCE_CHAIN_LOG_SWEEP,
    ASSET_SET_SOURCE_ETHERSCAN_PAGES,
    NATIVE_STATUS_PROVEN_ZERO,
    SWEEP_STATUS_COMPLETED,
)
from utils.restaking_status import (
    CONSENSUS_LAYER_RESIDUAL_NOT_DETERMINED,
    CROSS_READ_AGREE,
    CROSS_READ_AGREEMENTS,
    EIGENPOD_BASES,
    EIGENPOD_BASIS_NO_EIGENPOD_PROVEN,
    EIGENPOD_BASIS_PROVEN_CROSS_READ,
    NODE_SET_COMPLETENESS_NOT_DETERMINED,
    NON_OBSERVING_SHARES_BASES,
    SHARES_BASES,
    SHARES_BASIS_EIGENLAYER_BEACON_SHARES,
    SHARES_BASIS_NO_EIGENPOD_PROVEN,
    SHARES_COLUMN_COMMENT,
)

from .base import Base, _sql_tuple
from .contracts import Contract


class ContractBalanceFetch(Base):
    """One balance-read attempt against one address. **NOT a holdings witness.**

    This is the fetch-provenance plane. A row here records that a read was
    ATTEMPTED and how it went; it never asserts that anything is held. That
    separation is the whole point: the three-state discriminator cannot live on
    ``contract_balances`` because ``services.effects.selection`` consumes a
    ``contract_balances`` row's mere EXISTENCE as "this deployment holds this
    asset", so a ``fetch_failed`` or ``proven_zero`` row written there would
    publish holdings that do not exist.

    ``native_status`` must be read as the PAIR ``(native_status, block_number)``
    and never alone — ``proven_nonzero`` with a NULL block is "nonzero at an
    unrecorded height", not an as-of-block fact. Route consumers through
    :func:`services.monitoring.balance_reads.native_balance_fact`.
    """

    __tablename__ = "contract_balance_fetches"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    # NULL = this read is about an ENTITY with no ``contracts`` row, and
    # ``(entity_chain, entity_address)`` below is its identity. Exactly one of
    # the two arms is populated (``ck_cbf_exactly_one_subject_key``), so every
    # predicate written against ``contract_id`` still selects exactly the
    # contract-keyed rows it selected when the column was NOT NULL.
    contract_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=True
    )
    # The other identity arm: a discovery-only principal (a Safe owner, a
    # capability principal) is named by chain and address and by nothing else.
    # NULL on every contract-keyed row.
    entity_chain: Mapped[str | None] = mapped_column(String(100), nullable=True)
    entity_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    chain_id: Mapped[int] = mapped_column(Integer, nullable=False)
    # The address the read was actually ISSUED against, captured verbatim from
    # the write-point local. Not necessarily ``contracts.address``: the
    # resolution worker reads ``request['proxy_address'] or address``.
    observed_address: Mapped[str] = mapped_column(String(42), nullable=False)
    # The height the NATIVE quantity was read at. NULL = not_determined. Never
    # projected onto ERC-20 rows (Q1 keeps those unpinned).
    block_number: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    native_status: Mapped[str] = mapped_column(String(32), nullable=False)
    asset_set_status: Mapped[str] = mapped_column(String(32), nullable=False)
    # The RAW endpoint entry count, BEFORE the ``raw_balance > 0`` filter drops
    # entries. NULL = not_determined. This is the only thing that can witness
    # the at-cap case; a stored-row count cannot (the filter destroys it).
    asset_page_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # WHOSE answer the asset set is. ``asset_set_status`` says what the answer
    # was; only the pair is a claim. An empty set from
    # ``etherscan_pages`` is one index's negative and proves nothing about the
    # chain; an empty set from ``chain_log_sweep`` is an earned negative scoped
    # by ``asset_set_basis`` and ``swept_through_block``.
    asset_set_source: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default=ASSET_SET_SOURCE_ETHERSCAN_PAGES
    )
    # What the asset set is a set OF, in the terms it was obtained by — the
    # sentence a published claim derives its scope from, never re-invented
    # downstream.
    asset_set_basis: Mapped[str | None] = mapped_column(Text, nullable=True)
    # NULL = no sweep was attempted (a third state, not a failure).
    sweep_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # The ERC-721/1155 receipts the scan found, as
    # ``[{address, kind, quantity_readable}]``. Durable BECAUSE it is durable: a
    # typed receipt whose current holding has no readable ``balanceOf(address)``
    # answer is why an asset set's completeness is withheld, and the evidence for
    # that refusal has to outlive the window it was seen in. An incremental
    # window names only what arrived inside it, so a later cycle that could not
    # read this column would see no typed receipt, believe the set complete, and
    # publish the earned negative the earlier scan refused. NULL = no sweep has
    # answered for this contract; ``[]`` = a scan answered and found none.
    # ``none_as_null`` is load-bearing, not style: without it SQLAlchemy stores a
    # Python ``None`` as the JSON scalar ``null``, which is a THIRD shape beside
    # SQL NULL and ``[]`` — and every reader here keys on "NULL means no scan has
    # answered". The CHECK below refuses that shape outright, so the distinction
    # the code leans on is enforced rather than hoped for.
    typed_assets: Mapped[list | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    # The FIRST block of the union of every scan that produced the current asset
    # set — not this cycle's window start. The basis string publishes the extent
    # of the claim, and an incremental cycle whose window is 63 blocks wide still
    # rests on the full-history scan that preceded it.
    swept_from_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # The block the log scan ran through. Present ONLY on a completed sweep
    # (CHECK below), because it is the extent of the claim and a failed scan has
    # no extent. It is also the cursor: the next cycle scans from here, which is
    # what keeps a full-history sweep a once-per-contract cost.
    swept_through_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    writer: Mapped[str] = mapped_column(String(32), nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_cbf_contract_fetched", "contract_id", "fetched_at", "id"),
        # The entity arm's twin of the index above. The view picks a subject's
        # current fetch with ORDER BY fetched_at DESC, id DESC LIMIT 1 under an
        # equality on the subject, and an arm without that index turns the
        # per-row correlated subquery into a sequential scan of this table.
        Index("ix_cbf_entity_fetched", "entity_chain", "entity_address", "fetched_at", "id"),
        # One subject per row. A row carrying both keys would be two subjects at
        # once — the view would match it on either arm and a consumer could not
        # say whose holdings it is — and a row carrying neither would be a
        # reading of nobody.
        CheckConstraint(
            "(contract_id IS NOT NULL AND entity_chain IS NULL AND entity_address IS NULL) "
            "OR (contract_id IS NULL AND entity_chain IS NOT NULL AND entity_address IS NOT NULL)",
            name="ck_cbf_exactly_one_subject_key",
        ),
        CheckConstraint(
            f"native_status <> '{NATIVE_STATUS_PROVEN_ZERO}' OR block_number IS NOT NULL",
            name="ck_cbf_proven_zero_requires_block",
        ),
        # A sweep-sourced asset set without a through-block would be an unbounded
        # claim: "the chain says this is everything" with no statement of how far
        # the chain was read.
        CheckConstraint(
            f"asset_set_source <> '{ASSET_SET_SOURCE_CHAIN_LOG_SWEEP}' OR swept_through_block IS NOT NULL",
            name="ck_cbf_sweep_source_requires_block",
        ),
        # A cursor written by a scan that could not be shown whole would let the
        # next cycle skip the blocks the failed one never proved it read.
        CheckConstraint(
            f"swept_through_block IS NULL OR sweep_status = '{SWEEP_STATUS_COMPLETED}'",
            name="ck_cbf_swept_block_requires_completed_sweep",
        ),
        # NULL means "no scan has answered"; ``[]`` means "a scan answered and
        # found none". A scalar or an object would be neither, and every reader
        # of this column depends on that distinction being real.
        CheckConstraint(
            "typed_assets IS NULL OR jsonb_typeof(typed_assets) = 'array'",
            name="ck_cbf_typed_assets_is_array",
        ),
    )


class ContractBalance(Base):
    __tablename__ = "contract_balances"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # See ``ContractBalanceFetch``: NULL means the holding belongs to an entity
    # with no ``contracts`` row, identified by ``(entity_chain, entity_address)``.
    contract_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=True
    )
    entity_chain: Mapped[str | None] = mapped_column(String(100), nullable=True)
    entity_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    token_address: Mapped[str | None] = mapped_column(String(42), nullable=True)  # NULL = native ETH
    token_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    token_symbol: Mapped[str | None] = mapped_column(String(50), nullable=True)
    decimals: Mapped[int] = mapped_column(Integer, nullable=False, default=18)
    raw_balance: Mapped[str] = mapped_column(String, nullable=False)  # stored as string to avoid overflow
    # 18 fractional digits because that is the resolution the QUANTITY is quoted
    # at: a cent-scaled column silently republished every sub-cent holding as
    # 0.00, which no reader can tell from a holding of nothing. The column stores
    # what the producer computed and rounds nothing.
    usd_value: Mapped[float | None] = mapped_column(Numeric(38, 18), nullable=True)
    # Same 18 digits, and for a sharper reason than symmetry with the column
    # above: 0 is the literal the writers use for "no price known", so a quote
    # finer than the column can hold would be stored as that same 0 and read as
    # a price that never answered. The column holds the quote it was given.
    price_usd: Mapped[float | None] = mapped_column(Numeric(38, 18), nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    # The address this quantity was read at, verbatim from the write-point
    # local. NULL = not_determined (every row written before this column
    # existed; the address was never recorded and cannot be recovered).
    observed_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    # The height THIS quantity was read at. Populated only on the pinned
    # Multicall3 native path; NULL = not_determined, permanently, for every
    # Etherscan-sourced row. An ERC-20 row can never carry one (CHECK below):
    # its quantity comes from an unpinned ``tag=latest`` answer, and letting it
    # inherit the fetch's native height would mint a height it never had.
    block_number: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # Structurally always NULL, and that is the field's job. No price source in
    # this system carries a height (Etherscan's stats endpoint and
    # ``TokenPriceUSD`` are both heightless), and the same asset diverges up to
    # 20.97% within one recorded instant. A consumer MUST NOT substitute
    # ``block_number``: ``usd_value``/``price_usd`` are never as-of-block facts.
    # DB-enforced by ``ck_contract_balances_price_block_null``.
    price_block_number: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # The fetch that observed this row. NULL = legacy row, provenance
    # not_determined. The ``contract_balances_latest`` view keys off it, which
    # also makes it the row set's completeness handle: a row's OWN fetch carries
    # the asset-set status/source/basis that the row set was assembled under, so
    # a consumer asks the winning fetch rather than the latest one (see
    # ``balance_reads.winning_asset_fetches``).
    fetch_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("contract_balance_fetches.id", ondelete="CASCADE"), nullable=True
    )
    # Which mechanism read this quantity. NULL = legacy row, not_determined.
    # Stated per row because one fetch's row set can mix them: a page-derived
    # PRICED row and a sweep-derived unpriced one are both current holdings and
    # neither is the other's basis.
    source: Mapped[str | None] = mapped_column(String(32), nullable=True)

    contract: Mapped[Contract] = relationship("Contract", back_populates="balances")

    __table_args__ = (
        Index("ix_contract_balances_contract_id", "contract_id"),
        Index("ix_contract_balances_fetch_id", "fetch_id"),
        Index("ix_contract_balances_entity", "entity_chain", "entity_address"),
        CheckConstraint(
            "(contract_id IS NOT NULL AND entity_chain IS NULL AND entity_address IS NULL) "
            "OR (contract_id IS NULL AND entity_chain IS NOT NULL AND entity_address IS NOT NULL)",
            name="ck_contract_balances_exactly_one_subject_key",
        ),
        CheckConstraint(
            "token_address IS NULL OR block_number IS NULL",
            name="ck_contract_balances_token_block_null",
        ),
        CheckConstraint(
            "price_block_number IS NULL",
            name="ck_contract_balances_price_block_null",
        ),
    )


class ContractBalanceLatest(Base):
    """READ-ONLY mapping of the ``contract_balances_latest`` VIEW.

    The view is what every consumer must read now that the writers are
    insert-only. It is a pure projection of ``contract_balances`` — same columns,
    a subset of the rows, never a join that can multiply or manufacture one — and
    it answers one question per (contract, row class): which fetch's row set is
    current?

    The question is asked per SUBJECT, and a subject is a ``contracts`` row or
    an entity that has none — ``(entity_chain, entity_address)``. The two arms
    are mutually exclusive at the schema (``ck_*_exactly_one_subject_key``), so
    the coalesced rule the view carries is the contract rule, term for term, for
    every row that has a contract. Matching on ``contract_id`` alone would have
    been NULL for every entity-keyed row: written, stored, and silently absent
    from the view every consumer reads.

    * Per ROW CLASS (native vs ERC-20), independently: the latest fetch that did
      NOT fail for that class wins WHOLESALE. A fetch's rows ARE the set it
      observed, so an asset the holder has since sold correctly disappears, and
      a transient token-fetch failure does not withdraw the native holding (or
      vice versa).
    * A failed fetch never wins. Letting one win would republish "holds nothing"
      out of a failure — the exact fail-open this unit exists to close.
    * Legacy rows (``fetch_id IS NULL``) remain visible until a NON-FAILED fetch
      exists for that contract and class. A first fetch that fails must not
      delete history from the view.

    Not autogenerate-visible: :func:`include_object` (in this module, wired into
    ``alembic/env.py``) filters it out on the ``info={"is_view": True}`` marker
    below — not by name — because Alembic cannot tell a mapped view from a mapped
    table and would otherwise emit a ``CREATE TABLE`` shadowing it.
    ``tests/test_alembic_chain.py`` asserts the filtered diff is empty.
    """

    __tablename__ = "contract_balances_latest"
    __table_args__ = {"info": {"is_view": True}}

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    contract_id: Mapped[int | None] = mapped_column(Integer)
    entity_chain: Mapped[str | None] = mapped_column(String(100))
    entity_address: Mapped[str | None] = mapped_column(String(42))
    token_address: Mapped[str | None] = mapped_column(String(42))
    token_name: Mapped[str | None] = mapped_column(String(255))
    token_symbol: Mapped[str | None] = mapped_column(String(50))
    decimals: Mapped[int] = mapped_column(Integer)
    raw_balance: Mapped[str] = mapped_column(String)
    usd_value: Mapped[float | None] = mapped_column(Numeric(38, 18))
    price_usd: Mapped[float | None] = mapped_column(Numeric(38, 18))
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    observed_address: Mapped[str | None] = mapped_column(String(42))
    block_number: Mapped[int | None] = mapped_column(BigInteger)
    price_block_number: Mapped[int | None] = mapped_column(BigInteger)
    fetch_id: Mapped[int | None] = mapped_column(BigInteger)
    source: Mapped[str | None] = mapped_column(String(32))


class RestakingPosition(Base):
    """One node's EigenLayer beaconChainETH position at ONE pinned height.

    A separate plane from ``contract_balances`` on purpose, and the separation is
    structural rather than a filter. Every spot-balance reader joins
    ``contract_balances(_latest).contract_id`` to ``contracts.id``; the live
    EtherFiNode instances are BeaconProxy deployments with NO ``contracts`` row
    (measured: zero), and ``contract_balances.contract_id`` is ``NOT NULL``. So a
    restaking row cannot be written into that table at all without first minting
    a ``contracts`` row per node — which would make
    ``services.effects.selection`` read the share quantity as a HOLDING of a
    deployment and sum it into the authority graph. That is the shape the
    balance-provenance unit exists to close, in a new place.

    There is deliberately **no USD column anywhere on this plane**, so a share
    quantity cannot be added to a dollar figure even by accident.

    ``eigenlayer_beacon_shares_wei`` is named for its scope because a bare
    "position" would be read as the node's money. Measured at block 25643300
    over the 26 enumerated nodes: every one reads 0 shares, while their pods hold
    374.148164612 ETH between them — one of them exactly 320 ETH. Summing this
    column over the enumerated set yields 0 wei against that. The node's and the
    pod's execution-layer native balances are ``not_determined`` here, and the
    consensus-layer residual is ``not_determined`` and unbounded above.
    """

    __tablename__ = "restaking_positions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    chain_id: Mapped[int] = mapped_column(Integer, nullable=False)
    node_address: Mapped[str] = mapped_column(String(42), nullable=False)
    # PROVENANCE ONLY: the ``contracts`` row whose ADDRESS EQUALS the address the
    # enumerating log was emitted at — the proxy, not the implementation row that
    # shares the manager's name. Never "this contract holds the position".
    manager_contract_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("contracts.id", ondelete="SET NULL"), nullable=True
    )
    protocol_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("protocols.id", ondelete="SET NULL"), nullable=True
    )
    # Every read of a row is ISSUED at this height. There is no unpinned path on
    # this plane: without a height nothing is written at all.
    block_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    # The reorg witness (inv.11/12). Without it a replay "at block N" cannot tell
    # it is on the same chain history; the event indexer stamps
    # ``last_indexed_block_hash`` for the same reason.
    block_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    eigenpod: Mapped[str | None] = mapped_column(String(42), nullable=True)
    eigenpod_basis: Mapped[str] = mapped_column(String(32), nullable=False)
    eigenlayer_beacon_shares_wei: Mapped[Any | None] = mapped_column(
        Numeric(80, 0), nullable=True, comment=SHARES_COLUMN_COMMENT
    )
    shares_basis: Mapped[str] = mapped_column(String(40), nullable=False)
    # Read from ``EigenPodManager.beaconChainETHStrategy()`` at the SAME block.
    # A literal would be indefensible: the near-miss
    # ``0xbeac0eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee`` answers 0 with success, as
    # does a nonexistent staker, byte-identical to the real 26/26 answer.
    shares_strategy: Mapped[str | None] = mapped_column(String(42), nullable=True)
    # ``int256`` on EigenPodManager and genuinely able to go negative. Stored
    # signed and unclamped.
    deposit_shares_wei: Mapped[Any | None] = mapped_column(Numeric(80, 0), nullable=True)
    cross_read_agreement: Mapped[str] = mapped_column(String(30), nullable=False)
    active_validator_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_checkpoint_timestamp: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    consensus_layer_residual: Mapped[str] = mapped_column(String(20), nullable=False)
    node_set_completeness: Mapped[str] = mapped_column(String(20), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # The basis columns are NOT NULL for a load-bearing reason, not tidiness: the
    # OR-joined arms below are only fail-closed while they are. A NULL basis
    # makes every arm NULL, an OR of NULLs is NULL, and a CHECK that evaluates to
    # NULL PASSES in Postgres — so a nullable basis would readmit every shape
    # these constraints exist to reject.
    __table_args__ = (
        Index("ix_rp_node_block", "chain_id", "node_address", "block_number", "id"),
        CheckConstraint(
            "shares_basis IN " + _sql_tuple(SHARES_BASES),
            name="ck_rp_basis_domain",
        ),
        CheckConstraint(
            "eigenpod_basis IN " + _sql_tuple(EIGENPOD_BASES),
            name="ck_rp_pod_basis_domain",
        ),
        CheckConstraint(
            "cross_read_agreement IN " + _sql_tuple(CROSS_READ_AGREEMENTS),
            name="ck_rp_agreement_domain",
        ),
        # ONE ARM PER BASIS, OR-joined, each arm pinning the basis AND the value
        # together. An arm naming only the basis, or only the value, is vacuous.
        # An unrecognised basis satisfies no arm, so the expression is FALSE.
        CheckConstraint(
            "("
            f"  shares_basis = '{SHARES_BASIS_EIGENLAYER_BEACON_SHARES}'"
            "   AND eigenlayer_beacon_shares_wei IS NOT NULL"
            f"  AND eigenpod_basis = '{EIGENPOD_BASIS_PROVEN_CROSS_READ}'"
            "   AND shares_strategy IS NOT NULL"
            f"  AND (eigenlayer_beacon_shares_wei <> 0 OR cross_read_agreement = '{CROSS_READ_AGREE}')"
            ") OR ("
            f"  shares_basis = '{SHARES_BASIS_NO_EIGENPOD_PROVEN}'"
            "   AND eigenlayer_beacon_shares_wei IS NOT DISTINCT FROM 0"
            f"  AND eigenpod_basis = '{EIGENPOD_BASIS_NO_EIGENPOD_PROVEN}'"
            "   AND shares_strategy IS NULL"
            ") OR ("
            "   shares_basis IN " + _sql_tuple(NON_OBSERVING_SHARES_BASES) + ""
            "   AND eigenlayer_beacon_shares_wei IS NULL"
            "   AND shares_strategy IS NULL"
            ")",
            name="ck_rp_basis_matches_value",
        ),
        # A share quantity is unsigned by construction (the withdrawable leg is
        # a ``uint256``); only the DEPOSIT leg is signed. Without this the DB
        # would accept a negative the producer cannot emit.
        CheckConstraint(
            "eigenlayer_beacon_shares_wei IS NULL OR eigenlayer_beacon_shares_wei >= 0",
            name="ck_rp_shares_non_negative",
        ),
        CheckConstraint(
            f"eigenpod_basis <> '{EIGENPOD_BASIS_NO_EIGENPOD_PROVEN}' OR eigenpod IS NULL",
            name="ck_rp_no_pod_has_no_address",
        ),
        CheckConstraint(
            f"eigenpod_basis <> '{EIGENPOD_BASIS_PROVEN_CROSS_READ}' OR eigenpod IS NOT NULL",
            name="ck_rp_pod_cross_read_has_address",
        ),
        # Pod-derived facts require the proven pod. Without this a
        # ``last_checkpoint_timestamp`` of 0 — a real "never checkpointed"
        # witness — could be minted against an address never proven to have one.
        CheckConstraint(
            f"eigenpod_basis = '{EIGENPOD_BASIS_PROVEN_CROSS_READ}'"
            " OR (active_validator_count IS NULL AND last_checkpoint_timestamp IS NULL)",
            name="ck_rp_pod_facts_require_pod",
        ),
        CheckConstraint(
            f"consensus_layer_residual = '{CONSENSUS_LAYER_RESIDUAL_NOT_DETERMINED}'",
            name="ck_rp_cl_residual_not_determined",
        ),
        CheckConstraint(
            f"node_set_completeness = '{NODE_SET_COMPLETENESS_NOT_DETERMINED}'",
            name="ck_rp_node_set_completeness",
        ),
    )


class RestakingPositionLatest(Base):
    """READ-ONLY mapping of the ``restaking_positions_latest`` VIEW.

    Per ``(chain_id, node_address)`` — the chain is part of the key because the
    same address on two chains is two different entities — the most recent
    OBSERVING row wins, ordered ``block_number DESC, id DESC`` so the order is
    total and two rows at one height resolve deterministically.

    Both non-observing bases are excluded from winning. ``read_failed`` is a
    transport or decode failure; ``not_determined`` is a transport success whose
    evidence does not license a value. Letting either win would withdraw a proven
    position on the strength of a non-observation.

    **Absence from this view is ``not_determined``, never "no position".** A node
    whose every row is non-observing does not appear at all, so a consumer that
    read a missing row as zero would reintroduce, at the projection layer, the
    absent-row-as-``$0`` shape the balance-provenance unit exists to close.

    Not autogenerate-visible: :func:`include_object` filters it on the
    ``info={"is_view": True}`` marker, as it does the balance view.
    """

    __tablename__ = "restaking_positions_latest"
    __table_args__ = {"info": {"is_view": True}}

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    chain_id: Mapped[int] = mapped_column(Integer)
    node_address: Mapped[str] = mapped_column(String(42))
    manager_contract_id: Mapped[int | None] = mapped_column(Integer)
    protocol_id: Mapped[int | None] = mapped_column(Integer)
    block_number: Mapped[int] = mapped_column(BigInteger)
    block_hash: Mapped[bytes] = mapped_column(LargeBinary(32))
    eigenpod: Mapped[str | None] = mapped_column(String(42))
    eigenpod_basis: Mapped[str] = mapped_column(String(32))
    eigenlayer_beacon_shares_wei: Mapped[Any | None] = mapped_column(Numeric(80, 0))
    shares_basis: Mapped[str] = mapped_column(String(40))
    shares_strategy: Mapped[str | None] = mapped_column(String(42))
    deposit_shares_wei: Mapped[Any | None] = mapped_column(Numeric(80, 0))
    cross_read_agreement: Mapped[str] = mapped_column(String(30))
    active_validator_count: Mapped[int | None] = mapped_column(Integer)
    last_checkpoint_timestamp: Mapped[int | None] = mapped_column(BigInteger)
    consensus_layer_residual: Mapped[str] = mapped_column(String(20))
    node_set_completeness: Mapped[str] = mapped_column(String(20))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class DAppInteraction(Base):
    __tablename__ = "dapp_interactions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False
    )
    protocol_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("protocols.id", ondelete="SET NULL"), nullable=True
    )
    type: Mapped[str] = mapped_column(String(50), nullable=False)
    page_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    to_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    value: Mapped[str | None] = mapped_column(String(80), nullable=True)
    data: Mapped[str | None] = mapped_column(Text, nullable=True)
    method_selector: Mapped[str | None] = mapped_column(String(10), nullable=True)
    typed_data: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    is_permit: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    captured_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_dapp_interactions_job_id", "job_id"),
        Index("ix_dapp_interactions_to_address", "to_address"),
        Index("ix_dapp_interactions_protocol_id", "protocol_id"),
    )


class TvlSnapshot(Base):
    __tablename__ = "tvl_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    total_usd: Mapped[float | None] = mapped_column(Numeric(20, 2), nullable=True)
    defillama_tvl: Mapped[float | None] = mapped_column(Numeric(20, 2), nullable=True)
    chain_breakdown: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=True
    )
    contract_breakdown: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=True
    )
    source: Mapped[str] = mapped_column(String(20), nullable=False, default="on_chain")

    __table_args__ = (Index("ix_tvl_snapshots_protocol_timestamp", "protocol_id", "timestamp"),)


class IndexedEventLog(Base):
    """Generic append-only log store for resolver enumeration hints.

    Rows are keyed only by chain, emitting address, event topic, and
    log identity. Descriptor-specific meaning (which topic maps to
    which semantic key) stays in ``enumeration_hint``.
    """

    __tablename__ = "indexed_event_logs"

    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_address: Mapped[str] = mapped_column(String(42), primary_key=True)
    topic0: Mapped[str] = mapped_column(String(66), primary_key=True)
    tx_hash: Mapped[bytes] = mapped_column(LargeBinary(32), primary_key=True)
    log_index: Mapped[int] = mapped_column(Integer, primary_key=True)
    block_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    block_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    transaction_index: Mapped[int] = mapped_column(Integer, nullable=False)
    topics: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    data_words: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        Index(
            "ix_indexed_event_logs_lookup",
            "chain_id",
            "event_address",
            "topic0",
            "block_number",
            "transaction_index",
            "log_index",
        ),
        Index(
            "ix_indexed_event_logs_block",
            "chain_id",
            "event_address",
            "block_number",
            "log_index",
        ),
    )


# ``indexed_event_cursors`` provenance vocabulary. It lives here, with the
# columns, because the writer (the indexer worker) and the reader (the resolution
# repo) must agree on the exact tokens and neither may import the other.
#
# ``first_indexed_block_basis`` — only CREATION licenses citing the lower bound.
FIRST_INDEXED_BASIS_CREATION = "creation_block_minus_one"
FIRST_INDEXED_BASIS_EXPLICIT = "explicit_seed"
CURSOR_BASIS_NOT_DETERMINED = "not_determined"
# ``enrollment_basis`` — whether the row carries a variable attribution.
ENROLLMENT_BASIS_PREDICATE_HINT = "predicate_tree_hint"
ENROLLMENT_BASIS_TRACKED_TOPICS = "tracked_topics_asserted"
# ALLOW-LIST, deliberately, and it is the whole point of the column. Exactness —
# a zero-row fold published as "this event never fired" — is permitted only for a
# basis that is known to carry a variable attribution. A deny-list on the one
# token we happened to invent would fail OPEN on every other value, and there is
# already such a value in the schema: ``enroll_event_cursor`` stores the literal
# ``not_determined`` whenever a caller omits the argument, which is precisely the
# case that must not license anything. NULL is included because it means "row
# predates this column", and those 80 rows were folding before the column existed;
# demoting them is a separate change with its own blast radius.
EXACTNESS_ELIGIBLE_ENROLLMENT_BASES = frozenset({None, ENROLLMENT_BASIS_PREDICATE_HINT})


def enrollment_basis_permits_exactness(basis: str | None) -> bool:
    """Whether a cursor with this ``enrollment_basis`` may support an exact empty.

    Anything unrecognised — a future token, a hand-written value, the
    ``not_determined`` default — answers False. New enrolment sources are
    therefore inert until someone deliberately adds them here.
    """
    return basis in EXACTNESS_ELIGIBLE_ENROLLMENT_BASES


# ``window_stats_basis`` — neither token ever means "measured and incomplete";
# that is expressed by a count at or above the cap that gated it.
WINDOW_STATS_CONTINUOUS = "continuous_from_first_indexed_block"
WINDOW_STATS_UNMEASURED_LEGACY = "unmeasured_legacy"
WINDOW_STATS_NOT_DETERMINED = CURSOR_BASIS_NOT_DETERMINED


class IndexedEventCursor(Base):
    """One scan cursor per ``(chain_id, event_address, topic0)``."""

    __tablename__ = "indexed_event_cursors"

    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_address: Mapped[str] = mapped_column(String(42), primary_key=True)
    topic0: Mapped[str] = mapped_column(String(66), primary_key=True)
    last_indexed_block: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")
    last_indexed_block_hash: Mapped[bytes | None] = mapped_column(LargeBinary(32), nullable=True)
    last_run_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    # True once the historical backfill has reached the confirmed head at least
    # once. Cursors are seeded at the event address's *creation block* (not 0),
    # so ``last_indexed_block > 0`` no longer implies "indexed" — a freshly
    # enrolled cursor sits at a positive block having scanned nothing. Resolvers
    # consult this flag (not the block number) before trusting the durable index;
    # until it flips True they fall back to an inline fetch.
    backfill_complete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    # Lower bound of the range this cursor's logs cover, and what proves it.
    # ``backfill_complete`` is an UPPER-bound flag only; nothing here bounds the
    # range from below, so absence of a log below ``first_indexed_block`` is
    # proven only when the basis is ``creation_block_minus_one`` — which requires
    # all three pinned reads of ``_witness_seed_block`` to agree. NULL/NULL means
    # the row predates these columns (lower bound unknown); a populated block with
    # basis ``explicit_seed`` is a seed a caller supplied, NOT a witness; basis
    # ``not_determined`` means the witness was attempted and failed, and the block
    # is NULL because a number no consumer may cite is a number no consumer should
    # see.
    first_indexed_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    first_indexed_block_basis: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # How this cursor came to exist, and — through the ALLOW-LIST
    # ``enrollment_basis_permits_exactness`` — whether it may ever support an
    # exact empty. ``predicate_tree_hint`` = a static ``enumeration_hint`` named
    # this (chain, address, topic0) as a writer of a specific storage variable;
    # eligible. NULL = predates the column; eligible, because those rows folded
    # before it existed. Everything else is INELIGIBLE, including
    # ``tracked_topics_asserted`` (minted from a tracking plan, which names topics
    # an emitter CAN emit and attributes them to no variable), the literal
    # ``not_determined`` that ``enroll_event_cursor`` stores when a caller omits
    # the argument, and any token added later. Read at the ``_cursor_state`` choke
    # point in ``services/resolution/repos/event_logs_pg.py`` and by the two
    # out-of-band cursor readers (``_authority_has_role_store_cursor``,
    # ``_authority_backfilled``).
    enrollment_basis: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Largest ``eth_getLogs`` page this cursor has ever accepted, the result cap
    # in force when those pages were fetched, and whether the record is continuous
    # from ``first_indexed_block``. A page returned at the cap may have been
    # truncated by the upstream, so "no such log exists" is proven only when every
    # window came back strictly under a cap that was actually enforced. All three
    # are NULL on rows whose windows predate the columns.
    max_window_log_count: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    window_stats_cap: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    window_stats_basis: Mapped[str | None] = mapped_column(String(48), nullable=True)


def exactness_eligible_cursor_clause():
    """SQL form of :func:`enrollment_basis_permits_exactness`, for the readers
    that ask "does a usable cursor exist" without loading the row.

    Derived from the same frozenset the Python predicate reads, so the two
    cannot drift into disagreeing about which rows may support an exact empty.
    """
    non_null = sorted(b for b in EXACTNESS_ELIGIBLE_ENROLLMENT_BASES if b is not None)
    clauses = []
    if None in EXACTNESS_ELIGIBLE_ENROLLMENT_BASES:
        clauses.append(IndexedEventCursor.enrollment_basis.is_(None))
    if non_null:
        clauses.append(IndexedEventCursor.enrollment_basis.in_(non_null))
    return or_(*clauses)


# ``role_holder_planes`` vocabulary. Each token names the evidence that put the
# row in that state; there is no token meaning "we looked and there is nobody".
HOLDERS_BASIS_PINNED_HAS_ROLE = "pinned_has_role_confirmed"
HOLDER_SET_EXHAUSTIVE_NOT_DETERMINED = "not_determined"
ROLE_COVERAGE_LOWER_BOUND = "lower_bound"
ROLE_COVERAGE_PARTIAL = "partial"
ROLE_NAME_BASIS_KECCAK = "keccak_preimage"
ROLE_NAME_BASIS_AC_DEFAULT_ADMIN = "accesscontrol_default_admin_literal"
ROLE_NAME_BASIS_NOT_DETERMINED = "not_determined"

# ``role_holder_plane_refreshes`` outcomes. Both mean a pass RAN against a
# registry whose gate was open; they differ only in whether the fold proposed
# anything. A registry whose gate was closed gets no row at all — see the model.
ROLE_REFRESH_OUTCOME_NO_ROWS = "no_rows"
ROLE_REFRESH_OUTCOME_ROWS_WRITTEN = "rows_written"

# "No holder set was published", as SQL. A bare ``holders IS NULL`` is NOT this:
# a JSONB column also accepts the jsonb scalar ``null``, which is what a write of
# a Python None stores unless the column says otherwise, and which every SQL null
# test reads as a present payload. Both spellings must count as withheld or the
# constraints below stop discriminating exactly where it matters. Enforced from
# the other side too, by ``holders_is_array_or_absent``, so the two can't drift.
HOLDERS_WITHHELD_SQL = "(holders IS NULL OR jsonb_typeof(holders) = 'null')"
# The same two spellings for the disagreement log. It travels with ``holders``:
# on a withheld row nothing was read, or what was read is not published, so
# "no disagreement was observed" is not_determined rather than an empty list.
DISAGREEMENTS_WITHHELD_SQL = "(fold_chain_disagreements IS NULL OR jsonb_typeof(fold_chain_disagreements) = 'null')"
