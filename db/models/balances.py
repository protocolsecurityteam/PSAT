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
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Numeric,
    String,
    Text,
    and_,
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
    """One balance-read attempt against one address; not a holdings witness.

    The status lives here, not on ``contract_balances``, because ``services.effects.selection`` treats a
    ``contract_balances`` row's existence as a holding. Read ``native_status`` with ``block_number``; use
    :func:`services.monitoring.balance_reads.native_balance_fact`.
    """

    __tablename__ = "contract_balance_fetches"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    # NULL means the subject is an entity without a ``contracts`` row, identified by ``(entity_chain, entity_address)``.
    # Exactly one arm is set (``ck_cbf_exactly_one_subject_key``).
    contract_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=True
    )
    # The entity arm (e.g. a Safe owner); NULL on contract-keyed rows.
    entity_chain: Mapped[str | None] = mapped_column(String(100), nullable=True)
    entity_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    chain_id: Mapped[int] = mapped_column(Integer, nullable=False)
    # The address the read was actually issued against (may be the proxy, not ``contracts.address``).
    observed_address: Mapped[str] = mapped_column(String(42), nullable=False)
    # The native read's height; NULL = not determined. Never applied to ERC-20 rows.
    block_number: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    native_status: Mapped[str] = mapped_column(String(32), nullable=False)
    asset_set_status: Mapped[str] = mapped_column(String(32), nullable=False)
    # The raw endpoint entry count before zero balances are filtered, the only witness of the at-cap case. NULL = not
    # determined.
    asset_page_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Whose answer the asset set is; only with ``asset_set_status`` is it a claim. Empty from ``etherscan_pages`` proves
    # nothing; empty from ``chain_log_sweep`` is an earned negative within ``asset_set_basis`` and
    # ``swept_through_block``.
    asset_set_source: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default=ASSET_SET_SOURCE_ETHERSCAN_PAGES
    )
    # What the asset set is a set of, as obtained; published claims derive their scope from it.
    asset_set_basis: Mapped[str | None] = mapped_column(Text, nullable=True)
    # NULL = no sweep attempted.
    sweep_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # ERC-721/1155 receipts found, ``[{address, kind, quantity_readable}]``. Durable because a typed receipt with no
    # readable balance withholds completeness, and later incremental cycles must still see it. NULL = no sweep answered;
    # ``[]`` = none found. ``none_as_null`` plus the CHECK keep jsonb ``null`` out.
    typed_assets: Mapped[list | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    # Start of the union of scans behind the current asset set, not this cycle's window.
    swept_from_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # Where the sweep ran through: present only on a completed sweep (CHECK), and the next cycle's cursor.
    swept_through_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    writer: Mapped[str] = mapped_column(String(32), nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_cbf_contract_fetched", "contract_id", "fetched_at", "id"),
        # The entity arm's index; without it the view's per-row subquery is a sequential scan.
        Index("ix_cbf_entity_fetched", "entity_chain", "entity_address", "fetched_at", "id"),
        # Exactly one subject per row.
        CheckConstraint(
            "(contract_id IS NOT NULL AND entity_chain IS NULL AND entity_address IS NULL) "
            "OR (contract_id IS NULL AND entity_chain IS NOT NULL AND entity_address IS NOT NULL)",
            name="ck_cbf_exactly_one_subject_key",
        ),
        CheckConstraint(
            f"native_status <> '{NATIVE_STATUS_PROVEN_ZERO}' OR block_number IS NOT NULL",
            name="ck_cbf_proven_zero_requires_block",
        ),
        # A sweep-sourced asset set needs a through-block, or it's an unbounded claim.
        CheckConstraint(
            f"asset_set_source <> '{ASSET_SET_SOURCE_CHAIN_LOG_SWEEP}' OR swept_through_block IS NOT NULL",
            name="ck_cbf_sweep_source_requires_block",
        ),
        # A failed scan must not advance the cursor past blocks it never proved it read.
        CheckConstraint(
            f"swept_through_block IS NULL OR sweep_status = '{SWEEP_STATUS_COMPLETED}'",
            name="ck_cbf_swept_block_requires_completed_sweep",
        ),
        # NULL (no scan) vs ``[]`` (found none); other shapes are neither.
        CheckConstraint(
            "typed_assets IS NULL OR jsonb_typeof(typed_assets) = 'array'",
            name="ck_cbf_typed_assets_is_array",
        ),
    )


class ContractBalance(Base):
    __tablename__ = "contract_balances"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # See ``ContractBalanceFetch``.
    contract_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=True
    )
    entity_chain: Mapped[str | None] = mapped_column(String(100), nullable=True)
    entity_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    token_address: Mapped[str | None] = mapped_column(String(42), nullable=True)  # NULL = native ETH
    token_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    token_symbol: Mapped[str | None] = mapped_column(String(50), nullable=True)
    decimals: Mapped[int] = mapped_column(Integer, nullable=False, default=18)
    decimals_known: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    price_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    raw_balance: Mapped[str] = mapped_column(String, nullable=False)  # stored as string to avoid overflow
    # 18 digits to match quantity resolution; cents rounded sub-cent holdings to 0.00.
    usd_value: Mapped[float | None] = mapped_column(Numeric(38, 18), nullable=True)
    # 18 digits because 0 means "no price known"; a finer quote would otherwise round to that.
    price_usd: Mapped[float | None] = mapped_column(Numeric(38, 18), nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    # The read address, verbatim. NULL = not recorded (pre-column rows).
    observed_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    # Height of this quantity, only on the pinned Multicall3 native path; NULL otherwise. ERC-20 rows can't carry one
    # (CHECK), since their quantity is an unpinned ``latest`` read.
    block_number: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # Always NULL: no price source has a height (prices diverge ~21% within an instant). Never substitute
    # ``block_number``. Enforced by ``ck_contract_balances_price_block_null``.
    price_block_number: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # The fetch that observed this row (NULL = legacy). The latest view keys on it, and its fetch carries the asset-set
    # status/source/basis for the row set (``balance_reads.winning_asset_fetches``).
    fetch_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("contract_balance_fetches.id", ondelete="CASCADE"), nullable=True
    )
    # Which mechanism read this quantity (one fetch can mix them). NULL = legacy.
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
    """Read-only mapping of the ``contract_balances_latest`` view, which every consumer must read (writers are
    insert-only).

    A pure projection answering which fetch's row set is current, per subject (a contract or an entity arm) and per row
    class (native vs ERC-20):

    * the latest non-failed fetch for that class wins wholesale, so sold assets disappear and one class's failure
    doesn't withdraw the other;
    * a failed fetch never wins (it would publish "holds nothing");
    * legacy rows (``fetch_id IS NULL``) stay visible until a non-failed fetch exists.

    Hidden from autogenerate by :func:`include_object` via ``info={"is_view": True}``;
    ``tests/storage/test_alembic_chain.py``
    checks the diff is empty.
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
    decimals_known: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    price_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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
    """One node's EigenLayer beaconChainETH position at one pinned height.

    Separate from ``contract_balances`` structurally: EtherFiNode instances are BeaconProxies with no ``contracts`` row,
    and minting one per node would make ``services.effects.selection`` treat shares as holdings. There is no USD column,
    so shares can't be added to dollars.

    ``eigenlayer_beacon_shares_wei`` is named for its scope: measured, every node reads 0 shares while their pods hold
    ~374 ETH, so this isn't the node's money. Native and consensus-layer balances are ``not_determined`` here.
    """

    __tablename__ = "restaking_positions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    chain_id: Mapped[int] = mapped_column(Integer, nullable=False)
    node_address: Mapped[str] = mapped_column(String(42), nullable=False)
    # Provenance only: the ``contracts`` row at the enumerating log's emitter address (the proxy). Not a holder.
    manager_contract_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("contracts.id", ondelete="SET NULL"), nullable=True
    )
    protocol_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("protocols.id", ondelete="SET NULL"), nullable=True
    )
    # Every read is at this height; unpinned reads write nothing.
    block_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    # Reorg witness, like ``last_indexed_block_hash``.
    block_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    eigenpod: Mapped[str | None] = mapped_column(String(42), nullable=True)
    eigenpod_basis: Mapped[str] = mapped_column(String(32), nullable=False)
    eigenlayer_beacon_shares_wei: Mapped[Any | None] = mapped_column(
        Numeric(80, 0), nullable=True, comment=SHARES_COLUMN_COMMENT
    )
    shares_basis: Mapped[str] = mapped_column(String(40), nullable=False)
    # Read from ``beaconChainETHStrategy()`` at the same block; a hardcoded near-miss address also answers 0
    # successfully.
    shares_strategy: Mapped[str | None] = mapped_column(String(42), nullable=True)
    # ``int256`` and can be negative; stored signed and unclamped.
    deposit_shares_wei: Mapped[Any | None] = mapped_column(Numeric(80, 0), nullable=True)
    cross_read_agreement: Mapped[str] = mapped_column(String(30), nullable=False)
    active_validator_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_checkpoint_timestamp: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    consensus_layer_residual: Mapped[str] = mapped_column(String(20), nullable=False)
    node_set_completeness: Mapped[str] = mapped_column(String(20), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Basis columns are NOT NULL because a NULL would make every OR arm NULL, and a NULL CHECK passes in Postgres.
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
        # One arm per basis, each pinning basis and value together; unknown bases satisfy none.
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
        # Only the deposit leg is signed.
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
        # Pod-derived facts need the proven pod, or a 0 checkpoint could be minted for an address with none.
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
    """Read-only mapping of the ``restaking_positions_latest`` view.

    Per ``(chain_id, node_address)``, the newest observing row wins (``block_number DESC, id DESC``). ``read_failed``
    and ``not_determined`` rows never win. Absence from the view is ``not_determined``, never "no position". Hidden from
    autogenerate like the balance view.
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

    holdings_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    holdings_partial: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    valuation_partial: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    __table_args__ = (Index("ix_tvl_snapshots_protocol_timestamp", "protocol_id", "timestamp"),)


class IndexedEventLog(Base):
    """Generic append-only log store for resolver enumeration hints, keyed by chain, emitter, topic and log identity;
    meaning stays in ``enumeration_hint``.
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
    # Set only when ``data`` isn't word-aligned (``data_words`` is then empty); such a row's data isn't decodable.
    data_hex: Mapped[str | None] = mapped_column(Text, nullable=True)
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
        Index("ix_indexed_event_logs_role_lookup", "chain_id", func.lower(event_address), "topic0", "block_number"),
        Index(
            "ix_indexed_event_logs_block",
            "chain_id",
            "event_address",
            "block_number",
            "log_index",
        ),
    )


# ``indexed_event_cursors`` vocabulary, here because the indexer (writer) and the resolution repo (reader) can't import
# each other. Only CREATION licenses citing the lower bound.
FIRST_INDEXED_BASIS_CREATION = "creation_block_minus_one"
FIRST_INDEXED_BASIS_EXPLICIT = "explicit_seed"
CURSOR_BASIS_NOT_DETERMINED = "not_determined"
# Whether the row carries a variable attribution.
ENROLLMENT_BASIS_PREDICATE_HINT = "predicate_tree_hint"
ENROLLMENT_BASIS_TRACKED_TOPICS = "tracked_topics_asserted"
# A tracked cursor whose rows the operator's retire tool is deleting: never upgraded, never eligible, so a partly
# deleted row set can't back an exact answer.
ENROLLMENT_BASIS_RETIRING = "retiring"
# Allowlist: exactness (a zero-row fold published as "never fired") only for bases known to attribute a variable. A
# denylist would fail open, e.g. on the ``not_determined`` that ``enroll_event_cursor`` stores by default. NULL
# (pre-column rows) stays eligible.
EXACTNESS_ELIGIBLE_ENROLLMENT_BASES = frozenset({None, ENROLLMENT_BASIS_PREDICATE_HINT})


def enrollment_basis_permits_exactness(basis: str | None) -> bool:
    """Whether a cursor with this ``enrollment_basis`` may support an exact empty.

    Unrecognised values, including ``not_determined``, answer False.
    """
    return basis in EXACTNESS_ELIGIBLE_ENROLLMENT_BASES


# Neither token means "measured and incomplete"; that's a count at or above its cap.
WINDOW_STATS_CONTINUOUS = "continuous_from_first_indexed_block"
WINDOW_STATS_UNMEASURED_LEGACY = "unmeasured_legacy"
WINDOW_STATS_NOT_DETERMINED = CURSOR_BASIS_NOT_DETERMINED


class IndexedEventCursor(Base):
    __tablename__ = "indexed_event_cursors"

    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_address: Mapped[str] = mapped_column(String(42), primary_key=True)
    topic0: Mapped[str] = mapped_column(String(66), primary_key=True)
    last_indexed_block: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")
    last_indexed_block_hash: Mapped[bytes | None] = mapped_column(LargeBinary(32), nullable=True)
    last_run_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    # True once backfill reached the confirmed head. Cursors are seeded at the creation block, so a positive block
    # doesn't mean indexed; resolvers check this flag.
    backfill_complete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    # Lower bound of the covered range. ``backfill_complete`` only bounds from above; absence below is proven only with
    # basis ``creation_block_minus_one`` (three pinned reads agreeing). NULL/NULL = pre-column; ``explicit_seed`` =
    # caller-supplied, not a witness; ``not_determined`` = witness failed (block NULL).
    first_indexed_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    first_indexed_block_basis: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # How the cursor came to exist and, with ``first_indexed_block_basis`` via ``cursor_permits_exactness``, whether it
    # may support an exact result. ``predicate_tree_hint`` and NULL are eligible bases; everything else isn't, including
    # ``tracked_topics_asserted`` (topics with no variable attribution) and the default ``not_determined``. Read in
    # ``_cursor_state`` (services/resolution/repos/event_logs_pg.py), ``_authority_has_role_store_cursor`` and
    # ``_authority_backfilled``. Only ever upgraded, to ``predicate_tree_hint``, and only on a witnessed cursor.
    enrollment_basis: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Largest accepted page, the cap in force, and whether the record is continuous from ``first_indexed_block``. A page
    # at the cap may be truncated, so absence is proven only when every window came back under an enforced cap. NULL on
    # older rows.
    max_window_log_count: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    window_stats_cap: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    window_stats_basis: Mapped[str | None] = mapped_column(String(48), nullable=True)
    # Operational only, never evidence: when a page commit last moved this cursor, and the logs per block of that page
    # (sizes the next page).
    last_advanced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    recent_logs_per_block: Mapped[float | None] = mapped_column(Float, nullable=True)
    # The block the cursor was seeded at, whatever its witness said. A later witness proving this same seed is the only
    # evidence that may set ``first_indexed_block`` after enrolment. NULL on cursors enrolled before the column.
    enrolled_seed_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # Operational only, never evidence: the widest range the next page may request, lowered when the upstream refuses
    # one (a size limit or a query timeout) so later visits don't start at a span it already refused.
    request_span_limit: Mapped[int | None] = mapped_column(BigInteger, nullable=True)


def exactness_eligible_cursor_clause():
    """SQL form of :func:`cursor_permits_exactness`, derived from the same frozenset so they can't drift."""
    non_null = sorted(b for b in EXACTNESS_ELIGIBLE_ENROLLMENT_BASES if b is not None)
    clauses = []
    if None in EXACTNESS_ELIGIBLE_ENROLLMENT_BASES:
        clauses.append(IndexedEventCursor.enrollment_basis.is_(None))
    if non_null:
        clauses.append(IndexedEventCursor.enrollment_basis.in_(non_null))
    return and_(or_(*clauses), IndexedEventCursor.first_indexed_block_basis == FIRST_INDEXED_BASIS_CREATION)


def cursor_permits_exactness(enrollment_basis: str | None, first_indexed_block_basis: str | None) -> bool:
    """An exact result needs both an allow-listed ``enrollment_basis`` and a witnessed lower bound; NULL and
    ``explicit_seed`` first-block bases are not witnesses.
    """
    return (
        enrollment_basis_permits_exactness(enrollment_basis)
        and first_indexed_block_basis == FIRST_INDEXED_BASIS_CREATION
    )


# Per-address deploy-floor witness, kept independently of cursors. ``first_indexed_block`` is set only with
# ``creation_block_minus_one``; ``not_determined`` means a witness was attempted and did not prove the floor. No row
# means none was ever attempted.
FLOOR_WITNESS_BASES = (FIRST_INDEXED_BASIS_CREATION, CURSOR_BASIS_NOT_DETERMINED)
# Why a row holds the basis it does. ``prior_incarnation`` (logs at or below the seed) is evidence and final;
# ``failed`` and ``cursor_conflict`` are undecided and retried after ``next_attempt_at``.
FLOOR_WITNESS_PROVEN = "proven"
FLOOR_WITNESS_PRIOR_INCARNATION = "prior_incarnation"
FLOOR_WITNESS_FAILED = "failed"
FLOOR_WITNESS_CURSOR_CONFLICT = "cursor_conflict"
FLOOR_WITNESS_OUTCOMES = (
    FLOOR_WITNESS_PROVEN,
    FLOOR_WITNESS_PRIOR_INCARNATION,
    FLOOR_WITNESS_FAILED,
    FLOOR_WITNESS_CURSOR_CONFLICT,
)
FLOOR_WITNESS_RETRYABLE = (FLOOR_WITNESS_FAILED, FLOOR_WITNESS_CURSOR_CONFLICT)


class AddressFloorWitness(Base):
    __tablename__ = "address_floor_witnesses"

    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    address: Mapped[str] = mapped_column(String(42), primary_key=True)
    first_indexed_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    basis: Mapped[str] = mapped_column(String(32), nullable=False)
    witnessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    outcome: Mapped[str] = mapped_column(String(24), nullable=False)
    # The seed the outcome is about (creation block - 1); a prior-incarnation verdict refutes this number only.
    seed_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # Consecutive undecided attempts, driving the retry backoff.
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            f"basis IN ('{FIRST_INDEXED_BASIS_CREATION}', '{CURSOR_BASIS_NOT_DETERMINED}')",
            name="ck_address_floor_witnesses_basis",
        ),
        CheckConstraint(
            "outcome IN (" + ", ".join(f"'{o}'" for o in FLOOR_WITNESS_OUTCOMES) + ")",
            name="ck_address_floor_witnesses_outcome",
        ),
        CheckConstraint(
            f"(outcome = '{FLOOR_WITNESS_PROVEN}') = (basis = '{FIRST_INDEXED_BASIS_CREATION}')",
            name="ck_address_floor_witnesses_proven_iff_creation",
        ),
        CheckConstraint(
            "(outcome IN ("
            + ", ".join(f"'{o}'" for o in FLOOR_WITNESS_RETRYABLE)
            + ")) = (next_attempt_at IS NOT NULL)",
            name="ck_address_floor_witnesses_retry_iff_undecided",
        ),
        CheckConstraint(
            f"(basis = '{FIRST_INDEXED_BASIS_CREATION}') = (first_indexed_block IS NOT NULL)",
            name="ck_address_floor_witnesses_block_iff_proven",
        ),
        CheckConstraint("address = lower(address)", name="ck_address_floor_witnesses_address_lower"),
    )


# No token means "looked and found nobody".
HOLDERS_BASIS_PINNED_HAS_ROLE = "pinned_has_role_confirmed"
HOLDER_SET_EXHAUSTIVE_NOT_DETERMINED = "not_determined"
ROLE_COVERAGE_LOWER_BOUND = "lower_bound"
ROLE_COVERAGE_PARTIAL = "partial"
ROLE_NAME_BASIS_KECCAK = "keccak_preimage"
ROLE_NAME_BASIS_AC_DEFAULT_ADMIN = "accesscontrol_default_admin_literal"
ROLE_NAME_BASIS_NOT_DETERMINED = "not_determined"

# Both mean a pass ran with the gate open; a closed-gate registry gets no row.
ROLE_REFRESH_OUTCOME_NO_ROWS = "no_rows"
ROLE_REFRESH_OUTCOME_ROWS_WRITTEN = "rows_written"

# "No holder set published" must include jsonb ``null``, which a bare ``IS NULL`` misses. ``holders_is_array_or_absent``
# enforces the other side.
HOLDERS_WITHHELD_SQL = "(holders IS NULL OR jsonb_typeof(holders) = 'null')"
# Same for the disagreement log, which travels with ``holders``.
DISAGREEMENTS_WITHHELD_SQL = "(fold_chain_disagreements IS NULL OR jsonb_typeof(fold_chain_disagreements) = 'null')"
