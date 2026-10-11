"""Pipeline artifact tables: contracts, summaries, control graph, functions, labels."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Identity,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base
from .jobs import Job
from .protocol import Protocol

if TYPE_CHECKING:
    from .balances import ContractBalance


class Contract(Base):
    __tablename__ = "contracts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True
    )
    protocol_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("protocols.id", ondelete="SET NULL"), nullable=True
    )
    # The protocol that nominated this address. Not membership: ``protocol_id`` is the member stamp, written
    # only by ``services.discovery.membership_gate``.
    nominated_protocol_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("protocols.id", ondelete="SET NULL"), nullable=True
    )
    address: Mapped[str] = mapped_column(String(42), nullable=False)
    source_verified: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    chain: Mapped[str | None] = mapped_column(String(100), nullable=True)
    contract_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    compiler_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    language: Mapped[str | None] = mapped_column(String(20), nullable=True)
    evm_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    optimization: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    optimization_runs: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_format: Mapped[str | None] = mapped_column(String(50), nullable=True)
    source_file_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    license: Mapped[str | None] = mapped_column(String(100), nullable=True)
    is_proxy: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    proxy_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    implementation: Mapped[str | None] = mapped_column(String(42), nullable=True)
    beacon: Mapped[str | None] = mapped_column(String(42), nullable=True)
    admin: Mapped[str | None] = mapped_column(String(42), nullable=True)
    # The last upgrade-history fetch for this proxy: 'complete' | 'error' (a topic failed, so its ``upgrade_events``
    # are a partial set) | NULL (never fetched since the field was added).
    upgrade_history_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Extra logic contracts beyond the EIP-1967 implementation: split proxies whose fallback delegatecalls an address in
    # a state variable (e.g. LRTSquared's ``adminImpl``). Resolved against the proxy's storage and analysed as
    # proxy-child jobs. See services/discovery/secondary_impl.py.
    secondary_implementations: Mapped[list[str] | None] = mapped_column(ARRAY(String(42)), nullable=True)
    deployer: Mapped[str | None] = mapped_column(String(42), nullable=True)
    remappings: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
    rank_score: Mapped[float | None] = mapped_column(Numeric(10, 4), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Numeric(10, 4), nullable=True)
    # Every source that confirmed this contract; writers union their tag so ranking can boost multiply-corroborated
    # contracts.
    discovery_sources: Mapped[list[str] | None] = mapped_column(ARRAY(String(100)), nullable=True)
    discovery_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    chains: Mapped[list[str] | None] = mapped_column(ARRAY(String(100)), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    job: Mapped[Job] = relationship("Job")
    protocol: Mapped[Protocol | None] = relationship("Protocol", back_populates="contracts", foreign_keys=[protocol_id])
    summary: Mapped["ContractSummary | None"] = relationship(
        "ContractSummary", back_populates="contract", uselist=False, cascade="all, delete-orphan"
    )
    role_definitions: Mapped[list["RoleDefinition"]] = relationship(
        "RoleDefinition", back_populates="contract", cascade="all, delete-orphan"
    )
    controller_values: Mapped[list["ControllerValue"]] = relationship(
        "ControllerValue", back_populates="contract", cascade="all, delete-orphan"
    )
    control_graph_nodes: Mapped[list["ControlGraphNode"]] = relationship(
        "ControlGraphNode", back_populates="contract", cascade="all, delete-orphan"
    )
    control_graph_edges: Mapped[list["ControlGraphEdge"]] = relationship(
        "ControlGraphEdge", back_populates="contract", cascade="all, delete-orphan"
    )
    upgrade_events: Mapped[list["UpgradeEvent"]] = relationship(
        "UpgradeEvent", back_populates="contract", cascade="all, delete-orphan"
    )
    effective_functions: Mapped[list["EffectiveFunction"]] = relationship(
        "EffectiveFunction", back_populates="contract", cascade="all, delete-orphan"
    )
    principal_labels: Mapped[list["PrincipalLabel"]] = relationship(
        "PrincipalLabel", back_populates="contract", cascade="all, delete-orphan"
    )
    dependencies: Mapped[list["ContractDependency"]] = relationship(
        "ContractDependency", back_populates="contract", cascade="all, delete-orphan"
    )
    balances: Mapped[list["ContractBalance"]] = relationship(
        "ContractBalance", back_populates="contract", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_contracts_job_id", "job_id"),
        Index("ix_contracts_protocol_id", "protocol_id"),
        Index("ix_contracts_nominated_protocol_id", "nominated_protocol_id"),
        UniqueConstraint("address", "chain", name="uq_contract_address_chain"),
    )


class ContractSummary(Base):
    __tablename__ = "contract_summaries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    control_model: Mapped[str | None] = mapped_column(String(50), nullable=True)
    is_upgradeable: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    is_pausable: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    has_timelock: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    is_factory: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    is_nft: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    standards: Mapped[list[str] | None] = mapped_column(ARRAY(String(50)), nullable=True)
    source_verified: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    contract: Mapped[Contract] = relationship("Contract", back_populates="summary")


class RoleDefinition(Base):
    __tablename__ = "role_definitions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    role_name: Mapped[str] = mapped_column(String(255), nullable=False)
    declared_in: Mapped[str | None] = mapped_column(String(255), nullable=True)

    contract: Mapped[Contract] = relationship("Contract", back_populates="role_definitions")

    __table_args__ = (Index("ix_role_definitions_contract_id", "contract_id"),)


class ControllerValue(Base):
    __tablename__ = "controller_values"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    # The proxy this row was resolved against (NULL = own deployment), so one impl row can hold per-proxy sets
    # (migration d4e8f1a9c2b7).
    deployment_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    controller_id: Mapped[str] = mapped_column(String(255), nullable=False)
    value: Mapped[str | None] = mapped_column(String(66), nullable=True)
    resolved_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    source: Mapped[str | None] = mapped_column(String(255), nullable=True)
    block_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # ``none_as_null`` so ``None`` (not determined) is SQL NULL, not the jsonb ``null`` that ``IS NULL`` can't see
    # (db/jsonb.py). The watcher clears this on rotation.
    details: Mapped[Any | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    # 'eth_call' / 'eth_call_impl_fallback' / 'eth_call_error' / 'beacon_owner' from the resolution snapshot, or
    # 'event_log' / 'storage_poll' from the watcher.
    observed_via: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # 'caller_gate' | 'call_target' | NULL (not determined, not a synonym for either). Separates authority registries
    # from mere callees. See ``ControllerProvenance``.
    authority_provenance: Mapped[str | None] = mapped_column(String(32), nullable=True)

    contract: Mapped[Contract] = relationship("Contract", back_populates="controller_values")

    __table_args__ = (Index("ix_controller_values_contract_id", "contract_id"),)


class ControlGraphNode(Base):
    __tablename__ = "control_graph_nodes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    deployment_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    address: Mapped[str] = mapped_column(String(42), nullable=False)
    node_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    resolved_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    contract_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    depth: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Compatibility only; ``False`` conflates four populations. Read ``analysis_state``.
    analyzed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # 'analyzed' | 'not_analyzable' | 'attempt_failed' | 'beyond_depth_horizon' | NULL. ``beyond_depth_horizon`` is
    # about our walk, not the address. Written by the resolution walk, and NULLs are filled by
    # ``services.governance.control_graph_types.reconcile_control_graph_types``. See
    # ``schemas.resolved_control_graph.ResolvedAnalysisState``.
    analysis_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # The producing walk's ``max_depth`` (NULL = unknown), so ``depth`` can show a horizon cutoff.
    graph_max_depth: Mapped[int | None] = mapped_column(Integer, nullable=True)
    details: Mapped[Any | None] = mapped_column(JSONB, nullable=True)

    contract: Mapped[Contract] = relationship("Contract", back_populates="control_graph_nodes")

    __table_args__ = (Index("ix_control_graph_nodes_contract_id", "contract_id"),)


class ControlGraphEdge(Base):
    __tablename__ = "control_graph_edges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    deployment_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    from_node_id: Mapped[str] = mapped_column(String(255), nullable=False)
    to_node_id: Mapped[str] = mapped_column(String(255), nullable=False)
    relation: Mapped[str | None] = mapped_column(String(100), nullable=True)
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_controller_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    notes: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)

    contract: Mapped[Contract] = relationship("Contract", back_populates="control_graph_edges")

    __table_args__ = (Index("ix_control_graph_edges_contract_id", "contract_id"),)


# ``ControlGraphEdge.relation`` vocabulary. ``controller_value`` and owner/principal relations are control claims
# (reversed: the to-node controls the from-node). ``external_call_target`` only says the from-node calls the to-node,
# which confers no authority.
EDGE_RELATION_CONTROLLER_VALUE = "controller_value"
EDGE_RELATION_EXTERNAL_CALL_TARGET = "external_call_target"
# For a tracked controller with absent ``authority_provenance``: neither an authority claim nor a callee claim is
# proven. Keeps the edge visible but out of ``CONTROL_EDGE_RELATIONS``.
EDGE_RELATION_CONTROLLER_VALUE_UNATTRIBUTED = "controller_value_unattributed"

# A ``function_principals`` row materialized into the graph by
# ``services.governance.control_graph_types.materialize_fp_principal_nodes``.
#
# Not ``role_principal``, which asserts a witnessed role; many of these rows are ones where ``capability_role_grants``
# refused to assert one. It does assert authority (a resolved principal of a gated function), so it's in
# ``CONTROL_EDGE_RELATIONS``. It adds no new value to the effects closure (``build_authority_graph`` already folds FP
# rows); it makes the link visible to table-plane readers.
EDGE_RELATION_CAPABILITY_PRINCIPAL = "capability_principal"

# Allowlist: new relations move no authority until classified here.
CONTROL_EDGE_RELATIONS = frozenset(
    {
        EDGE_RELATION_CONTROLLER_VALUE,
        "safe_owner",
        "timelock_owner",
        "proxy_admin_owner",
        "role_principal",
        "mapping_member",
        EDGE_RELATION_CAPABILITY_PRINCIPAL,
    }
)


# Values written by the monitoring watcher; the resolution snapshot's own live in services/resolution.
CONTROLLER_OBSERVED_VIA_EVENT_LOG = "event_log"
CONTROLLER_OBSERVED_VIA_STORAGE_POLL = "storage_poll"


# ``UpgradeEvent.source`` vocabulary; NULL means the writer is unknown (pre-column rows).
UPGRADE_SOURCE_BACKFILL = "backfill"
UPGRADE_SOURCE_EVENT_SCAN = "event_scan"
UPGRADE_SOURCE_POLL = "poll"


# ``UpgradeTransaction.executor_kind``. Two proven positives (a keccak-matched marker log whose emitter was
# independently typed) and ``not_determined`` for everything else. No ``eoa_one_hop``: a receipt's ``tx.from`` isn't
# proof of the caller at the upgrade site.
EXECUTOR_KIND_TIMELOCK_ROUTED = "timelock_routed"
EXECUTOR_KIND_SAFE_DIRECT = "safe_direct"
EXECUTOR_KIND_NOT_DETERMINED = "not_determined"
EXECUTOR_KINDS = (
    EXECUTOR_KIND_TIMELOCK_ROUTED,
    EXECUTOR_KIND_SAFE_DIRECT,
    EXECUTOR_KIND_NOT_DETERMINED,
)


class UpgradeTransaction(Base):
    """Receipt-derived facts about one upgrade transaction.

    Keyed on the transaction because one tx can emit many ``Upgraded`` logs; ``(chain_id, tx_hash)`` is the governance
    action id. A row means a receipt was read and decoded; absence means never read or read failed, which nullable
    columns on ``upgrade_events`` couldn't express.
    """

    __tablename__ = "upgrade_transactions"

    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Lowercased; also the governance action id (aggregate on this, not ``upgrade_events.id``).
    tx_hash: Mapped[str] = mapped_column(String(66), primary_key=True)
    # ``eth_getTransactionReceipt`` can't be pinned, so ``block_hash`` lets later readers detect a reorg.
    block_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    block_hash: Mapped[str] = mapped_column(String(66), nullable=False)
    # 1 = success, 0 = reverted. A reverted tx upgraded nothing, so positives are withheld unless 1.
    tx_status: Mapped[int] = mapped_column(Integer, nullable=False)
    receipt_from: Mapped[str] = mapped_column(String(42), nullable=False)
    # NULL is a fact (contract creation); "unknown" is the absence of the row.
    receipt_to: Mapped[str | None] = mapped_column(String(42), nullable=True)
    created_contract_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    is_contract_creation: Mapped[bool] = mapped_column(Boolean, nullable=False)
    executor_kind: Mapped[str] = mapped_column(String(20), nullable=False)
    executor_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    # Which plane typed the emitter, for auditability. Plane order isn't a strength ranking; disagreement is
    # ``not_determined``.
    executor_classification_source: Mapped[str | None] = mapped_column(String(40), nullable=True)
    executor_classified_type: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # The height the emitter was classified at (``safe_protection.probe_block``), so ``executor_kind`` doesn't imply the
    # emitter was a Safe at the upgrade's block.
    executor_classification_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # ``CallExecuted`` targets, only for ``timelock_routed`` (NULL otherwise), so readers know which proxies the
    # timelock actually targeted. ``none_as_null`` so absence is SQL NULL, which the CHECK distinguishes.
    executor_call_targets: Mapped[Any | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    # Computed. True only when every stored ``Upgraded`` event for the tx is in the receipt logs, the ``logsBloom`` is
    # well-formed and confirms a present ``Upgraded`` (ruling out an all-zero bloom), and the bloom agrees with the logs
    # about ``CallExecuted``. False withdraws every marker-absence inference, which ``safe_direct`` depends on.
    receipt_log_set_complete_for_tx: Mapped[bool] = mapped_column(Boolean, nullable=False)
    # The receipt's own ``Upgraded`` count per proxy, since stored rows can't reveal their own under-projection.
    receipt_upgraded_counts: Mapped[Any] = mapped_column(JSONB, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "executor_kind IN ('timelock_routed', 'safe_direct', 'not_determined')",
            name="ck_upgrade_transactions_executor_kind",
        ),
        # A positive kind must carry its emitter and typing plane; ``not_determined`` carries neither.
        CheckConstraint(
            "(executor_kind = 'not_determined') = (executor_address IS NULL) "
            "AND (executor_kind = 'not_determined') = (executor_classification_source IS NULL) "
            "AND (executor_kind = 'not_determined') = (executor_classified_type IS NULL)",
            name="ck_upgrade_transactions_executor_gate_attached",
        ),
        # ``jsonb_typeof`` because a null test also passes jsonb ``null``; only never-written is allowed outside
        # ``timelock_routed``.
        CheckConstraint(
            "executor_kind = 'timelock_routed' OR coalesce(jsonb_typeof(executor_call_targets), 'unset') = 'unset'",
            name="ck_upgrade_transactions_call_targets_gated",
        ),
        Index("ix_upgrade_transactions_tx_hash", "tx_hash"),
    )


class ContractCreationWitness(Base):
    """Two independent witnesses that an address was created in a given tx.

    The receipt rule (``to IS NULL AND contractAddress == proxy``) misses factory-deployed proxies, whose
    deployment-time ``Upgraded`` log would otherwise count as an upgrade. The indexer's ``creation_tx_hash`` and
    ``code_absent_at_probe`` (no code the block before) must both be present and agree; otherwise ``not_determined``,
    and the event stays counted (over-counting is honest, dropping real upgrades isn't).
    """

    __tablename__ = "contract_creation_witnesses"

    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    address: Mapped[str] = mapped_column(String(42), primary_key=True)
    # From Etherscan ``getcontractcreation``. NULL = no answer, not "no creation tx".
    creation_tx_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    creation_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # The factory contract whose CREATE/CREATE2 minted this address. NULL = not recorded, not "EOA-created".
    creation_factory: Mapped[str | None] = mapped_column(String(42), nullable=True)
    # Written together with the result, so "probed and code present" differs from "never probed".
    code_probe_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    code_absent_at_probe: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "(code_probe_block IS NULL) = (code_absent_at_probe IS NULL)",
            name="ck_contract_creation_witnesses_code_probe_paired",
        ),
    )


# ``ContractMembershipWitness.rule`` vocabulary; deterministic evidence only, never LLM output.
WITNESS_RULE_W1_CODE = "w1_code"
WITNESS_RULE_W2_STRUCTURAL = "w2_structural"
WITNESS_RULE_W3_CONTROL = "w3_control"
WITNESS_RULE_W4_DEPLOYER = "w4_deployer"
# W4 second arm: lineage from the protocol's own member factory; revoked when the factory is demoted.
WITNESS_RULE_W4_FACTORY = "w4_factory"
WITNESS_RULE_W5_HUMAN = "w5_human"
WITNESS_RULE_W6_LLAMA_SEED = "w6_llama_seed"
# W4-H: admitted on measured deployer affinity, not proof. The distinct rule string is
# how nothing presents it as proven.
WITNESS_RULE_W4H_DEPLOYER_AFFINITY = "w4h_deployer_affinity"
WITNESS_RULES = frozenset(
    {
        WITNESS_RULE_W1_CODE,
        WITNESS_RULE_W2_STRUCTURAL,
        WITNESS_RULE_W3_CONTROL,
        WITNESS_RULE_W4_DEPLOYER,
        WITNESS_RULE_W4_FACTORY,
        WITNESS_RULE_W4H_DEPLOYER_AFFINITY,
        WITNESS_RULE_W5_HUMAN,
        WITNESS_RULE_W6_LLAMA_SEED,
    }
)
# W1 is the code precondition for every promotion and admits nothing alone.
ADMITTING_WITNESS_RULES = frozenset(WITNESS_RULES - {WITNESS_RULE_W1_CODE})


class ContractMembershipWitness(Base):
    """One reason a contract is (or was) a protocol member.

    Member iff ``contracts.protocol_id`` is set and at least one unrevoked row exists. Rows are revoked, never deleted.
    """

    __tablename__ = "contract_membership_witnesses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"), nullable=False)
    rule: Mapped[str] = mapped_column(String(32), nullable=False)
    # The via-fact (member proxy, perimeter controller, deployer EOA); NULL for w1/w5/w6.
    via_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    evidence: Mapped[Any] = mapped_column(JSONB, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    contract: Mapped[Contract] = relationship("Contract")

    __table_args__ = (
        CheckConstraint(
            "rule IN ('w1_code', 'w2_structural', 'w3_control', 'w4_deployer', 'w4_factory', "
            "'w4h_deployer_affinity', 'w5_human', 'w6_llama_seed')",
            name="ck_contract_membership_witnesses_rule",
        ),
        Index("ix_contract_membership_witnesses_contract_id", "contract_id"),
        Index("ix_contract_membership_witnesses_protocol_id", "protocol_id"),
        # Partial uniques because Postgres treats NULL ≠ NULL; a plain composite would admit duplicate via-less rows.
        Index(
            "uq_membership_witness_with_via",
            "contract_id",
            "protocol_id",
            "rule",
            "via_address",
            unique=True,
            postgresql_where=text("via_address IS NOT NULL"),
        ),
        Index(
            "uq_membership_witness_no_via",
            "contract_id",
            "protocol_id",
            "rule",
            unique=True,
            postgresql_where=text("via_address IS NULL"),
        ),
        # For revocation lookups by via alone, over live rows.
        Index(
            "ix_contract_membership_witnesses_active_via",
            "via_address",
            postgresql_where=text("revoked_at IS NULL AND via_address IS NOT NULL"),
        ),
        # Serves the ``evidence @> …`` lookup for a W3-D1 witness by an address in its anchor chain.
        Index(
            "ix_contract_membership_witnesses_evidence",
            "evidence",
            postgresql_using="gin",
            postgresql_ops={"evidence": "jsonb_path_ops"},
        ),
    )


class ContractProbeAttempt(Base):
    """Latest corroboration-probe attempt per (contract, chain): which reads ran, at what block, and what
    they resolved, so a parked candidate is explainable.
    """

    __tablename__ = "contract_probe_attempts"

    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), primary_key=True)
    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # NULL = the probe never reached the wire (unroutable chain).
    block_number: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # {"status": "probed"|"not_routable", "reads": {...}, "resolved_addresses": [...]}; the addresses feed targeted
    # candidate lookups.
    results: Mapped[Any] = mapped_column(JSONB, nullable=False)
    probed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    contract: Mapped[Contract] = relationship("Contract")

    __table_args__ = (
        Index(
            "ix_contract_probe_attempts_resolved",
            text("(results->'resolved_addresses')"),
            postgresql_using="gin",
        ),
    )


class UpgradeEvent(Base):
    __tablename__ = "upgrade_events"
    __table_args__ = (
        Index("ix_upgrade_events_contract_id", "contract_id"),
        # MATCH SIMPLE: a NULL in either column disables it, so an event can exist without its receipt fact.
        ForeignKeyConstraint(
            ["chain_id", "tx_hash"],
            ["upgrade_transactions.chain_id", "upgrade_transactions.tx_hash"],
            name="fk_upgrade_events_upgrade_transaction",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    proxy_address: Mapped[str] = mapped_column(String(42), nullable=False)
    # NULL means this writer doesn't record the predecessor, not that there wasn't one; ``source`` tells them apart.
    old_impl: Mapped[str | None] = mapped_column(String(42), nullable=True)
    new_impl: Mapped[str | None] = mapped_column(String(42), nullable=True)
    # NULL = undetermined. Never 0, which would sort ahead of the real genesis deployment.
    block_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Block timestamp for ``backfill``/``event_scan``; detection time (an upper bound) for ``poll``.
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    tx_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    # 'backfill' | 'event_scan' | 'poll'; NULL = pre-column, writer unknown.
    source: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # Half of the FK to ``upgrade_transactions``, set only once that row exists. NULL means no linked receipt, not an
    # unknown chain.
    chain_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    contract: Mapped[Contract] = relationship("Contract", back_populates="upgrade_events")


class EffectiveFunction(Base):
    __tablename__ = "effective_functions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    deployment_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    function_name: Mapped[str] = mapped_column(String(255), nullable=False)
    selector: Mapped[str | None] = mapped_column(String(10), nullable=True)
    abi_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    effect_labels: Mapped[list[str] | None] = mapped_column(ARRAY(String(100)), nullable=True)
    effect_targets: Mapped[list[str] | None] = mapped_column(ARRAY(String(255)), nullable=True)
    action_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    authority_public: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment=(
            "TWO states over a three-state fact: true = a public path was earned; "
            "false merges 'a caller restriction was witnessed' with 'the authority "
            "could not be determined at all'. Read authority_openness for the split "
            "-- this column alone cannot tell a gated function from an unread one."
        ),
    )
    # Three-state counterpart to ``authority_public``: 'open' | 'restricted' | 'not_determined'. NULL = written before
    # the column.
    authority_openness: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
        comment=(
            "Three-state authority verdict: 'open' (a public path was earned), "
            "'restricted' (a caller restriction was witnessed), 'not_determined' "
            "(no public path and no witnessed caller set). NULL = written before "
            "this column existed; never read it as any of the three."
        ),
    )
    authority_roles: Mapped[Any | None] = mapped_column(
        JSONB,
        nullable=True,
        comment=(
            "Three states, and [] is the NEGATION of null, not a coarsening of it: a "
            "non-empty list is a witnessed (role, principals) requirement; null is "
            "role-gated with the role NOT determined; [] is proven not role-gated. "
            "The null is the JSONB SCALAR null, not SQL NULL -- 'WHERE authority_roles "
            "IS NULL' matches 0 of the 379 undetermined rows; test "
            "jsonb_typeof(authority_roles) = 'null' (see db/jsonb.py)."
        ),
    )
    capability_expr: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    conditions: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    status: Mapped[str | None] = mapped_column(String(50), nullable=True)
    # Plane-1 claims ``{claim_id, tier, witness}``, dual-written beside effect_labels; NULL/[] on older rows.
    claims: Mapped[Any | None] = mapped_column(JSONB, nullable=True)

    # State-mutability witness from ``EffectInfo``. ``effect_targets`` mixes state writes with call heads, so it
    # couldn't answer "does this write state".
    #
    # NULL means not determined (no effects record, or a contradictory one; see ``_mutability_fields``);
    # ``[]``/``false`` mean proven none. ``none_as_null`` on the JSONB pair keeps ``None`` as SQL NULL (db/jsonb.py).
    state_changing: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
        comment=(
            "ABI mutability of a selector-bearing external/public entry point: true when "
            "non-view and non-pure. SQL NULL = not determined and is NOT the same fact as "
            "false; fallback/receive are always NULL here because they have no selector, "
            "which is a different reason from being proven non-mutating."
        ),
    )
    state_writes: Mapped[Any | None] = mapped_column(
        JSONB(none_as_null=True),
        nullable=True,
        comment=(
            "Proven state writes, richer than the state_write sinks (member path, "
            "granularity, hygiene class). SQL NULL = not determined; [] = the effects "
            "stage looked and proved none."
        ),
    )
    sinks: Mapped[Any | None] = mapped_column(
        JSONB(none_as_null=True),
        nullable=True,
        comment=(
            "Kind-tagged sinks (state_write | external_call | delegatecall | "
            "contract_creation | selfdestruct) with body/guard origin. Kept alongside "
            "state_writes because a function can be a proven actor with zero state "
            "writes -- EtherFiRedemptionManager.sweepDust moves tokens under a role gate "
            "with state_writes=[]. SQL NULL = not determined; [] = proven none."
        ),
    )
    cross_contract_gaps: Mapped[Any | None] = mapped_column(
        JSONB(none_as_null=True),
        nullable=True,
        comment=(
            "Body calls whose callee resolves to an address with no readable facts, so their cross-contract claims "
            "are not determined: [{sink_id, selector, callee, reason, callee_job_id}]. SQL NULL = not evaluated; "
            "[] = every resolved callee had facts."
        ),
    )
    writer_selectors: Mapped[list[str] | None] = mapped_column(
        ARRAY(String(10)),
        nullable=True,
        comment=(
            "Selectors to replay when attributing the state writes of this function; empty "
            "when it writes no state. SQL NULL = not determined."
        ),
    )

    contract: Mapped[Contract] = relationship("Contract", back_populates="effective_functions")
    principals: Mapped[list["FunctionPrincipal"]] = relationship(
        "FunctionPrincipal", back_populates="function", cascade="all, delete-orphan"
    )

    __table_args__ = (Index("ix_effective_functions_contract_id", "contract_id"),)


class FunctionPrincipal(Base):
    __tablename__ = "function_principals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    function_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("effective_functions.id", ondelete="CASCADE"), nullable=False
    )
    address: Mapped[str] = mapped_column(String(42), nullable=False)
    resolved_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    origin: Mapped[str | None] = mapped_column(String(255), nullable=True)
    principal_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    details: Mapped[Any | None] = mapped_column(JSONB, nullable=True)

    function: Mapped[EffectiveFunction] = relationship("EffectiveFunction", back_populates="principals")

    __table_args__ = (
        Index("ix_function_principals_function_id", "function_id"),
        Index("ix_function_principals_lower_address", text("lower(address)")),
        Index(
            "ix_function_principals_safe_owners",
            text("(details->'owners')"),
            postgresql_using="gin",
            postgresql_where=text("resolved_type = 'safe'"),
        ),
    )


class PrincipalLabel(Base):
    __tablename__ = "principal_labels"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    deployment_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    address: Mapped[str] = mapped_column(String(42), nullable=False)
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    resolved_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    labels: Mapped[list[str] | None] = mapped_column(ARRAY(String(255)), nullable=True)
    confidence: Mapped[str | None] = mapped_column(String(20), nullable=True)
    details: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    graph_context: Mapped[list[str] | None] = mapped_column(ARRAY(String(255)), nullable=True)

    contract: Mapped[Contract] = relationship("Contract", back_populates="principal_labels")

    __table_args__ = (Index("ix_principal_labels_contract_id", "contract_id"),)


class AddressLabel(Base):
    """Admin-curated name for an arbitrary address, mainly Safe signers and EOA principals.

    Distinct from worker-populated, per-contract ``PrincipalLabel``.

    Global plus per-chain override. ``chain IS NULL`` is global (right for EOAs; the whole legacy
    population). A concrete ``chain`` overrides on that chain only, which matters for contracts. Surrogate ``id``;
    uniqueness via two partial unique indexes, since Postgres treats NULL ≠ NULL.
    """

    __tablename__ = "address_labels"

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    address: Mapped[str] = mapped_column(String(42), nullable=False)
    chain: Mapped[str | None] = mapped_column(String(64), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __table_args__ = (
        Index(
            "uq_address_labels_address_chain",
            "address",
            "chain",
            unique=True,
            postgresql_where=text("chain IS NOT NULL"),
        ),
        Index(
            "uq_address_labels_address_global",
            "address",
            unique=True,
            postgresql_where=text("chain IS NULL"),
        ),
    )


class ContractDependency(Base):
    __tablename__ = "contract_dependencies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    dependency_address: Mapped[str] = mapped_column(String(42), nullable=False)
    dependency_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    relationship_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    source: Mapped[list[str] | None] = mapped_column(ARRAY(String(50)), nullable=True)
    proxy_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    implementation: Mapped[str | None] = mapped_column(String(42), nullable=True)
    admin: Mapped[str | None] = mapped_column(String(42), nullable=True)

    contract: Mapped[Contract] = relationship("Contract", back_populates="dependencies")

    __table_args__ = (Index("ix_contract_dependencies_contract_id", "contract_id"),)
