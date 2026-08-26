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


# ---------------------------------------------------------------------------
# Pipeline artifact tables (replace JSONB blobs)
# ---------------------------------------------------------------------------


class Contract(Base):
    __tablename__ = "contracts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True
    )
    protocol_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("protocols.id", ondelete="SET NULL"), nullable=True
    )
    # Which protocol NOMINATED this address (membership gate, spec §3.1).
    # Never a membership claim: ``protocol_id`` stays the single member stamp,
    # and only ``services.discovery.membership_gate`` may write it.
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
    # Additional logic contracts this proxy delegates to beyond the EIP-1967
    # slot ``implementation`` — the split-proxy / admin-impl pattern where the
    # primary impl's ``fallback`` delegatecalls an address held in an ordinary
    # state variable (e.g. ether.fi LRTSquared's ``adminImpl``). Resolved
    # against the PROXY's storage and analyzed as proxy-child jobs so their
    # authority resolves to the proxy's controller. See
    # services/discovery/secondary_impl.py.
    secondary_implementations: Mapped[list[str] | None] = mapped_column(ARRAY(String(42)), nullable=True)
    deployer: Mapped[str | None] = mapped_column(String(42), nullable=True)
    remappings: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
    rank_score: Mapped[float | None] = mapped_column(Numeric(10, 4), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Numeric(10, 4), nullable=True)
    # Every source that has independently confirmed this contract for the
    # protocol. Writers union their tag in instead of overwriting, so
    # ranking can boost contracts corroborated by multiple discovery
    # pipelines (e.g. shown on the docs page AND called by the DApp).
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
    # Proxy/deployment this row was resolved against (NULL = own/sole deployment).
    # Lets one impl-bytecode contract row hold N per-proxy sets; see migration d4e8f1a9c2b7.
    deployment_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    controller_id: Mapped[str] = mapped_column(String(255), nullable=False)
    value: Mapped[str | None] = mapped_column(String(66), nullable=True)
    resolved_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    source: Mapped[str | None] = mapped_column(String(255), nullable=True)
    block_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # ``none_as_null=True``: a Python ``None`` here means "not determined" and
    # must reach the database as SQL NULL. SQLAlchemy's default renders it as
    # the jsonb scalar ``null``, which is a DIFFERENT state that no ``IS NULL``
    # test can see (db/jsonb.py). The watcher clears this field on a
    # controller rotation, so the distinction is load-bearing.
    details: Mapped[Any | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    # How the current value was observed: 'eth_call' / 'eth_call_impl_fallback'
    # / 'eth_call_error' / 'beacon_owner' from the resolution snapshot, or
    # 'event_log' / 'storage_poll' when the watcher rotated it.
    observed_via: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # 'caller_gate' | 'call_target' | NULL. NULL is a third state — the static
    # stage did not determine why this address is attached — and is NOT a
    # synonym for either value. Before this column the analyzer unioned "the
    # caller is checked against this address" with "this address gets called",
    # so a callee (eETH, lido, liquidityPool) was indistinguishable from an
    # authority registry on the persisted row. See ``ControllerProvenance``.
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
    # Kept for compatibility; ``False`` on it is four different populations at
    # once. ``analysis_state`` is what a consumer must read.
    analyzed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # 'analyzed' | 'not_analyzable' | 'attempt_failed' | 'beyond_depth_horizon'
    # | NULL (not determined). ``beyond_depth_horizon`` is a fact about OUR
    # walk, not about the address, and is the one the bool could never express:
    # without ``graph_max_depth`` below it was not even derivable from the row.
    # Two writers: the resolution walk's stamp, and
    # ``services.governance.control_graph_types.reconcile_control_graph_types``,
    # which fills NULL (only NULL) with the walk's own derivation after a type
    # fold determines analyzability the walk could not.
    # See ``schemas.resolved_control_graph.ResolvedAnalysisState``.
    analysis_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # The ``max_depth`` of the walk that produced this row. NULL = not
    # determined. Without it ``depth`` alone cannot say whether an unanalysed
    # contract was skipped by the horizon or by something else.
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


# ``ControlGraphEdge.relation`` vocabulary.
#
# ``controller_value`` and the owner/principal relations are *control* claims:
# reversed, they say the to-node has authority over the from-node.
# ``external_call_target`` is not — it says the from-node calls the to-node,
# which is a proven fact about the code but carries no authority: being called
# by X confers nothing over X. Until this split both were written as
# ``controller_value``, and 66 directed edge pairs asserted "A controls B" and
# "B controls A" at once.
EDGE_RELATION_CONTROLLER_VALUE = "controller_value"
EDGE_RELATION_EXTERNAL_CALL_TARGET = "external_call_target"
# The third state. ``controller_value`` asserts "the to-node has authority over
# the from-node"; ``external_call_target`` asserts the opposite positive fact
# ("merely called, confers nothing"). A tracked controller whose
# ``authority_provenance`` is ABSENT supports NEITHER: the static stage answered
# neither question, so the address appeared in a lowered predicate tree without
# ever being shown to gate a caller or to be a call destination. Writing it
# ``controller_value`` makes an authority claim nothing proved (widening the
# lowered tree minted 37 such targets at once, incl. pure constants like
# HUNDRED_PERCENT_IN_BPS and non-authority mappings like _balances); writing it
# ``external_call_target`` asserts the other unproven fact. This relation keeps
# the edge VISIBLE and out of ``CONTROL_EDGE_RELATIONS``, so it moves no
# authority and no value through the closure.
EDGE_RELATION_CONTROLLER_VALUE_UNATTRIBUTED = "controller_value_unattributed"

# A ``function_principals`` row, materialized into the graph plane by
# ``services.governance.control_graph_types.materialize_fp_principal_nodes``.
#
# Deliberately NOT ``role_principal``. That relation asserts a WITNESSED ROLE
# ("this address holds role R"), and the largest population reaching this pass
# is precisely the one for which ``capability_role_grants`` REFUSED to assert a
# role: a ``_ROLE_DISSOLVING_TRACE_STEPS`` trace leaves
# ``effective_functions.authority_roles`` JSON null, and 127 further rows carry
# ``authority_roles == []`` (authority proven, not role-keyed). Writing those as
# ``role_principal`` would mint the exact claim the upstream declined to make.
#
# What it DOES assert is the FP row itself: this address is a resolved principal
# of a gated function on the from-node contract. That is an authority claim, so
# it belongs in ``CONTROL_EDGE_RELATIONS`` below. It moves NO NEW VALUE through
# the effects closure: ``services.effects.selection.build_authority_graph``
# already folds ``function_principals`` straight into the closure as
# "principal -> the contract the function lives on", so this edge duplicates an
# authority link the closure carries anyway — it makes it reachable in the TABLE
# plane (Surface, chat, enrollment) that reads edges instead of FP rows.
EDGE_RELATION_CAPABILITY_PRINCIPAL = "capability_principal"

# Allowlist, not a denylist: a relation this set does not name contributes no
# authority. A new relation therefore has to be classified deliberately before
# it can move value through the authority closure, instead of being folded in
# by default the way ``external_call_target`` would have been.
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


# ``ControllerValue.observed_via`` values written by the monitoring watcher.
# The resolution snapshot's own vocabulary ('eth_call', 'eth_call_error',
# 'eth_call_impl_fallback', 'beacon_owner') lives in services/resolution.
CONTROLLER_OBSERVED_VIA_EVENT_LOG = "event_log"
CONTROLLER_OBSERVED_VIA_STORAGE_POLL = "storage_poll"


# ``UpgradeEvent.source`` vocabulary. Three writers, three values; NULL is the
# fourth state ("writer unknown") and belongs to rows written before the column.
UPGRADE_SOURCE_BACKFILL = "backfill"
UPGRADE_SOURCE_EVENT_SCAN = "event_scan"
UPGRADE_SOURCE_POLL = "poll"


# ``UpgradeTransaction.executor_kind`` vocabulary. The enum is deliberately
# three-valued: the two positives are each a *proven* routing fact (a
# keccak-matched marker log whose emitter an independent classifier typed), and
# ``not_determined`` is the single state every failure, revert, absence and
# unclassified-emitter path reaches. There is no ``eoa_one_hop`` member: a
# receipt proves ``tx.from`` was msg.sender in the TOP-LEVEL frame, which is not
# proof it was msg.sender at the upgrade site, and never proof of who authorised.
EXECUTOR_KIND_TIMELOCK_ROUTED = "timelock_routed"
EXECUTOR_KIND_SAFE_DIRECT = "safe_direct"
EXECUTOR_KIND_NOT_DETERMINED = "not_determined"
EXECUTOR_KINDS = (
    EXECUTOR_KIND_TIMELOCK_ROUTED,
    EXECUTOR_KIND_SAFE_DIRECT,
    EXECUTOR_KIND_NOT_DETERMINED,
)


class UpgradeTransaction(Base):
    """Receipt-derived facts about ONE upgrade transaction.

    Keyed on the transaction, not the event, because the facts are properties of
    the transaction: one tx emits up to 19 ``Upgraded`` logs across 19 proxies in
    this corpus, and storing the executor fact per event would store 19 mutable
    copies of one fact and let a consumer count one governance action 19 times.
    ``(chain_id, tx_hash)`` IS the governance action id.

    **Row existence is the coverage discriminator.** A row means a receipt was
    read and decoded; its absence means never read or read failed. That is the
    distinction nullable columns on ``upgrade_events`` could not express —
    ``executor_kind IS NULL`` would conflate "not fetched" with "fetched and
    undetermined", which is a defaulted witness by construction.
    """

    __tablename__ = "upgrade_transactions"

    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Lowercased 0x-prefixed 32-byte hash. Also the ``governance_action_id``:
    # aggregate on this, never on ``upgrade_events.id``.
    tx_hash: Mapped[str] = mapped_column(String(66), primary_key=True)
    # Observation coordinates. ``eth_getTransactionReceipt`` takes no block
    # parameter, so this read cannot be pinned by parameter the way every other
    # chain read in the codebase is; ``block_hash`` is what lets a later reader
    # DETECT a reorg instead of having to trust the original observation.
    block_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    block_hash: Mapped[str] = mapped_column(String(66), nullable=False)
    # 1 = success, 0 = reverted. A reverted transaction cannot have upgraded
    # anything, so every positive below is withheld unless this is 1.
    tx_status: Mapped[int] = mapped_column(Integer, nullable=False)
    receipt_from: Mapped[str] = mapped_column(String(42), nullable=False)
    # NULL is a FACT (the transaction is a contract creation), distinguished
    # from "unknown" by the row existing at all.
    receipt_to: Mapped[str | None] = mapped_column(String(42), nullable=True)
    created_contract_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    is_contract_creation: Mapped[bool] = mapped_column(Boolean, nullable=False)
    executor_kind: Mapped[str] = mapped_column(String(20), nullable=False)
    executor_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    # Which persisted plane typed the emitter, and as what. Recorded so the
    # verdict is auditable; the plane order is fixed and is NOT a strength
    # ranking — planes that disagree yield ``not_determined``.
    executor_classification_source: Mapped[str | None] = mapped_column(String(40), nullable=True)
    executor_classified_type: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # Height at which the emitter was classified, from the classifier's own
    # ``safe_protection.probe_block``. NULL = not determined. The classification
    # plane carries no block on rows written before that probe existed, so this
    # is the field that keeps ``executor_kind`` from implying "…and the emitter
    # was a Safe AT the upgrade's block", which the receipt cannot prove.
    executor_classification_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # The ``target`` word decoded from each ``CallExecuted`` log, gated on
    # ``executor_kind='timelock_routed'`` (NULL otherwise — the strength gate is
    # not detachable from the payload). Lets a reader tell which proxies the
    # timelock call actually targeted instead of attributing every log in the
    # transaction to it.
    # ``none_as_null`` so an absent target list is SQL NULL (not determined),
    # never the JSON literal ``null`` — the CHECK below distinguishes them and
    # so would any consumer.
    executor_call_targets: Mapped[Any | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    # COMPUTED, never asserted. True only when (i) every stored ``Upgraded``
    # event for this tx is present in the receipt's own log array, emitted by
    # its proxy, (ii) the ``logsBloom`` is present, well-formed and passes a
    # positive control — it must confirm an ``Upgraded`` log the array actually
    # carries, which is what rules out the all-zero bloom that answers "absent"
    # to everything — and (iii) that usable bloom agrees with the log array
    # about ``CallExecuted`` (a bloom has no false negatives, so bloom-absent is
    # then independent proof of absence; bloom-present with no such log means
    # the array may be pruned). False withdraws every marker-ABSENCE inference —
    # which is the whole basis of ``safe_direct``.
    receipt_log_set_complete_for_tx: Mapped[bool] = mapped_column(Boolean, nullable=False)
    # The receipt's own ``Upgraded``-log count per emitting proxy. Kept because
    # the projected rows cannot witness their own under-projection: if only one
    # of two logs was stored, the stored pair count says "one event" and the
    # deployment guard would exclude a transaction that also carried a real
    # implementation change.
    receipt_upgraded_counts: Mapped[Any] = mapped_column(JSONB, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "executor_kind IN ('timelock_routed', 'safe_direct', 'not_determined')",
            name="ck_upgrade_transactions_executor_kind",
        ),
        # The strength gate may never be published apart from its payload: a
        # positive kind must carry its emitter AND the plane that typed it, and
        # ``not_determined`` may carry neither.
        CheckConstraint(
            "(executor_kind = 'not_determined') = (executor_address IS NULL) "
            "AND (executor_kind = 'not_determined') = (executor_classification_source IS NULL) "
            "AND (executor_kind = 'not_determined') = (executor_classified_type IS NULL)",
            name="ck_upgrade_transactions_executor_gate_attached",
        ),
        # ``jsonb_typeof`` rather than a SQL null test: a null test also passes
        # the jsonb scalar ``null``, and a written-null here would be a target
        # list a writer claimed to have recorded. Only the never-written state
        # is admissible outside ``timelock_routed``.
        CheckConstraint(
            "executor_kind = 'timelock_routed' OR coalesce(jsonb_typeof(executor_call_targets), 'unset') = 'unset'",
            name="ck_upgrade_transactions_call_targets_gated",
        ),
        Index("ix_upgrade_transactions_tx_hash", "tx_hash"),
    )


class ContractCreationWitness(Base):
    """Two independent witnesses that an address was created in a given tx.

    The receipt rule (``to IS NULL AND contractAddress == proxy``) catches only
    the proxies deployed by an EOA-sent creation transaction. A proxy deployed
    BY A FACTORY has a populated ``receipt.to`` and is indistinguishable from an
    upgrade on the receipt alone, so its deployment-time ``Upgraded`` log gets
    counted as an upgrade. This table carries the second arm.

    **Both witnesses are required and they must agree.** ``creation_tx_hash``
    alone is a claim by an indexer; ``code_absent_at_probe`` alone proves only
    that the address was empty at some height. Together — the indexer names this
    exact tx AND the address provably had no code in the block before the event
    — they prove the event is a deployment. Disagreement, or either witness
    missing, yields ``not_determined``, and a ``not_determined`` event stays
    COUNTED (an upgrade count that may over-count is honest; one that silently
    drops real upgrades is not).
    """

    __tablename__ = "contract_creation_witnesses"

    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    address: Mapped[str] = mapped_column(String(42), primary_key=True)
    # From Etherscan ``getcontractcreation``. NULL = the indexer did not answer,
    # never "the address has no creation tx".
    creation_tx_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    creation_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # ``getcontractcreation``'s ``contractFactory``: the contract whose CREATE/
    # CREATE2 frame minted this address. NULL = no factory attribution recorded
    # — never "created directly by an EOA".
    creation_factory: Mapped[str | None] = mapped_column(String(42), nullable=True)
    # The height at which ``eth_getCode`` was read, and what it said. NULL/NULL
    # = not probed; the pair is written together so "probed and code was there"
    # is distinguishable from "never probed".
    code_probe_block: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    code_absent_at_probe: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "(code_probe_block IS NULL) = (code_absent_at_probe IS NULL)",
            name="ck_contract_creation_witnesses_code_probe_paired",
        ),
    )


# ``ContractMembershipWitness.rule`` vocabulary (membership gate, spec §3.2).
# Deterministic evidence only; no rule may ever be produced from LLM output.
WITNESS_RULE_W1_CODE = "w1_code"
WITNESS_RULE_W2_STRUCTURAL = "w2_structural"
WITNESS_RULE_W3_CONTROL = "w3_control"
WITNESS_RULE_W4_DEPLOYER = "w4_deployer"
# W4 family, second arm (owner ruling): lineage from the protocol's own
# ANCHORING MEMBER factory, per the recorded ``creation_factory`` attribution.
# Its via-fact is a member, not a registry EOA, so it carries its own
# revocation story — the factory's demotion revokes it.
WITNESS_RULE_W4_FACTORY = "w4_factory"
WITNESS_RULE_W5_HUMAN = "w5_human"
WITNESS_RULE_W6_LLAMA_SEED = "w6_llama_seed"
# W4-H (DEPLOYER_HEURISTIC_SPEC.md §1): lineage from a trust-class-H deployer,
# admitted on measured affinity rather than on proof. The distinct rule string
# is the honesty boundary — no display, export or API may present a heuristic
# membership as proven (that spec's invariant 1).
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
# Rules that admit membership on their own. W1 is the code precondition for
# every promotion (invariant 3) and alone admits nothing.
ADMITTING_WITNESS_RULES = frozenset(WITNESS_RULES - {WITNESS_RULE_W1_CODE})


class ContractMembershipWitness(Base):
    """One recorded reason a contract is (or was) a member of a protocol.

    Member ⇔ ``contracts.protocol_id`` set AND ≥1 row here with
    ``revoked_at IS NULL``. Rows are revoked, never deleted (invariant 4).
    """

    __tablename__ = "contract_membership_witnesses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    protocol_id: Mapped[int] = mapped_column(Integer, ForeignKey("protocols.id", ondelete="CASCADE"), nullable=False)
    rule: Mapped[str] = mapped_column(String(32), nullable=False)
    # The via-fact the witness rests on (member proxy, perimeter controller,
    # deployer EOA). NULL for rules with no via-fact (w1/w5/w6).
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
        # Uniqueness on (contract, protocol, rule, via_address) — as a partial
        # pair because Postgres treats NULL ≠ NULL: a plain composite unique
        # would admit duplicate via-less (w1/w5/w6) rows (same trap
        # ``uq_contract_address_chain`` already hit; see ``AddressLabel``).
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
        # The revocation frontier probes the via ALONE, which the composite
        # uniques above cannot serve (via_address is their fourth column), and
        # only over live rows — a revoked witness is history, never a target.
        Index(
            "ix_contract_membership_witnesses_active_via",
            "via_address",
            postgresql_where=text("revoked_at IS NULL AND via_address IS NOT NULL"),
        ),
        # Serves the ``evidence @> …`` containment that finds a W3-D1 witness
        # by an address inside its published anchor chain.
        Index(
            "ix_contract_membership_witnesses_evidence",
            "evidence",
            postgresql_using="gin",
            postgresql_ops={"evidence": "jsonb_path_ops"},
        ),
    )


class ContractProbeAttempt(Base):
    """Latest corroboration-probe attempt per (contract, chain) — spec §3.5.

    Exists so a candidate's parked state is explainable from persisted rows
    (invariant 5): which reads ran, at what block, and what each resolved.
    Code/creation facts stay in ``contract_creation_witnesses``; this row
    carries the owner/authority/EIP-1967 reads that table cannot express.
    """

    __tablename__ = "contract_probe_attempts"

    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), primary_key=True)
    chain_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Height the reads were pinned at. NULL = the probe never reached the wire
    # (unroutable chain), which ``results.status`` states explicitly.
    block_number: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # {"status": "probed"|"not_routable", "reads": {read: {ok, value, error}},
    #  "resolved_addresses": [..]} — the address list feeds the gate's targeted
    # candidate lookups (spec §3.4 event 2).
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
        # MATCH SIMPLE: a NULL in EITHER column disables the constraint, which
        # is what lets an event exist before (or without) its receipt fact and
        # what carries the poll writer's tx_hash-less rows.
        ForeignKeyConstraint(
            ["chain_id", "tx_hash"],
            ["upgrade_transactions.chain_id", "upgrade_transactions.tx_hash"],
            name="fk_upgrade_events_upgrade_transaction",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    contract_id: Mapped[int] = mapped_column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False)
    proxy_address: Mapped[str] = mapped_column(String(42), nullable=False)
    # NULL means "this writer does not record the predecessor", not "there was
    # no predecessor". ``source`` is what tells the two apart: the backfiller
    # projects an artifact that never carried old_impl, the watcher reads the
    # slot's previous value. Without the discriminator both are NULL.
    old_impl: Mapped[str | None] = mapped_column(String(42), nullable=True)
    new_impl: Mapped[str | None] = mapped_column(String(42), nullable=True)
    # NULL = the block was not determined by the writer. Never 0: every
    # consumer orders by this column with ``nullslast()``, and 0 sorts ahead
    # of the genuine genesis deployment, which shifts every impl-era window.
    block_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # For ``source='backfill'`` / ``'event_scan'`` this is the on-chain block
    # timestamp. For ``source='poll'`` no block is known, so it carries the
    # detection time — an upper bound within one poll interval of the change.
    # ``source`` is the only thing that distinguishes the two readings.
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    tx_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    # Which writer produced this row: 'backfill' (upgrade-history artifact
    # projection), 'event_scan' (log-derived), 'poll' (storage-slot poll).
    # NULL = written before this column existed; the writer is unknown, which
    # is a third state and not a synonym for either value.
    source: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # Link half of the composite FK to ``upgrade_transactions``. Set ONLY once
    # the receipt-fact row for this ``tx_hash`` exists, so NULL means "no linked
    # receipt fact" — it is NOT a claim that the chain is unknown (the chain is
    # always derivable from ``contracts.chain``). Nothing reads it as a chain
    # discriminator; it exists so the join to the per-transaction facts is a
    # real foreign key rather than a convention.
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
    # Three-state counterpart to ``authority_public`` (whose ``False`` merges a
    # witnessed caller restriction with "we could not determine the authority"):
    # 'open' | 'restricted' | 'not_determined'. NULL = the writer that produced
    # this row predates the column and cannot be read as any of the three.
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
    # Plane-1 claims: list of {claim_id, tier, witness}, dual-written alongside
    # the legacy effect_labels. NULL/[] on rows written before the claims plane.
    claims: Mapped[Any | None] = mapped_column(JSONB, nullable=True)

    # State-mutability witness, carried from the effects stage's ``EffectInfo``.
    # Before these columns the only way to ask "does this function write state"
    # was ``effect_targets``, which concatenates state-write variable names with
    # dotted external-call heads: 501 of its 1642 populated rows carry only call
    # heads, so a populated value asserted a write that was never proven.
    #
    # All four are nullable BECAUSE SQL NULL is a distinct fact here — "not
    # determined", i.e. no effects record covered this signature, or the record
    # contradicted itself (see ``_mutability_fields``). ``[]`` / ``false`` mean
    # the effects stage looked and proved none. A consumer that cannot tell those
    # apart re-creates the defect these columns exist to remove.
    #
    # ``none_as_null=True`` on the JSONB pair is load-bearing: SQLAlchemy's
    # default renders a Python ``None`` as the jsonb scalar ``null``, which is a
    # DIFFERENT state from SQL NULL and is why ``conditions`` above is unusable
    # in a null test on 780 of its 1773 rows (see ``db/jsonb.py``).
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
    """Admin-curated human-readable name for an arbitrary address.

    Exists to give Safe signers and EOA principals — which are just raw
    addresses with no on-chain metadata — a legible name in the UI. Distinct
    from ``PrincipalLabel`` which is worker-populated and scoped per-contract.

    Global-plus-override model (invariant 12): ``chain`` is a nullable
    chain-NAME string (``'ethereum'``, ``'base'`` — entity tables key on chain
    names, not ids, per invariant 11).

      * ``chain IS NULL`` is a **global** label that applies on every chain.
        This is the right semantics for EOA/Safe-signer labels — the same key
        controls the same off-chain account everywhere — and is this table's
        entire legacy population, so those rows stay untouched and behave
        exactly as before (no backfill).
      * A row with a concrete ``chain`` **overrides** the global label on that
        chain only. This is what makes *contract* labels safe cross-chain: the
        same address is a different contract on each chain and can carry a
        different name per network.

    Identity is a surrogate ``id`` (the bare-address PK collided for contracts
    at the same address on two chains). Uniqueness is enforced by two PARTIAL
    unique indexes rather than a plain ``UNIQUE(address, chain)`` — Postgres
    treats NULL ≠ NULL, so a plain composite unique would admit duplicate
    global rows (this codebase was already bitten by exactly that on
    ``uq_contract_address_chain``). A sentinel chain value was also rejected
    because the sentinel would leak into API semantics.
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
