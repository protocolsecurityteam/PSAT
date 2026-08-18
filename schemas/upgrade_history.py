"""Typed schemas for upgrade history artifacts.

Shapes mirror what ``services.discovery.upgrade_history`` actually writes:
``parse_upgrade_log`` builds ``UpgradeEventRecord`` (four base keys always,
per-event-type keys only when the log data decodes), and
``build_upgrade_history`` returns ``UpgradeHistoryOutput``. ``UpgradeEventRecord``
is named to stay distinct from the ORM model ``db.models.UpgradeEvent``, which
the producer module also imports.
"""

from __future__ import annotations

from typing import Literal, TypedDict, get_args

from typing_extensions import NotRequired, Required

UpgradeEventType = Literal[
    "upgraded",
    "admin_changed",
    "beacon_upgraded",
    # GnosisSafe ChangedMasterCopy
    "changed_master_copy",
    # Compound NewImplementation / NewPendingImplementation
    "new_implementation",
    "new_pending_implementation",
    # Synthetix TargetUpdated
    "target_updated",
    # Aave V2 — carries a revision number, not an implementation address
    "upgraded_revision",
    # EIP-2535 DiamondCut
    "diamond_cut",
]

UPGRADE_EVENT_TYPES: frozenset[str] = frozenset(get_args(UpgradeEventType))


class UpgradeEventRecord(TypedDict):
    event_type: UpgradeEventType
    block_number: int
    tx_hash: str | None
    # Absent on the DB-projection path (persisted rows don't carry it).
    log_index: NotRequired[int]
    timestamp: NotRequired[int | None]
    # upgraded / changed_master_copy / new_implementation /
    # new_pending_implementation / target_updated / diamond_cut (first facet)
    implementation: NotRequired[str]
    # new_implementation only — the displaced implementation from the log data
    old_implementation: NotRequired[str]
    # admin_changed
    previous_admin: NotRequired[str]
    new_admin: NotRequired[str]
    # beacon_upgraded
    beacon: NotRequired[str]
    # upgraded_revision
    revision: NotRequired[int]
    # diamond_cut — every non-Remove facet address
    facets: NotRequired[list[str]]


class ImplementationRecord(TypedDict, total=False):
    address: Required[str]
    contract_name: str | None
    block_introduced: int
    timestamp_introduced: int | None
    tx_hash: str | None
    block_replaced: int | None
    timestamp_replaced: int | None


class ProxyUpgradeHistory(TypedDict):
    proxy_address: str
    proxy_type: str
    current_implementation: str | None
    upgrade_count: int
    first_upgrade_block: int | None
    last_upgrade_block: int | None
    implementations: list[ImplementationRecord]
    events: list[UpgradeEventRecord]


class UpgradeHistoryOutput(TypedDict):
    schema_version: str
    target_address: str
    proxies: dict[str, ProxyUpgradeHistory]
    total_upgrades: int
    # Stamped only by ``synthesize_from_events`` (DB-projection fallback).
    synthesized: NotRequired[bool]
