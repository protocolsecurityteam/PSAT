"""Guard: the ``db/models/`` package registers every mapper on ``Base.metadata``.

``alembic/env.py`` imports ``Base`` from the package for autogenerate; a
submodule dropped from ``db/models/__init__.py`` silently removes its tables
from ``Base.metadata`` and a later autogenerate emits ``DROP TABLE``s. The
count and the sorted-name snapshot are hard-coded from the pre-split module so
a lost submodule import fails loudly here instead.
"""

from __future__ import annotations

from db.models import Base

EXPECTED_TABLE_COUNT = 54

EXPECTED_TABLES = [
    "address_labels",
    "artifacts",
    "audit_contract_coverage",
    "audit_reports",
    "bytecode_cache",
    "contract_balance_fetches",
    "contract_balances",
    "contract_balances_latest",
    "contract_creation_witnesses",
    "contract_dependencies",
    "contract_materializations",
    "contract_summaries",
    "contracts",
    "control_graph_edges",
    "control_graph_nodes",
    "controller_values",
    "daemon_leases",
    "dapp_interactions",
    "effect_behavior_cache",
    "effect_verdicts",
    "effective_functions",
    "effects_plan_markers",
    "etherscan_cache",
    "function_principals",
    "function_score_signals",
    "indexed_event_cursors",
    "indexed_event_logs",
    "job_dependencies",
    "jobs",
    "mapping_enumeration_cache",
    "monitored_contracts",
    "monitored_events",
    "monitoring_enrollment_queue",
    "principal_labels",
    "protocol_score_queue",
    "protocol_scores",
    "protocol_scores_latest",
    "protocol_subscriptions",
    "protocols",
    "proxy_subscriptions",
    "proxy_upgrade_events",
    "restaking_positions",
    "restaking_positions_latest",
    "role_definitions",
    "role_holder_plane_refreshes",
    "role_holder_planes",
    "source_files",
    "token_delivery_evidence",
    "token_protocol_reference",
    "tvl_snapshots",
    "upgrade_events",
    "upgrade_transactions",
    "watched_proxies",
    "worker_heartbeats",
]


def test_metadata_table_count_matches_pre_split_module():
    assert len(Base.metadata.tables) == EXPECTED_TABLE_COUNT


def test_metadata_table_names_match_pre_split_snapshot():
    assert sorted(Base.metadata.tables) == EXPECTED_TABLES
