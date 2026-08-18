"""Integration tests for cross-module pipeline wiring.

Validates behavior that spans multiple modules:
  1. Static worker dependency phase wiring (proxy_address, upgrade_history storage)
  2. API merge + display name pipeline
  3. API detail endpoint artifact inlining
  4. Graph builder label resolution via contract_meta
  5. Full dependency data flow: unified deps -> graph viz -> upgrade history
  6. Discovery -> Static artifact handoff (contract_meta, build_settings, source files)
  7. Static -> Resolution artifact handoff (contract_analysis, control_tracking_plan)
  8. Resolution -> Policy artifact handoff (control_snapshot, resolved_control_graph)
  9. Policy final artifact storage (effective_permissions, principal_labels)
  10. API analyses list and detail endpoints serve worker-stored artifacts correctly
  11. Resolution worker proxy_address override for impl jobs
  12. Tracking plan construction from contract_analysis output
  13. Discovery company mode child job creation

All tests run without live services (no RPC, no Etherscan, no database).
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from tests.support.balance_stubs import page, pinned_native_unavailable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# offline: the dependency phase probes eth_getCode and company mode resolves the
# protocol via DefiLlama — stub both so the cross-module wiring runs with no wire.
pytestmark = pytest.mark.usefixtures("_stub_rpc_bytecode", "_stub_defillama_protocols", "_stub_classifier_rpc")


@pytest.fixture(autouse=True)
def _stub_etherscan_balances(monkeypatch):
    """Offline: the resolution worker's ``_fetch_balances`` probes ETH + token
    balances via Etherscan; benign defaults (these tests assert on address
    rewriting / handoff, not balances). The same call also issues a pinned
    native read over a separate wire, stubbed here to its unavailable outcome."""
    monkeypatch.setattr("utils.etherscan.get_eth_balance", lambda addr, *a, **k: 0)
    monkeypatch.setattr("utils.etherscan.get_native_price", lambda *a, **k: 0.0)
    monkeypatch.setattr("utils.etherscan.get_token_balances_page", lambda addr, *a, **k: page([]))
    pinned_native_unavailable(monkeypatch)


# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

TARGET = "0x1111111111111111111111111111111111111111"
PROXY = "0x2222222222222222222222222222222222222222"
IMPL = "0x3333333333333333333333333333333333333333"
DEP_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
DEP_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

# ---------------------------------------------------------------------------
# Shared helpers / fixtures
# ---------------------------------------------------------------------------


def _job(**overrides) -> Any:
    """Create a duck-typed Job stand-in for tests (avoids DB dependency)."""
    defaults: dict[str, Any] = {
        "id": "job-1",
        "address": TARGET,
        "name": "TestContract",
        "request": {"rpc_url": "https://rpc.example", "chain_id": 1},
        "company": None,
        "protocol_id": None,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _fake_api_job(
    address: str = "0xabc",
    name: str = "demo_run",
    request: dict | None = None,
    company: str | None = None,
    is_proxy: bool = False,
) -> MagicMock:
    job = MagicMock()
    job.id = uuid.uuid4()
    job.address = address
    job.company = company
    job.name = name
    job.status = MagicMock(value="completed")
    job.stage = MagicMock(value="done")
    job.detail = "done"
    job.request = request or {"address": address}
    job.error = None
    job.worker_id = None
    # Must be set explicitly — bare MagicMock attributes are truthy and
    # the analyses listing now reads Job.is_proxy directly (denormalized
    # from contract_flags by the static worker).
    job.is_proxy = is_proxy
    job.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    job.updated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    job.to_dict.return_value = {"job_id": str(job.id), "address": address, "name": name}
    return job


def _mock_session_ctx(mock_session_cls: MagicMock, mock_session: MagicMock) -> None:
    mock_session_cls.return_value.__enter__ = MagicMock(return_value=mock_session)
    mock_session_cls.return_value.__exit__ = MagicMock(return_value=False)


def _static_deps(address: str = TARGET, deps: list[str] | None = None) -> dict:
    return {
        "address": address,
        "dependencies": deps or [],
        "rpc": "https://rpc.example",
        "network": "ethereum",
    }


def _dynamic_deps(address: str = TARGET, deps: list[str] | None = None, graph: list | None = None) -> dict:
    return {
        "address": address,
        "dependencies": deps or [],
        "rpc": "https://rpc.example",
        "dependency_graph": graph or [],
        "transactions_analyzed": [],
        "trace_methods": ["debug_traceTransaction"],
        "trace_errors": [],
    }


def _classifications(target: str = TARGET, cls_map: dict | None = None, discovered: list | None = None) -> dict:
    return {
        "address": target,
        "classifications": cls_map or {},
        "discovered_addresses": discovered or [],
    }


def _patch_dep_phase(monkeypatch, worker, static=None, dynamic=None, classify=None):
    """Wire all external calls for _run_dependency_phase with sensible defaults."""
    store: dict[str, Any] = {}
    monkeypatch.setattr(
        "workers.static_worker.store_artifact",
        lambda _s, _j, name, data=None, text_data=None: store.update({name: data or text_data}),
    )
    monkeypatch.setattr("workers.static_worker.get_artifact", lambda _s, _j, _name: None)
    monkeypatch.setattr(worker, "update_detail", lambda *_a, **_kw: None)
    monkeypatch.setattr(
        "workers.static_worker.find_dependencies",
        lambda addr, rpc_url, code_cache=None, chain_id=None: static or _static_deps(addr),
    )
    monkeypatch.setattr(
        "workers.static_worker.find_dynamic_dependencies",
        dynamic
        or (
            lambda addr, rpc_url=None, tx_limit=10, tx_hashes=None, proxy_address=None, code_cache=None, **kw: (
                _dynamic_deps(addr)
            )
        ),
    )
    monkeypatch.setattr(
        "workers.static_worker.classify_contracts",
        classify or (lambda tgt, deps, rpc, dynamic_edges=None, code_cache=None, **kw: _classifications(tgt)),
    )
    monkeypatch.setattr("workers.static_worker.enrich_dependency_metadata", lambda u, **kw: u)
    return store


# ===================================================================
# 1. Static worker: proxy_address wiring to find_dynamic_dependencies
# ===================================================================


def test_dep_phase_passes_proxy_address(monkeypatch, tmp_path):
    """For impl jobs, proxy_address from the job request propagates to
    find_dynamic_dependencies so transactions are fetched from the proxy."""
    from workers.static_worker import StaticWorker

    worker = StaticWorker()
    captured: list[dict] = []

    def capture_dynamic(address, rpc_url=None, tx_limit=10, tx_hashes=None, proxy_address=None, code_cache=None, **kw):
        captured.append({"address": address, "proxy_address": proxy_address})
        graph = [{"from": address, "to": DEP_A, "op": "CALL", "provenance": []}]
        return _dynamic_deps(address, deps=[DEP_A], graph=graph)

    job = _job(
        address=IMPL,
        name="Impl",
        request={"rpc_url": "https://rpc.example", "proxy_address": PROXY, "chain_id": 1},
    )
    _patch_dep_phase(monkeypatch, worker, dynamic=capture_dynamic)
    # Mock upgrade history to avoid Etherscan calls
    monkeypatch.setattr(
        "services.discovery.upgrade_history.build_upgrade_history",
        lambda _p, enrich=True, from_block=0: {
            "schema_version": "0.1",
            "target_address": IMPL,
            "proxies": {},
            "total_upgrades": 0,
        },
    )

    project_dir = tmp_path / "p"
    project_dir.mkdir()
    worker._run_dependency_phase(MagicMock(), job, project_dir, "Impl", IMPL)

    assert len(captured) == 1
    assert captured[0]["address"] == IMPL
    assert captured[0]["proxy_address"] == PROXY


# ===================================================================
# 2. Static worker: upgrade_history stored when proxies exist
# ===================================================================


def test_dep_phase_stores_upgrade_history(monkeypatch, tmp_path):
    """When build_upgrade_history finds proxies, the artifact is stored."""
    from workers.static_worker import StaticWorker

    worker = StaticWorker()
    store = _patch_dep_phase(
        monkeypatch,
        worker,
        static=_static_deps(TARGET, [DEP_A]),
        dynamic=lambda addr, **_kw: _dynamic_deps(addr, [DEP_A]),
    )
    fake_uh = {
        "schema_version": "0.1",
        "target_address": TARGET,
        "proxies": {DEP_A: {}},
        "total_upgrades": 2,
    }
    monkeypatch.setattr(
        "services.discovery.upgrade_history.build_upgrade_history",
        lambda _p, enrich=True, from_block=0, chain_id=1: fake_uh,
    )

    project_dir = tmp_path / "p"
    project_dir.mkdir()
    worker._run_dependency_phase(MagicMock(), _job(), project_dir, "TestContract", TARGET)

    assert "upgrade_history" in store
    assert store["upgrade_history"]["total_upgrades"] == 2


def test_dep_phase_skips_upgrade_history_when_no_proxies(monkeypatch, tmp_path):
    """When no proxies are found, upgrade_history artifact is not stored."""
    from workers.static_worker import StaticWorker

    worker = StaticWorker()
    store = _patch_dep_phase(
        monkeypatch,
        worker,
        static=_static_deps(TARGET, [DEP_A]),
        dynamic=lambda addr, **_kw: _dynamic_deps(addr, [DEP_A]),
    )
    monkeypatch.setattr(
        "services.discovery.upgrade_history.build_upgrade_history",
        lambda _p, enrich=True: {"schema_version": "0.1", "target_address": TARGET, "proxies": {}, "total_upgrades": 0},
    )

    project_dir = tmp_path / "p"
    project_dir.mkdir()
    worker._run_dependency_phase(MagicMock(), _job(), project_dir, "TestContract", TARGET)

    assert "upgrade_history" not in store
    assert "dependencies" in store


# ===================================================================
# 3. API: _merge_proxy_impl_entries + _display_name together
# ===================================================================


def test_merge_uses_impl_name_and_propagates_company():
    """Merged entry gets impl contract_name as display_name and inherits
    the proxy's company and rank_score."""
    from services.governance.proxies import _merge_proxy_impl_entries

    proxy_entry = {
        "run_name": "MyProxy",
        "job_id": "j1",
        "address": PROXY,
        "chain": "ethereum",
        "company": "TestCo",
        "parent_job_id": None,
        "rank_score": 0.8,
        "is_proxy": True,
        "proxy_type": "eip1967",
        "implementation_address": IMPL,
        "proxy_address": None,
        "contract_name": "TransparentUpgradeableProxy",
    }
    impl_entry = {
        "run_name": "MyProxy: (impl)",
        "job_id": "j2",
        "address": IMPL,
        "chain": "ethereum",
        "company": None,
        "parent_job_id": "j1",
        "rank_score": None,
        "is_proxy": False,
        "proxy_type": None,
        "implementation_address": None,
        "proxy_address": PROXY,
        "contract_name": "LiquidityPool",
    }

    # Partial test payloads: the merge reads via .get, full AnalysisListEntry not needed.
    merged = _merge_proxy_impl_entries([proxy_entry, impl_entry])  # pyright: ignore[reportArgumentType]
    assert len(merged) == 1
    # Merge sets display_name from impl's contract_name directly (no chain suffix)
    assert merged[0].get("display_name") == "LiquidityPool"
    assert merged[0]["company"] == "TestCo"
    assert merged[0]["rank_score"] == 0.8
    assert merged[0].get("proxy_address_display") == PROXY


def test_display_name_chain_suffix_and_generic_fallback():
    """_display_name appends chain, prefers display_name, and falls back
    to run_name for generic proxy contract names."""
    from services.governance.proxies import _display_name

    entry1 = {"contract_name": "Pool", "run_name": "x", "display_name": None, "chain": "base"}
    assert _display_name(entry1) == "Pool (base)"
    entry2 = {"contract_name": "ERC1967Proxy", "run_name": "Router", "display_name": None, "chain": None}
    assert _display_name(entry2) == "Router"
    entry3 = {"contract_name": "Proxy", "run_name": "r", "display_name": "Custom", "chain": None}
    assert _display_name(entry3) == "Custom"


def test_proxy_with_completed_impl_visible_after_merge():
    """A proxy entry whose impl child has completed should appear as
    a merged entry in the list (this is the normal end state)."""
    from services.governance.proxies import _merge_proxy_impl_entries

    proxy_entry = {
        "run_name": "eETH",
        "job_id": "j1",
        "address": "0x3333333333333333333333333333333333333333",
        "chain": "ethereum",
        "company": "etherfi",
        "parent_job_id": None,
        "rank_score": 0.9,
        "is_proxy": True,
        "proxy_type": "eip1967",
        "implementation_address": "0x4444444444444444444444444444444444444444",
        "proxy_address": None,
        "contract_name": "ERC1967Proxy",
    }
    impl_entry = {
        "run_name": "eETH: (impl)",
        "job_id": "j2",
        "address": "0x4444444444444444444444444444444444444444",
        "chain": "ethereum",
        "company": None,
        "parent_job_id": "j1",
        "rank_score": None,
        "is_proxy": False,
        "proxy_type": None,
        "implementation_address": None,
        "proxy_address": "0x3333333333333333333333333333333333333333",
        "contract_name": "EETH",
    }
    merged = _merge_proxy_impl_entries([proxy_entry, impl_entry])  # pyright: ignore[reportArgumentType]
    assert len(merged) == 1
    assert merged[0].get("display_name") == "EETH"
    assert merged[0].get("proxy_address_display") == "0x3333333333333333333333333333333333333333"


def test_orphan_impl_appears_in_merged_list():
    """An impl whose proxy_address is not in the list still appears."""
    from services.governance.proxies import _merge_proxy_impl_entries

    orphan = {
        "run_name": "Orphan",
        "job_id": "j1",
        "address": IMPL,
        "chain": None,
        "company": None,
        "parent_job_id": "jx",
        "rank_score": None,
        "is_proxy": False,
        "proxy_type": None,
        "implementation_address": None,
        "proxy_address": "0x9999999999999999999999999999999999999999",
        "contract_name": "Impl",
    }
    merged = _merge_proxy_impl_entries([orphan])  # pyright: ignore[reportArgumentType]
    assert len(merged) == 1


# ===================================================================
# 4. API detail: inlines upgrade_history and dependency_graph_viz
# ===================================================================


@patch("routers.deps.get_all_artifacts")
@patch("routers.deps.SessionLocal")
def test_detail_inlines_upgrade_history_and_graph_viz(mock_session_cls, mock_get_all_artifacts):
    from fastapi.testclient import TestClient

    import api

    client = TestClient(api.app)
    fake_job = _fake_api_job(name="proxy_run", address=TARGET)

    mock_session = MagicMock()
    mock_session.execute.return_value.scalar_one_or_none.return_value = fake_job
    _mock_session_ctx(mock_session_cls, mock_session)

    mock_get_all_artifacts.return_value = {
        "contract_analysis": {"subject": {"name": "Pool"}, "summary": {"control_model": "proxy"}},
        "upgrade_history": {"schema_version": "0.1", "proxies": {PROXY: {}}, "total_upgrades": 3},
        "dependency_graph_viz": {"nodes": [{"id": "addr:" + TARGET}], "edges": []},
        "dependencies": {"address": TARGET, "dependencies": {}},
    }

    resp = client.get("/api/analyses/proxy_run")
    assert resp.status_code == 200
    body = resp.json()
    assert body["upgrade_history"]["total_upgrades"] == 3
    assert len(body["dependency_graph_viz"]["nodes"]) == 1
    assert body["contract_name"] == "Pool"


# ===================================================================
# 5. Graph builder: label uses display_name for generic proxy names
# ===================================================================


def test_graph_label_prefers_caller_supplied_label():
    """Callers supply target_label explicitly; the graph uses it as the root label."""
    from services.discovery.dependency_graph_builder import build_dependency_visualization

    unified = {"address": TARGET, "dependencies": {DEP_A: {"type": "regular", "source": ["static"]}}}

    viz = build_dependency_visualization(unified, target_label="Rewards Router")
    target_node = next(n for n in viz["nodes"] if n["is_target"])
    assert target_node["label"] == "Rewards Router"


# ===================================================================
# 6. Full data flow: unified -> graph viz -> upgrade history
# ===================================================================


def test_full_data_flow_unified_through_graph_and_upgrade_history(monkeypatch, tmp_path):
    """Exercise the real build_unified_dependencies, build_dependency_visualization,
    and build_upgrade_history functions with mocks only at the network boundary,
    verifying the entire data chain."""
    from services.discovery.dependency_graph_builder import build_dependency_visualization
    from services.discovery.unified_dependencies import build_unified_dependencies
    from services.discovery.upgrade_history import build_upgrade_history

    static = _static_deps(TARGET, [DEP_A, DEP_B])
    dynamic = {
        **_dynamic_deps(TARGET, [DEP_A]),
        "dependency_graph": [
            {"from": TARGET, "to": DEP_A, "op": "CALL", "provenance": [{"tx_hash": "0xaa", "block_number": 100}]},
        ],
        "transactions_analyzed": [{"tx_hash": "0xaa", "block_number": 100, "method_selector": "0xdeadbeef"}],
    }
    cls = _classifications(
        TARGET,
        cls_map={
            DEP_A: {"address": DEP_A, "type": "proxy", "proxy_type": "eip1967", "implementation": IMPL},
            DEP_B: {"address": DEP_B, "type": "regular"},
            IMPL: {"address": IMPL, "type": "implementation", "proxies": [DEP_A]},
        },
        discovered=[IMPL],
    )

    # -- unified deps --
    unified = build_unified_dependencies(TARGET, static, dynamic, cls)
    assert DEP_A in unified["dependencies"]
    assert IMPL not in unified["dependencies"]  # nested under DEP_A
    assert unified["dependencies"][DEP_A]["implementation"]["address"] == IMPL

    # -- graph viz --
    viz = build_dependency_visualization(unified, target_label="TestContract")
    node_addrs = {n["address"] for n in viz["nodes"]}
    assert {TARGET, DEP_A, DEP_B, IMPL} <= node_addrs

    edge_ops = {(e["from"], e["to"], e["op"]) for e in viz["edges"]}
    assert (f"addr:{DEP_A}", f"addr:{IMPL}", "DELEGATES_TO") in edge_ops
    assert (f"addr:{TARGET}", f"addr:{DEP_A}", "CALL") in edge_ops
    assert any(e["op"] == "STATIC_REF" and e["to"] == f"addr:{DEP_B}" for e in viz["edges"])

    # -- upgrade history (mock Etherscan boundary) --
    # Upgrade history only runs for the target. DEP_A is a dependency proxy
    # and will get its own upgrade_history when it's analyzed as its own
    # target in a later job, so it should NOT appear here even though it's
    # classified as a proxy.
    monkeypatch.setattr("services.discovery.upgrade_history._fetch_logs_etherscan", lambda _a, _t, from_block=0: [])
    from utils import etherscan

    monkeypatch.setattr(etherscan, "get_contract_info", lambda _a: (None, {}))

    uh = build_upgrade_history(unified)
    assert DEP_A not in uh["proxies"]
    assert uh["proxies"] == {}
    assert uh["total_upgrades"] == 0


# ===================================================================
# 7. Discovery -> Static: artifact name contract between workers
# ===================================================================


def test_discovery_artifact_names_match_static_worker_reads():
    """The data that discovery stores must match what static reads.

    Discovery writes to the Contract table and stores source files via
    store_source_files.  Static reads from the Contract table via
    session.execute(select(Contract)...) and source files via
    get_source_files.  This test verifies both modules reference the
    same DB model (Contract) and source-file helpers.
    """
    import inspect

    import workers.discovery as disc
    import workers.static_worker as sw

    # Discovery writes to Contract table and stores source files
    disc_source = inspect.getsource(disc.DiscoveryWorker._process_address)
    assert "Contract(" in disc_source
    assert "store_source_files" in disc_source

    # Static reads from Contract table and source files
    sw_source = inspect.getsource(sw.StaticWorker.process)
    assert "Contract" in sw_source
    assert "get_source_files" in sw_source


# ===================================================================
# 8. Static -> Resolution: artifact name contract between workers
# ===================================================================


def test_static_artifact_names_match_resolution_worker_reads():
    """Static stores 'contract_analysis' and 'control_tracking_plan';
    Resolution reads them back."""
    import inspect

    import workers.resolution_worker as rw
    import workers.static_worker as sw

    # Static stores
    slither_source = inspect.getsource(sw.StaticWorker._run_analysis_phase)
    plan_source = inspect.getsource(sw.StaticWorker._run_tracking_plan_phase)
    assert '"contract_analysis"' in slither_source
    assert '"control_tracking_plan"' in plan_source

    # Resolution reads
    rw_source = inspect.getsource(rw.ResolutionWorker.process)
    assert '"control_tracking_plan"' in rw_source
    assert '"contract_analysis"' in rw_source


# ===================================================================
# 9. Resolution -> Policy: artifact name contract between workers
# ===================================================================


def test_resolution_artifact_names_match_policy_worker_reads():
    """Resolution stores 'control_snapshot' and 'resolved_control_graph';
    Policy reads them back."""
    import inspect

    import workers.policy_worker as pw
    import workers.resolution_worker as rw

    # Resolution stores
    rw_source = inspect.getsource(rw.ResolutionWorker.process)
    assert '"control_snapshot"' in rw_source
    assert '"resolved_control_graph"' in rw_source

    # Policy reads
    pw_source = inspect.getsource(pw.PolicyWorker.process)
    assert '"contract_analysis"' in pw_source
    assert '"control_snapshot"' in pw_source
    assert '"resolved_control_graph"' in pw_source


# ===================================================================
# 10. Policy: stores final artifacts that API detail endpoint inlines
# ===================================================================


def test_policy_stores_all_artifacts_that_api_detail_inlines():
    """Policy worker stores effective_permissions, principal_labels,
    principal_history, and resolved_control_graph. The API detail aggregator
    inlines each of these.
    Verify the names match between producer and consumer."""
    import inspect

    import workers.policy_worker as pw
    from services.aggregations import analysis_detail as detail_module

    pw_source = inspect.getsource(pw.PolicyWorker.process)

    # Policy stores these
    assert '"effective_permissions"' in pw_source
    assert '"principal_labels"' in pw_source
    assert '"principal_history"' in pw_source
    assert '"resolved_control_graph"' in pw_source

    # API detail aggregator inlines these
    detail_source = inspect.getsource(detail_module)
    assert '"effective_permissions"' in detail_source
    assert '"principal_labels"' in detail_source
    assert '"principal_history"' in detail_source
    assert '"resolved_control_graph"' in detail_source
    assert '"contract_analysis"' in detail_source
    assert '"control_snapshot"' in detail_source


# ===================================================================
# 11. API detail endpoint inlines all expected artifacts
# ===================================================================


@patch("routers.deps.get_all_artifacts")
@patch("routers.deps.SessionLocal")
def test_detail_inlines_all_pipeline_artifacts(mock_session_cls, mock_get_all_artifacts):
    """The API detail endpoint must inline effective_permissions,
    principal_labels, principal_history, control_snapshot, and resolved_control_graph
    alongside the already-tested contract_analysis and dependencies."""
    from fastapi.testclient import TestClient

    import api

    client = TestClient(api.app)
    fake_job = _fake_api_job(name="full_run", address=TARGET)

    mock_session = MagicMock()

    # Build mock relational objects for effective_permissions and principal_labels.
    # The API now reads these from the EffectiveFunction / PrincipalLabel tables,
    # not from artifacts.
    fake_contract_row = MagicMock()
    fake_contract_row.id = "contract-1"
    fake_contract_row.contract_name = "Vault"
    fake_contract_row.address = TARGET
    fake_contract_row.is_proxy = False
    fake_contract_row.implementation = None
    fake_contract_row.summary = None

    fake_ef = MagicMock()
    fake_ef.id = "ef-1"
    fake_ef.abi_signature = "pause()"
    fake_ef.function_name = "pause"
    fake_ef.selector = "0x12"
    fake_ef.effect_labels = []
    fake_ef.action_summary = None
    fake_ef.authority_public = False

    fake_fp = MagicMock()
    fake_fp.address = "0xaa"
    fake_fp.resolved_type = "admin"
    fake_fp.origin = None
    fake_fp.details = {}

    fake_pl = MagicMock()
    fake_pl.address = "0xaa"
    fake_pl.label = "admin"
    fake_pl.resolved_type = "eoa"

    # Route session.execute calls based on what the API queries
    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        stmt_str = str(stmt)
        # api.py now iterates Result.scalars() directly in the batched
        # prefetch paths, so MagicMock needs an explicit __iter__.
        items: list = []
        if call_count["n"] == 1:
            # First call: select(Job) to find job by name
            result.scalar_one_or_none.return_value = fake_job
        elif "contract" in stmt_str.lower() and "job_id" in stmt_str.lower() and call_count["n"] == 2:
            # Second call: select(Contract) for contract_row
            result.scalar_one_or_none.return_value = fake_contract_row
        elif "effective" in stmt_str.lower():
            items = [fake_ef]
        elif "function_principal" in stmt_str.lower():
            items = [fake_fp]
        elif "principal_label" in stmt_str.lower():
            items = [fake_pl]
        else:
            result.scalar_one_or_none.return_value = None
        result.scalars.return_value.all.return_value = items
        result.scalars.return_value.__iter__ = lambda s: iter(items)
        return result

    mock_session.execute.side_effect = route_execute
    mock_session.get.return_value = None
    _mock_session_ctx(mock_session_cls, mock_session)

    mock_get_all_artifacts.return_value = {
        "contract_analysis": {"subject": {"name": "Vault"}, "summary": {"control_model": "authority"}},
        "control_snapshot": {"schema_version": "0.1", "controller_values": {"state_variable:owner": {"value": "0xaa"}}},
        "resolved_control_graph": {"nodes": [{"id": "a", "address": TARGET}], "edges": []},
        "dependencies": {"address": TARGET, "dependencies": {}},
        "principal_history": {
            "schema_version": "principal_history.v1",
            "contract_address": TARGET,
            "status": "ok",
            "function_permissions": [{"function": "pause()", "principal": "0xaa"}],
        },
    }

    resp = client.get("/api/analyses/full_run")
    assert resp.status_code == 200
    body = resp.json()

    # JSON artifacts inlined from all_artifacts
    assert body["contract_analysis"]["summary"]["control_model"] == "authority"
    assert "state_variable:owner" in body["control_snapshot"]["controller_values"]
    assert len(body["resolved_control_graph"]["nodes"]) == 1
    assert body["dependencies"]["address"] == TARGET
    assert body["principal_history"]["function_permissions"][0]["principal"] == "0xaa"

    # effective_permissions built from EffectiveFunction + FunctionPrincipal tables
    assert body["effective_permissions"]["functions"][0]["function"] == "pause()"

    # principal_labels built from PrincipalLabel table
    assert body["principal_labels"]["principals"][0]["label"] == "admin"

    # Subject info should be extracted
    assert body["contract_name"] == "Vault"


# ===================================================================
# 12. API analyses list serves contract_flags stored by static worker
# ===================================================================


@patch("routers.deps.SessionLocal")
def test_analyses_list_reads_contract_flags_from_static_worker(mock_session_cls):
    """The analyses list endpoint reads 'contract_flags' artifact that
    static worker stores during _resolve_proxy. Verify the is_proxy
    and proxy_type fields propagate into the merged entry.

    _merge_proxy_impl_entries hides proxy entries whose impl child job
    hasn't completed, so we include both the proxy and impl jobs."""
    from types import SimpleNamespace

    from fastapi.testclient import TestClient

    import api

    client = TestClient(api.app)
    proxy_job = _fake_api_job(name="proxy_test", address=PROXY, is_proxy=True)
    impl_job = _fake_api_job(
        name="proxy_test: (impl)",
        address=IMPL,
        request={"address": IMPL, "proxy_address": PROXY, "parent_job_id": str(proxy_job.id)},
    )

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    from db.models import JobStatus

    impl_job.status = JobStatus.completed
    proxy_job.status = JobStatus.completed

    # proxy_type / implementation now come from the Contract row, not
    # the contract_flags artifact (which the listing no longer fetches).
    proxy_contract_row = SimpleNamespace(
        address=PROXY,
        chain=None,
        rank_score=None,
        contract_name="MyProxy",
        is_proxy=True,
        proxy_type="eip1967",
        implementation=IMPL,
    )

    artifacts = [
        SimpleNamespace(
            job_id=proxy_job.id,
            name="contract_analysis",
            storage_key=None,
            data={"subject": {"name": "MyProxy"}, "summary": {"control_model": "proxy"}},
            text_data=None,
            content_type=None,
        ),
        SimpleNamespace(
            job_id=impl_job.id,
            name="contract_analysis",
            storage_key=None,
            data={"subject": {"name": "VaultImpl"}, "summary": {"control_model": "authority"}},
            text_data=None,
            content_type=None,
        ),
    ]

    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        if call_count["n"] == 1:
            result.scalars.return_value.all.return_value = [proxy_job, impl_job]
        elif call_count["n"] == 2:
            result.scalars.return_value = iter([proxy_contract_row])
        elif call_count["n"] == 3:
            result.scalars.return_value = iter(artifacts)
        else:
            result.scalars.return_value.all.return_value = []
            result.scalar_one_or_none.return_value = None
        return result

    mock_session.execute.side_effect = route_execute

    resp = client.get("/api/analyses")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) >= 1
    merged = body[0]
    # The merged entry carries proxy info via proxy_address_display and
    # proxy_type_display (not is_proxy — that comes from the impl base).
    assert merged["proxy_address_display"] == PROXY
    assert merged["proxy_type_display"] == "eip1967"


# ===================================================================
# 13. Resolution worker: proxy_address overrides tracking plan address
# ===================================================================


def test_resolution_worker_rewrites_address_for_impl_jobs(monkeypatch):
    """When a job has proxy_address in its request, the resolution worker
    should override contract_address in the tracking plan and subject.address
    in the contract_analysis so state is read from the proxy, not the impl."""
    from workers.resolution_worker import ResolutionWorker

    worker = ResolutionWorker()
    session = MagicMock()

    job = _job(
        address=IMPL,
        name="Impl",
        request={"rpc_url": "https://rpc.example", "proxy_address": PROXY, "chain_id": 1},
    )

    # What static worker stored
    tracking_plan = {
        "schema_version": "0.1",
        "contract_address": IMPL,
        "contract_name": "VaultImpl",
        "tracking_strategy": "event_first_with_polling_fallback",
        "tracked_controllers": [],
    }
    contract_analysis = {
        "subject": {"address": IMPL, "name": "VaultImpl"},
        "semantic_control": {"semantic_functions": []},
    }

    artifacts = {
        "control_tracking_plan": tracking_plan,
        "contract_analysis": contract_analysis,
    }

    monkeypatch.setattr(
        "workers.resolution_worker.get_artifact",
        lambda _session, _job_id, name: artifacts.get(name),
    )

    # Capture what build_control_snapshot receives
    captured_plans: list[dict] = []
    captured_analyses: list[dict] = []

    def fake_build_snapshot(plan, _rpc_url, **_kw):
        captured_plans.append(plan)
        return {
            "schema_version": "0.1",
            "contract_address": plan["contract_address"],
            "contract_name": "VaultImpl",
            "block_number": 100,
            "controller_values": {},
        }

    stored_artifacts: dict[str, Any] = {}
    monkeypatch.setattr("workers.resolution_worker.build_control_snapshot", fake_build_snapshot)
    monkeypatch.setattr(
        "workers.resolution_worker.store_artifact",
        lambda _s, _j, name, data=None, text_data=None: stored_artifacts.update({name: data or text_data}),
    )
    monkeypatch.setattr(worker, "update_detail", lambda *_a, **_kw: None)

    # Mock resolve_control_graph to capture the analysis it receives.
    # Accept **_kw so the mock survives signature growth in the production
    # function (classify_cache, initial_graph, nested_artifacts_override
    # have all been threaded through during Phase A — pinning each kwarg
    # name here would create a brittle test-vs-prod coupling).
    def fake_resolve_graph(*, root_artifacts, rpc_url, max_depth, workspace_prefix, **_kw):
        captured_analyses.append(root_artifacts["analysis"])
        return {"nodes": [], "edges": []}, {}

    monkeypatch.setattr("workers.resolution_worker.resolve_control_graph", fake_resolve_graph)

    worker.process(session, job)

    # The tracking plan should have proxy address, not impl
    assert captured_plans[0]["contract_address"] == PROXY

    # The analysis written to disk should have proxy address
    assert captured_analyses[0]["subject"]["address"] == PROXY

    # Artifacts should be stored
    assert "control_snapshot" in stored_artifacts
    assert "resolved_control_graph" in stored_artifacts


# ===================================================================
# 14. Tracking plan construction preserves controller_tracking fields
# ===================================================================


def test_tracking_plan_preserves_controller_ids_and_read_specs():
    """The tracking plan builder must carry forward controller_id, read_spec,
    and associated_events from contract_analysis.controller_tracking. These
    are consumed by build_control_snapshot in the resolution stage."""
    from services.resolution.tracking_plan import build_control_tracking_plan

    analysis = {
        "subject": {"address": "0x1111111111111111111111111111111111111111", "name": "Vault"},
        "controller_tracking": [
            {
                "controller_id": "state_variable:owner",
                "label": "owner",
                "source": "owner",
                "kind": "state_variable",
                "read_spec": {"strategy": "getter_call", "target": "owner"},
                "tracking_mode": "event_plus_state",
                "associated_events": [
                    {
                        "name": "OwnershipTransferred",
                        "signature": "OwnershipTransferred(address,address)",
                        "topic0": "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0",
                        "inputs": [
                            {"name": "user", "type": "address", "indexed": True},
                            {"name": "newOwner", "type": "address", "indexed": True},
                        ],
                    }
                ],
                "writer_functions": [{"function": "transferOwnership(address)"}],
                "polling_sources": ["owner"],
                "notes": [],
            },
            {
                "controller_id": "external_contract:authority",
                "label": "authority",
                "source": "authority",
                "kind": "external_contract",
                "read_spec": {"strategy": "getter_call", "target": "authority"},
                "tracking_mode": "event_plus_state",
                "associated_events": [
                    {
                        "name": "AuthorityUpdated",
                        "signature": "AuthorityUpdated(address,address)",
                        "topic0": "0xa3396fd7f6e0a21b50e5089d2da70d5ac0a3bbbd1f617a93f134b76389980198",
                        "inputs": [
                            {"name": "user", "type": "address", "indexed": True},
                            {"name": "newAuthority", "type": "address", "indexed": True},
                        ],
                    }
                ],
                "writer_functions": [{"function": "setAuthority(address)"}],
                "polling_sources": ["authority"],
                "notes": [],
            },
        ],
    }

    plan = build_control_tracking_plan(analysis)  # pyright: ignore[reportArgumentType]

    assert plan["contract_address"] == "0x1111111111111111111111111111111111111111"
    assert plan["contract_name"] == "Vault"
    assert len(plan["tracked_controllers"]) == 2

    # Controller IDs carry through (resolution worker uses these as keys)
    ids = {tc["controller_id"] for tc in plan["tracked_controllers"]}
    assert ids == {"state_variable:owner", "external_contract:authority"}

    # Read specs carry through (build_control_snapshot uses these)
    for tc in plan["tracked_controllers"]:
        assert tc["read_spec"] is not None
        assert tc["read_spec"]["strategy"] == "getter_call"

    # Event watches carry through (event-first tracking)
    owner = next(tc for tc in plan["tracked_controllers"] if tc["label"] == "owner")
    assert owner["event_watch"] is not None
    assert len(owner["event_watch"]["events"]) == 1
    assert owner["event_watch"]["events"][0]["name"] == "OwnershipTransferred"


# ===================================================================
# 16. Discovery company mode writes contracts and advances to selection
# ===================================================================


def test_discovery_company_mode_advances_to_selection(monkeypatch):
    """DiscoveryWorker company mode now writes discovered contracts to the
    ``contracts`` table and hands off to the ``selection`` stage instead of
    creating analysis child jobs inline. Child creation happens later in
    the SelectionWorker, once DApp/DefiLlama siblings have also landed."""
    from db.models import JobStage
    from workers.base import JobHandledDirectly
    from workers.discovery import DiscoveryWorker

    worker = DiscoveryWorker()
    session = MagicMock()

    job = SimpleNamespace(
        id="parent-1",
        address=None,
        company="TestProtocol",
        name=None,
        protocol_id=None,
        request={"company": "TestProtocol", "chain": "ethereum", "rpc_url": "https://rpc.example", "analyze_limit": 2},
    )
    session.commit = MagicMock()
    session.flush = MagicMock()
    session.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    session.execute = MagicMock(return_value=mock_result)

    stored_artifacts: dict[str, Any] = {}
    advance_calls: list[tuple] = []

    monkeypatch.setattr(
        "workers.discovery.store_artifact",
        lambda _s, _j, name, data=None, text_data=None: stored_artifacts.update({name: data or text_data}),
    )

    def fail_create_job(*_a, **_kw):
        raise AssertionError("create_job should not be called from DiscoveryWorker company mode")

    monkeypatch.setattr("workers.discovery.create_job", fail_create_job)
    monkeypatch.setattr(
        "workers.discovery.advance_job",
        lambda _s, job_id, next_stage, detail="": advance_calls.append((job_id, next_stage, detail)),
    )
    monkeypatch.setattr(worker, "update_detail", lambda *_a, **_kw: None)

    monkeypatch.setattr(
        "workers.discovery.get_artifact",
        lambda _s, _j, _name: None,
    )
    monkeypatch.setattr(
        "workers.discovery.find_previous_company_inventory",
        lambda _s, _company, exclude_job_id=None, chain=None: None,
    )
    _fake_inventory = {
        "contracts": [
            {"address": "0xaaaa" + "a" * 36, "name": "TokenA", "chains": ["ethereum"], "confidence": 0.9},
            {"address": "0xbbbb" + "b" * 36, "name": "TokenB", "chains": ["ethereum"], "confidence": 0.8},
        ],
        "official_domain": "testprotocol.io",
    }
    monkeypatch.setattr(
        "services.discovery.run_discovery.run_discovery",
        lambda *_a, **_kw: {
            "audits": {"reports": [], "errors": [], "notes": []},
            "addresses": _fake_inventory,
            "meta": {"protocol": "TestProtocol", "estimated_cost_usd": 0.0, "search_calls": 0, "research_calls": 0},
        },
    )
    monkeypatch.setattr("workers.discovery.search_protocol_inventory", lambda *_a, **_kw: _fake_inventory)
    monkeypatch.setattr(worker, "_spawn_parallel_discovery", lambda *_a, **_kw: None)

    try:
        worker.process(session, job)  # pyright: ignore[reportArgumentType]
    except JobHandledDirectly:
        pass  # expected hand-off signal

    # Advance to the selection stage instead of queueing children here
    assert len(advance_calls) == 1
    job_id, next_stage, _detail = advance_calls[0]
    assert job_id == "parent-1"
    assert next_stage == JobStage.selection

    # discovery_summary now reports only what was discovered; ranking/queueing
    # runs later in SelectionWorker
    assert "discovery_summary" in stored_artifacts
    summary = stored_artifacts["discovery_summary"]
    assert summary["mode"] == "company"
    assert summary["company"] == "TestProtocol"
    assert summary["discovered_count"] == 2
    assert "analyzed_count" not in summary
    assert "child_jobs" not in summary

    assert "contract_inventory" in stored_artifacts


def test_discovery_reads_and_writes_protocol_declared_chains(monkeypatch):
    """Evidence-based membership (invariant 3): company discovery READS the
    protocol's declared chain set (requested chain + prior ``Protocol.chains``)
    to narrow the probe, and WRITES it back with the chains discovered contracts
    were confirmed on — excluding candidate-only hits."""
    from workers.base import JobHandledDirectly
    from workers.discovery import DiscoveryWorker

    worker = DiscoveryWorker()
    session = MagicMock()
    session.commit = MagicMock()

    job = SimpleNamespace(
        id="parent-2",
        address=None,
        company="TestProtocol",
        name=None,
        protocol_id=None,
        request={"company": "TestProtocol", "chain": "ethereum"},
    )
    # A prior run recorded this protocol on base — discovery must read it back.
    prev_job = SimpleNamespace(id="prev-1", protocol_id=7)
    prev_protocol = SimpleNamespace(id=7, chains=["base"])
    protocol_row = SimpleNamespace(id=7, chains=["base"])

    monkeypatch.setattr(
        "workers.discovery.find_previous_company_inventory",
        lambda _s, _c, exclude_job_id=None, chain=None: prev_job,
    )
    session.get = MagicMock(return_value=prev_protocol)
    monkeypatch.setattr("workers.discovery.get_artifact", lambda _s, _j, _n: None)
    monkeypatch.setattr("workers.discovery.get_or_create_protocol", lambda *_a, **_kw: protocol_row)
    monkeypatch.setattr("workers.discovery.resolve_protocol", lambda _c: {})
    monkeypatch.setattr("workers.discovery.pick_family_slug", lambda _r: None)
    monkeypatch.setattr("workers.discovery.store_artifact", lambda *_a, **_kw: None)
    monkeypatch.setattr("workers.discovery.advance_job", lambda *_a, **_kw: None)
    monkeypatch.setattr("workers.discovery.bulk_upsert_discovered_contracts", lambda *_a, **_kw: None)
    monkeypatch.setattr("workers.discovery._sync_audit_reports_to_db", lambda *_a, **_kw: None)
    monkeypatch.setattr(worker, "_spawn_parallel_discovery", lambda *_a, **_kw: None)
    monkeypatch.setattr(worker, "update_detail", lambda *_a, **_kw: None)

    captured: dict[str, Any] = {}

    def fake_run_discovery(company, *, official_domain=None, chain=None, declared_chains=None):
        captured["declared_chains"] = declared_chains
        return {
            "audits": {"reports": [], "errors": [], "notes": []},
            "addresses": {
                "contracts": [
                    {"address": "0x" + "a" * 40, "name": "Vault", "chains": ["ethereum"]},
                    # A candidate-only hit — must NOT feed the declared set.
                    {
                        "address": "0x" + "c" * 40,
                        "name": "Ghost",
                        "chains": ["unknown"],
                        "chain_candidates": ["optimism"],
                    },
                ],
                "official_domain": "x.io",
            },
            "meta": {},
        }

    monkeypatch.setattr("services.discovery.run_discovery.run_discovery", fake_run_discovery)

    try:
        worker.process(session, job)  # pyright: ignore[reportArgumentType]
    except JobHandledDirectly:
        pass

    # READ: requested chain + prior Protocol.chains both narrow the probe.
    assert captured["declared_chains"] == ["ethereum", "base"]
    # WRITE: declared set grows to include the confirmed chain, never the
    # candidate (optimism carries no corroborating evidence).
    assert protocol_row.chains == ["base", "ethereum"]


# ===================================================================
# 17. Static worker: process method reads discovery artifacts correctly
# ===================================================================


def test_static_worker_reads_discovery_artifacts(monkeypatch):
    """StaticWorker.process reads contract metadata from the Contract table
    and source files from get_source_files. Verify it handles the expected
    data shapes and passes them to _scaffold_project correctly."""
    from workers.static_worker import StaticWorker

    worker = StaticWorker()
    session = MagicMock()

    job = _job(name="TestContract")

    # Mock what discovery stored
    sources = {"src/Test.sol": "pragma solidity ^0.8.19;\ncontract Test {}"}

    monkeypatch.setattr("workers.static_worker.get_source_files", lambda _s, _j: sources)

    # Mock the Contract table row that discovery now writes
    contract_row = SimpleNamespace(
        address=TARGET,
        contract_name="Test",
        compiler_version="v0.8.19",
        language="solidity",
        evm_version="shanghai",
        optimization=True,
        optimization_runs=200,
        source_format="flat",
        source_file_count=1,
        remappings=[],
        is_proxy=False,
        # The fetch's verification fact, which ``process`` carries into
        # ``contract_meta.json`` for the static pipeline to publish.
        source_verified=True,
    )
    session.execute.return_value.scalar_one_or_none.return_value = contract_row
    session.refresh = MagicMock()

    # Capture calls to worker phases
    scaffold_args: list[tuple] = []
    monkeypatch.setattr(
        worker,
        "_scaffold_project",
        lambda project_dir, src, m, bs, rm: scaffold_args.append((src, m, bs, rm)),
    )
    monkeypatch.setattr(worker, "_resolve_proxy", lambda *_a, **_kw: None)
    monkeypatch.setattr(worker, "_run_dependency_phase", lambda *_a, **_kw: None)
    monkeypatch.setattr(worker, "_run_analysis_phase", lambda *_a, **_kw: True)
    monkeypatch.setattr(worker, "_run_tracking_plan_phase", lambda *_a, **_kw: None)
    monkeypatch.setattr(worker, "update_detail", lambda *_a, **_kw: None)

    worker.process(session, job)

    assert len(scaffold_args) == 1
    passed_sources, passed_meta, passed_build, passed_remap = scaffold_args[0]
    assert passed_sources == sources
    assert passed_meta["contract_name"] == "Test"
    assert passed_build["evm_version"] == "shanghai"
    assert passed_remap == []


# ===================================================================
# 18. Static worker: _scaffold_project writes foundry.toml and sources
# ===================================================================


def test_scaffold_project_writes_expected_files(tmp_path):
    """_scaffold_project must write foundry.toml, source files, remappings,
    and contract_meta.json. These files must be present for Slither and
    contract analysis to function."""
    from workers.static_worker import StaticWorker

    worker = StaticWorker()
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    sources = {
        "src/Vault.sol": "pragma solidity ^0.8.24;\ncontract Vault { address owner; }",
        "lib/openzeppelin/Ownable.sol": "pragma solidity ^0.8.24;\ncontract Ownable {}",
    }
    meta = {"address": TARGET, "contract_name": "Vault"}
    build_settings = {"evm_version": "shanghai", "optimization_used": True, "runs": 200}
    remappings = ["@openzeppelin/=lib/openzeppelin/"]

    worker._scaffold_project(project_dir, sources, meta, build_settings, remappings)

    # foundry.toml must exist with src dir and solc version
    foundry_toml = (project_dir / "foundry.toml").read_text()
    assert 'src = "src"' in foundry_toml
    assert "solc_version" in foundry_toml

    # Source files must be written
    assert (project_dir / "src" / "Vault.sol").exists()
    assert (project_dir / "lib" / "openzeppelin" / "Ownable.sol").exists()

    # Remappings must be written (since lib/openzeppelin/ has files)
    assert (project_dir / "remappings.txt").exists()

    # contract_meta.json must be written
    meta_data = json.loads((project_dir / "contract_meta.json").read_text())
    assert meta_data["contract_name"] == "Vault"


# ===================================================================
# 19. API artifact endpoint strips .json extension for lookup
# ===================================================================


@patch("routers.deps.get_artifact")
@patch("routers.deps.SessionLocal")
def test_artifact_endpoint_strips_json_extension(mock_session_cls, mock_get_artifact):
    """The artifact endpoint should strip .json and .txt extensions when
    looking up artifacts, since workers store artifacts without extensions
    but the frontend requests them with extensions."""
    from fastapi.testclient import TestClient

    import api
    from routers import deps

    client = TestClient(api.app)
    fake_job = _fake_api_job(name="test_run")

    mock_session = MagicMock()
    mock_session.execute.return_value.scalar_one_or_none.return_value = fake_job
    _mock_session_ctx(mock_session_cls, mock_session)

    call_names: list[str] = []

    def _get_artifact(_session, _job_id, name):
        call_names.append(name)
        if name == "effective_permissions":
            return {"functions": []}
        return None

    mock_get_artifact.side_effect = _get_artifact

    resp = client.get(
        "/api/analyses/test_run/artifact/effective_permissions.json",
        headers={"X-PSAT-Admin-Key": deps.ADMIN_KEY or ""},
    )
    assert resp.status_code == 200
    # First call should be with stripped name
    assert call_names[0] == "effective_permissions"


# ===================================================================
# 20. Static worker: dependency phase failures route through record_degraded
# ===================================================================


def test_dep_phase_records_degraded_on_failure(monkeypatch, tmp_path):
    """When dependency discovery sub-phases fail, the worker calls
    ``record_degraded(...)`` for each one. ``BaseWorker._execute_job``
    drains the per-job accumulator into the ``stage_errors`` artifact;
    this test pins the accumulator-write step in isolation.

    Replaces the old ``dependency_errors`` artifact assertion: that
    artifact is gone, and the same information now lives in the unified
    ``stage_errors`` schema written by ``BaseWorker``.
    """
    from workers.static_worker import StaticWorker

    worker = StaticWorker()
    store: dict[str, Any] = {}

    monkeypatch.setattr(
        "workers.static_worker.store_artifact",
        lambda _s, _j, name, data=None, text_data=None: store.update({name: data or text_data}),
    )
    monkeypatch.setattr("workers.static_worker.get_artifact", lambda _s, _j, _name: None)
    monkeypatch.setattr(worker, "update_detail", lambda *_a, **_kw: None)
    monkeypatch.setattr(
        "workers.static_worker.find_dependencies",
        lambda addr, rpc_url, code_cache=None, chain_id=None: (_ for _ in ()).throw(RuntimeError("static dep error")),
    )
    monkeypatch.setattr(
        "workers.static_worker.find_dynamic_dependencies",
        lambda addr, rpc_url=None, tx_limit=10, tx_hashes=None, proxy_address=None, code_cache=None, **kw: (
            _ for _ in ()
        ).throw(RuntimeError("dynamic dep error")),
    )

    from utils.logging import bind_trace_context, degraded_errors_var

    accumulator: list = []
    token = degraded_errors_var.set(accumulator)
    try:
        with bind_trace_context(
            stage="static",
            job_id="job-1",
            worker_id="test-worker",
        ):
            project_dir = tmp_path / "p"
            project_dir.mkdir()
            worker._run_dependency_phase(MagicMock(), _job(), project_dir, "Test", TARGET)
    finally:
        degraded_errors_var.reset(token)

    # Old artifact name is gone — the dependency_errors slot must NOT be written anywhere.
    assert "dependency_errors" not in store
    # Both static + dynamic sub-phase failures are now degraded entries on the accumulator.
    phases = {entry.phase: entry for entry in accumulator}
    assert "dependency_static" in phases
    assert "dependency_dynamic" in phases
    assert phases["dependency_static"].severity == "degraded"
    assert "static dep error" in phases["dependency_static"].message
    assert "dynamic dep error" in phases["dependency_dynamic"].message


# ===================================================================
# 21. Static worker: proxy jobs skip analysis and complete directly
# ===================================================================


def test_static_worker_proxy_skips_analysis_and_completes(monkeypatch):
    """When the static worker detects a proxy contract, it should skip
    Slither/analysis/tracking_plan, call complete_job, and raise
    JobHandledDirectly.  This test exercises the actual process() method
    to catch import errors and wiring bugs."""
    from workers.base import JobHandledDirectly
    from workers.static_worker import StaticWorker

    worker = StaticWorker()
    session = MagicMock()

    job = _job(name="MyProxy")

    sources = {"src/Proxy.sol": "pragma solidity ^0.8.19;\ncontract Proxy {}"}

    # Mock DB reads
    monkeypatch.setattr("workers.static_worker.get_source_files", lambda _s, _j: sources)

    # Mock the Contract table row — after _resolve_proxy runs and session.refresh
    # is called, is_proxy should be True
    contract_row = SimpleNamespace(
        address=TARGET,
        contract_name="Proxy",
        compiler_version="v0.8.19",
        language="solidity",
        evm_version="shanghai",
        optimization=True,
        optimization_runs=200,
        source_format="flat",
        source_file_count=1,
        remappings=[],
        is_proxy=True,
        # The fetch's verification fact, which ``process`` carries into
        # ``contract_meta.json`` for the static pipeline to publish.
        source_verified=True,
    )
    session.execute.return_value.scalar_one_or_none.return_value = contract_row
    session.refresh = MagicMock()

    # Mock external calls
    monkeypatch.setattr(worker, "_resolve_proxy", lambda *_a, **_kw: None)
    monkeypatch.setattr(worker, "_run_dependency_phase", lambda *_a, **_kw: None)
    monkeypatch.setattr(worker, "update_detail", lambda *_a, **_kw: None)

    completed = []
    monkeypatch.setattr("db.queue.complete_job", lambda _s, _j, detail="": completed.append(True))

    # Analysis/tracking-plan should NOT be called for a proxy parent
    # (proxies short-circuit to spawn an impl child job).
    slither_called = []
    monkeypatch.setattr(worker, "_run_analysis_phase", lambda *_a, **_kw: slither_called.append(True) or True)
    monkeypatch.setattr(worker, "_run_tracking_plan_phase", lambda *_a, **_kw: slither_called.append(True))

    try:
        worker.process(session, job)
        assert False, "Expected JobHandledDirectly"
    except JobHandledDirectly:
        pass

    assert len(completed) == 1, "complete_job should have been called"
    assert len(slither_called) == 0, "Slither/analysis should NOT run for proxy contracts"


# ===================================================================
# 22. Pipeline stage sequence: stage/next_stage chain is connected
# ===================================================================


def test_worker_stage_chain_is_complete(monkeypatch):
    """The pipeline stage chain must connect end to end so no job gets stuck.
    ``PolicyWorker.next_stage`` is flag-dynamic (``PSAT_EFFECTS_STAGE`` gates the
    policy->effects transition itself): off -> straight to coverage, on ->
    through the effects stage."""
    from db.models import JobStage
    from workers.coverage_worker import CoverageWorker
    from workers.discovery import DiscoveryWorker
    from workers.effects_worker import EffectsWorker
    from workers.policy_worker import PolicyWorker
    from workers.resolution_worker import ResolutionWorker
    from workers.static_worker import StaticWorker

    # Static edges (flag-independent).
    assert DiscoveryWorker.stage == JobStage.discovery
    assert DiscoveryWorker.next_stage == JobStage.static

    assert StaticWorker.stage == JobStage.static
    assert StaticWorker.next_stage == JobStage.resolution

    assert ResolutionWorker.stage == JobStage.resolution
    assert ResolutionWorker.next_stage == JobStage.policy

    assert PolicyWorker.stage == JobStage.policy

    assert EffectsWorker.stage == JobStage.effects
    assert EffectsWorker.next_stage == JobStage.coverage

    assert CoverageWorker.stage == JobStage.coverage
    assert CoverageWorker.next_stage == JobStage.done

    # Flag OFF: policy advances straight to coverage; effects is bypassed.
    monkeypatch.delenv("PSAT_EFFECTS_STAGE", raising=False)
    assert PolicyWorker().next_stage == JobStage.coverage

    # Flag ON: policy -> effects -> coverage; the inserted stage keeps the chain
    # connected (no parked jobs).
    monkeypatch.setenv("PSAT_EFFECTS_STAGE", "1")
    assert PolicyWorker().next_stage == JobStage.effects
    assert EffectsWorker.next_stage == CoverageWorker.stage


# ===================================================================
# 22. Policy worker reads all three required artifacts
# ===================================================================


def test_policy_worker_fails_cleanly_on_missing_artifacts(monkeypatch):
    """Policy worker should raise RuntimeError if contract_analysis or
    control_snapshot are missing. These are produced by the static and
    resolution workers respectively."""
    from workers.policy_worker import PolicyWorker

    worker = PolicyWorker()
    session = MagicMock()
    job = _job(request={"rpc_url": "https://rpc.example", "chain_id": 1})

    # Missing contract_analysis
    monkeypatch.setattr(
        "workers.policy_worker.get_artifact",
        lambda _s, _j, name: None,
    )

    import pytest

    with pytest.raises(RuntimeError, match="contract_analysis"):
        worker.process(session, job)

    # contract_analysis present but control_snapshot missing
    monkeypatch.setattr(
        "workers.policy_worker.get_artifact",
        lambda _s, _j, name: {"subject": {"address": TARGET, "name": "T"}} if name == "contract_analysis" else None,
    )

    with pytest.raises(RuntimeError, match="control_snapshot"):
        worker.process(session, job)


# ===================================================================
# 23. Resolution worker fails cleanly on missing artifacts
# ===================================================================


def test_resolution_worker_fails_on_missing_artifacts(monkeypatch):
    """Resolution worker should raise RuntimeError if control_tracking_plan
    or contract_analysis are missing from the DB."""
    from workers.resolution_worker import ResolutionWorker

    worker = ResolutionWorker()
    session = MagicMock()
    job = _job(request={"rpc_url": "https://rpc.example", "chain_id": 1})

    import pytest

    # Missing tracking plan
    monkeypatch.setattr(
        "workers.resolution_worker.get_artifact",
        lambda _s, _j, name: None,
    )
    with pytest.raises(RuntimeError, match="control_tracking_plan"):
        worker.process(session, job)

    # tracking plan present but contract_analysis missing
    monkeypatch.setattr(
        "workers.resolution_worker.get_artifact",
        lambda _s, _j, name: (
            {"schema_version": "0.1", "tracked_controllers": []} if name == "control_tracking_plan" else None
        ),
    )
    with pytest.raises(RuntimeError, match="contract_analysis"):
        worker.process(session, job)
