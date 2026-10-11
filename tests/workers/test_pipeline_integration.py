"""Cross-module stage handoffs, API merge/detail endpoints and impl-job proxy_address overrides, with no live
services.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from tests.support.balance_stubs import page, pinned_native_unavailable

pytestmark = pytest.mark.usefixtures("_stub_rpc_bytecode", "_stub_defillama_protocols", "_stub_classifier_rpc")


@pytest.fixture(autouse=True)
def _stub_etherscan_balances(monkeypatch):
    """These tests assert address handoff, not balances; the pinned native read is a separate wire stubbed
    unavailable.
    """
    monkeypatch.setattr("services.clients.etherscan.get_eth_balance", lambda addr, *a, **k: 0)
    monkeypatch.setattr("services.clients.etherscan.get_native_price", lambda *a, **k: 0.0)
    monkeypatch.setattr("services.clients.etherscan.get_token_balances_page", lambda addr, *a, **k: page([]))
    pinned_native_unavailable(monkeypatch)


TARGET = "0x1111111111111111111111111111111111111111"
PROXY = "0x2222222222222222222222222222222222222222"
IMPL = "0x3333333333333333333333333333333333333333"
DEP_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
DEP_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def _job(**overrides) -> Any:
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
    # A bare MagicMock attribute is truthy, and the listing reads Job.is_proxy directly.
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


def test_dep_phase_passes_proxy_address(monkeypatch, tmp_path):
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


@pytest.mark.parametrize(
    "fake_uh, expected_total_upgrades",
    [
        pytest.param(
            {"schema_version": "0.1", "target_address": TARGET, "proxies": {DEP_A: {}}, "total_upgrades": 2},
            2,
            id="stored-when-proxies-exist",
        ),
        pytest.param(
            {"schema_version": "0.1", "target_address": TARGET, "proxies": {}, "total_upgrades": 0},
            None,
            id="skipped-when-no-proxies",
        ),
    ],
)
def test_dep_phase_upgrade_history_artifact(monkeypatch, tmp_path, fake_uh, expected_total_upgrades):
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
        lambda _p, enrich=True, from_block=0, chain_id=1: fake_uh,
    )

    project_dir = tmp_path / "p"
    project_dir.mkdir()
    worker._run_dependency_phase(MagicMock(), _job(), project_dir, "TestContract", TARGET)

    assert ("upgrade_history" in store) is (expected_total_upgrades is not None)
    assert store.get("upgrade_history", {}).get("total_upgrades") == expected_total_upgrades
    assert "dependencies" in store


def test_orphan_impl_appears_in_merged_list():
    """Sole coverage of the orphan branch in ``services/governance/proxies.py``."""
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
    assert merged[0]["address"] == IMPL


def test_display_name_chain_suffix_and_generic_fallback():
    from services.governance.proxies import _display_name

    entry1 = {"contract_name": "Pool", "run_name": "x", "display_name": None, "chain": "base"}
    assert _display_name(entry1) == "Pool (base)"
    entry2 = {"contract_name": "ERC1967Proxy", "run_name": "Router", "display_name": None, "chain": None}
    assert _display_name(entry2) == "Router"
    entry3 = {"contract_name": "Proxy", "run_name": "r", "display_name": "Custom", "chain": None}
    assert _display_name(entry3) == "Custom"


def test_full_data_flow_unified_through_graph_and_upgrade_history(monkeypatch, tmp_path):
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

    unified = build_unified_dependencies(TARGET, static, dynamic, cls)
    assert DEP_A in unified["dependencies"]
    assert IMPL not in unified["dependencies"]  # nested under DEP_A
    assert unified["dependencies"][DEP_A]["implementation"]["address"] == IMPL

    viz = build_dependency_visualization(unified, target_label="TestContract")
    node_addrs = {n["address"] for n in viz["nodes"]}
    assert {TARGET, DEP_A, DEP_B, IMPL} <= node_addrs

    edge_ops = {(e["from"], e["to"], e["op"]) for e in viz["edges"]}
    assert (f"addr:{DEP_A}", f"addr:{IMPL}", "DELEGATES_TO") in edge_ops
    assert (f"addr:{TARGET}", f"addr:{DEP_A}", "CALL") in edge_ops
    assert any(e["op"] == "STATIC_REF" and e["to"] == f"addr:{DEP_B}" for e in viz["edges"])

    # DEP_A gets its own upgrade history when analyzed as a target later.
    monkeypatch.setattr(
        "services.discovery.upgrade_history._fetch_logs_etherscan", lambda _a, _t, from_block=0, chain_id=1: []
    )
    from services.clients import etherscan

    monkeypatch.setattr(etherscan, "get_contract_info", lambda _a: (None, {}))

    uh = build_upgrade_history(unified)
    assert DEP_A not in uh["proxies"]
    assert uh["proxies"] == {}
    assert uh["total_upgrades"] == 0


@patch("routers.deps.get_all_artifacts")
@patch("routers.deps.SessionLocal")
def test_detail_inlines_all_pipeline_artifacts(mock_session_cls, mock_get_all_artifacts):
    from fastapi.testclient import TestClient

    import api

    client = TestClient(api.app)
    fake_job = _fake_api_job(name="full_run", address=TARGET)

    mock_session = MagicMock()

    # The API reads these from tables, not artifacts.
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

    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        stmt_str = str(stmt)
        # The batched prefetch iterates ``Result.scalars()``, so the mock needs ``__iter__``.
        items: list = []
        if call_count["n"] == 1:
            result.scalar_one_or_none.return_value = fake_job
        elif "contract" in stmt_str.lower() and "job_id" in stmt_str.lower() and call_count["n"] == 2:
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

    assert body["contract_analysis"]["summary"]["control_model"] == "authority"
    assert "state_variable:owner" in body["control_snapshot"]["controller_values"]
    assert len(body["resolved_control_graph"]["nodes"]) == 1
    assert body["dependencies"]["address"] == TARGET
    assert body["principal_history"]["function_permissions"][0]["principal"] == "0xaa"

    assert body["effective_permissions"]["functions"][0]["function"] == "pause()"

    assert body["principal_labels"]["principals"][0]["label"] == "admin"

    assert body["contract_name"] == "Vault"


@patch("routers.deps.SessionLocal")
def test_analyses_list_reads_contract_flags_from_static_worker(mock_session_cls):
    """Hidden proxy entries whose impl hasn't completed mean both jobs are included."""
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

    # The listing no longer fetches contract_flags.
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
    assert merged["proxy_address_display"] == PROXY
    assert merged["proxy_type_display"] == "eip1967"


def test_resolution_worker_rewrites_address_for_impl_jobs(monkeypatch):
    from workers.resolution_worker import ResolutionWorker

    worker = ResolutionWorker()
    monkeypatch.setattr(worker, "_fetch_balances", lambda *args, **kwargs: None)
    session = MagicMock()

    job = _job(
        address=IMPL,
        name="Impl",
        request={"rpc_url": "https://rpc.example", "proxy_address": PROXY, "chain_id": 1},
    )

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

    # ``**_kw`` so the mock survives new keyword arguments.
    def fake_resolve_graph(*, root_artifacts, rpc_url, max_depth, workspace_prefix, **_kw):
        captured_analyses.append(root_artifacts["analysis"])
        return {"nodes": [], "edges": []}, {}

    monkeypatch.setattr("workers.resolution_worker.resolve_control_graph", fake_resolve_graph)

    worker.process(session, job)

    assert captured_plans[0]["contract_address"] == PROXY

    assert captured_analyses[0]["subject"]["address"] == PROXY

    assert "control_snapshot" in stored_artifacts
    assert "resolved_control_graph" in stored_artifacts


def test_tracking_plan_preserves_controller_ids_and_read_specs():
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

    ids = {tc["controller_id"] for tc in plan["tracked_controllers"]}
    assert ids == {"state_variable:owner", "external_contract:authority"}

    for tc in plan["tracked_controllers"]:
        assert tc["read_spec"] is not None
        assert tc["read_spec"]["strategy"] == "getter_call"

    owner = next(tc for tc in plan["tracked_controllers"] if tc["label"] == "owner")
    assert owner["event_watch"] is not None
    assert len(owner["event_watch"]["events"]) == 1
    assert owner["event_watch"]["events"][0]["name"] == "OwnershipTransferred"


def test_discovery_company_mode_advances_to_selection(monkeypatch):
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

    assert len(advance_calls) == 1
    job_id, next_stage, _detail = advance_calls[0]
    assert job_id == "parent-1"
    assert next_stage == JobStage.selection

    assert "discovery_summary" in stored_artifacts
    summary = stored_artifacts["discovery_summary"]
    assert summary["mode"] == "company"
    assert summary["company"] == "TestProtocol"
    assert summary["discovered_count"] == 2
    assert "analyzed_count" not in summary
    assert "child_jobs" not in summary

    assert "contract_inventory" in stored_artifacts


def test_discovery_reads_and_writes_protocol_declared_chains(monkeypatch):
    """Evidence-based membership: company discovery READS the
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

    assert captured["declared_chains"] == ["ethereum", "base"]
    assert protocol_row.chains == ["base", "ethereum"]


def test_static_worker_reads_discovery_artifacts(monkeypatch):
    from workers.static_worker import StaticWorker

    worker = StaticWorker()
    session = MagicMock()

    job = _job(name="TestContract")

    sources = {"src/Test.sol": "pragma solidity ^0.8.19;\ncontract Test {}"}

    monkeypatch.setattr("workers.static_worker.get_source_files", lambda _s, _j: sources)

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
        source_verified=True,
    )
    session.execute.return_value.scalar_one_or_none.return_value = contract_row
    session.refresh = MagicMock()

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


def test_scaffold_project_writes_expected_files(tmp_path):
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

    foundry_toml = (project_dir / "foundry.toml").read_text()
    assert 'src = "src"' in foundry_toml
    assert "solc_version" in foundry_toml

    assert (project_dir / "src" / "Vault.sol").exists()
    assert (project_dir / "lib" / "openzeppelin" / "Ownable.sol").exists()

    assert (project_dir / "remappings.txt").exists()

    meta_data = json.loads((project_dir / "contract_meta.json").read_text())
    assert meta_data["contract_name"] == "Vault"


def test_dep_phase_records_degraded_on_failure(monkeypatch, tmp_path):
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

    assert "dependency_errors" not in store
    phases = {entry.phase: entry for entry in accumulator}
    assert "dependency_static" in phases
    assert "dependency_dynamic" in phases
    assert phases["dependency_static"].severity == "degraded"
    assert "static dep error" in phases["dependency_static"].message
    assert "dynamic dep error" in phases["dependency_dynamic"].message


def test_worker_stage_chain_is_complete(monkeypatch):
    """``PolicyWorker.next_stage`` depends on ``PSAT_EFFECTS_STAGE``."""
    from db.models import JobStage
    from workers.coverage_worker import CoverageWorker
    from workers.discovery import DiscoveryWorker
    from workers.effects_worker import EffectsWorker
    from workers.policy_worker import PolicyWorker
    from workers.resolution_worker import ResolutionWorker
    from workers.static_worker import StaticWorker

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

    monkeypatch.delenv("PSAT_EFFECTS_STAGE", raising=False)
    assert PolicyWorker().next_stage == JobStage.coverage

    monkeypatch.setenv("PSAT_EFFECTS_STAGE", "1")
    assert PolicyWorker().next_stage == JobStage.effects
    assert EffectsWorker.next_stage == CoverageWorker.stage
