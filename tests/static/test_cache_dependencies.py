from __future__ import annotations

import pytest

from tests.cache_helpers import (
    ADDR_A,
    FAKE_CLS_OUTPUT,
    FAKE_DYN_DEPS_NEW,
    FAKE_DYN_DEPS_OLD,
    FAKE_STATIC_DEPS,
    FAKE_UH_NEW,
    FAKE_UH_PREV,
    _create_completed_job_with_static_data,
    _make_dep_phase_job,
    _patch_dep_phase_helpers,
    db_session,  # noqa: F401
)


def test_static_deps_stored_on_first_run(db_session, monkeypatch):
    from db.models import Contract
    from db.queue import create_job, get_artifact, store_source_files
    from workers.static_worker import StaticWorker

    job = create_job(db_session, {"address": ADDR_A, "rpc_url": "https://rpc.example"})
    contract = Contract(
        job_id=job.id,
        address=ADDR_A,
        contract_name="TestContract",
        compiler_version="v0.8.24",
        language="solidity",
        evm_version="shanghai",
        optimization=True,
        optimization_runs=200,
        source_format="flat",
        source_file_count=1,
        remappings=[],
    )
    db_session.add(contract)
    db_session.commit()
    store_source_files(db_session, job.id, {"src/Test.sol": "contract Test {}"})

    monkeypatch.setattr(
        "workers.static_worker.find_dependencies",
        lambda *a, **kw: FAKE_STATIC_DEPS,
    )
    monkeypatch.setattr(
        "workers.static_worker.find_dynamic_dependencies",
        lambda *a, **kw: None,
    )
    monkeypatch.setattr(
        "workers.static_worker.classify_contracts",
        lambda *a, **kw: None,
    )
    monkeypatch.setattr(
        "workers.static_worker.build_unified_dependencies",
        lambda *a, **kw: {"target_address": ADDR_A, "dependencies": {}},
    )
    monkeypatch.setattr(
        "workers.static_worker.enrich_dependency_metadata",
        lambda *a, **kw: None,
    )
    monkeypatch.setattr(
        "workers.static_worker.build_dependency_visualization",
        lambda *a, **kw: {"nodes": [], "edges": [], "metadata": {}},
    )

    worker = StaticWorker()
    monkeypatch.setattr(worker, "_resolve_proxy", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_scaffold_project", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_run_analysis_phase", lambda *a, **kw: True)
    monkeypatch.setattr(worker, "_run_tracking_plan_phase", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)

    worker.process(db_session, job)

    art = get_artifact(db_session, job.id, "static_dependencies")
    assert isinstance(art, dict)
    assert art["address"] == FAKE_STATIC_DEPS["address"]
    assert art["dependencies"] == FAKE_STATIC_DEPS["dependencies"]


def test_static_deps_reused_on_cache_hit(db_session, monkeypatch):
    from db.models import Contract
    from db.queue import create_job, store_artifact, store_source_files
    from workers.static_worker import StaticWorker

    source_job = _create_completed_job_with_static_data(db_session)
    store_artifact(db_session, source_job.id, "static_dependencies", data=FAKE_STATIC_DEPS)

    job = create_job(
        db_session,
        {
            "address": ADDR_A,
            "rpc_url": "https://rpc.example",
            "static_cached": True,
            "cache_source_job_id": str(source_job.id),
        },
    )
    contract = Contract(
        job_id=job.id,
        address=ADDR_A,
        contract_name="TestContract",
        compiler_version="v0.8.24",
        language="solidity",
        evm_version="shanghai",
        optimization=True,
        optimization_runs=200,
        source_format="flat",
        source_file_count=1,
        remappings=[],
    )
    db_session.add(contract)
    db_session.commit()
    store_source_files(db_session, job.id, {"src/Test.sol": "contract Test {}"})
    store_artifact(db_session, job.id, "static_dependencies", data=FAKE_STATIC_DEPS)
    store_artifact(db_session, job.id, "contract_analysis", data={"summary": {}})

    find_deps_called = []

    def mock_find_deps(*a, **kw):
        find_deps_called.append(True)
        return FAKE_STATIC_DEPS

    monkeypatch.setattr("workers.static_worker.find_dependencies", mock_find_deps)
    monkeypatch.setattr(
        "workers.static_worker.find_dynamic_dependencies",
        lambda *a, **kw: None,
    )
    monkeypatch.setattr(
        "workers.static_worker.classify_contracts",
        lambda *a, **kw: None,
    )
    monkeypatch.setattr(
        "workers.static_worker.build_unified_dependencies",
        lambda *a, **kw: {"target_address": ADDR_A, "dependencies": {}},
    )
    monkeypatch.setattr(
        "workers.static_worker.enrich_dependency_metadata",
        lambda *a, **kw: None,
    )
    monkeypatch.setattr(
        "workers.static_worker.build_dependency_visualization",
        lambda *a, **kw: {"nodes": [], "edges": [], "metadata": {}},
    )

    worker = StaticWorker()
    monkeypatch.setattr(worker, "_resolve_proxy", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_scaffold_project", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_run_analysis_phase", lambda *a, **kw: True)
    monkeypatch.setattr(worker, "_run_tracking_plan_phase", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)

    worker.process(db_session, job)

    assert find_deps_called == []


def test_dynamic_deps_still_run_on_cache_hit(db_session, monkeypatch):
    from db.models import Contract
    from db.queue import create_job, store_artifact, store_source_files
    from workers.static_worker import StaticWorker

    source_job = _create_completed_job_with_static_data(db_session)
    store_artifact(db_session, source_job.id, "static_dependencies", data=FAKE_STATIC_DEPS)

    job = create_job(
        db_session,
        {
            "address": ADDR_A,
            "rpc_url": "https://rpc.example",
            "static_cached": True,
            "cache_source_job_id": str(source_job.id),
        },
    )
    contract = Contract(
        job_id=job.id,
        address=ADDR_A,
        contract_name="TestContract",
        compiler_version="v0.8.24",
        language="solidity",
        evm_version="shanghai",
        optimization=True,
        optimization_runs=200,
        source_format="flat",
        source_file_count=1,
        remappings=[],
    )
    db_session.add(contract)
    db_session.commit()
    store_source_files(db_session, job.id, {"src/Test.sol": "contract Test {}"})
    store_artifact(db_session, job.id, "static_dependencies", data=FAKE_STATIC_DEPS)
    store_artifact(db_session, job.id, "contract_analysis", data={"summary": {}})

    dynamic_called = []

    monkeypatch.setattr("workers.static_worker.find_dependencies", lambda *a, **kw: FAKE_STATIC_DEPS)
    monkeypatch.setattr(
        "workers.static_worker.find_dynamic_dependencies",
        lambda *a, **kw: dynamic_called.append(True) or {"dependencies": [], "dependency_graph": []},
    )
    monkeypatch.setattr(
        "workers.static_worker.classify_contracts",
        lambda *a, **kw: None,
    )
    monkeypatch.setattr(
        "workers.static_worker.build_unified_dependencies",
        lambda *a, **kw: {"target_address": ADDR_A, "dependencies": {}},
    )
    monkeypatch.setattr(
        "workers.static_worker.enrich_dependency_metadata",
        lambda *a, **kw: None,
    )
    monkeypatch.setattr(
        "workers.static_worker.build_dependency_visualization",
        lambda *a, **kw: {"nodes": [], "edges": [], "metadata": {}},
    )

    worker = StaticWorker()
    monkeypatch.setattr(worker, "_resolve_proxy", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_scaffold_project", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_run_analysis_phase", lambda *a, **kw: True)
    monkeypatch.setattr(worker, "_run_tracking_plan_phase", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)

    worker.process(db_session, job)

    assert dynamic_called == [True]


def test_merge_dynamic_deps():
    from workers.static_worker import _merge_dynamic_deps

    merged = _merge_dynamic_deps(FAKE_DYN_DEPS_OLD, FAKE_DYN_DEPS_NEW)

    assert "0x0000000000000000000000000000000000000042" in merged["dependencies"]
    assert "0x0000000000000000000000000000000000000099" in merged["dependencies"]
    assert len(merged["dependencies"]) == 2

    tx_hashes = [tx["tx_hash"] for tx in merged["transactions_analyzed"]]
    assert tx_hashes == ["0xaaa", "0xbbb", "0xccc"]

    prov_42 = merged["provenance"]["0x0000000000000000000000000000000000000042"]
    assert len(prov_42) == 2  # one from old, one from new
    assert any(p["tx_hash"] == "0xaaa" for p in prov_42)
    assert any(p["tx_hash"] == "0xccc" for p in prov_42)

    prov_99 = merged["provenance"]["0x0000000000000000000000000000000000000099"]
    assert len(prov_99) == 1

    assert len(merged["dependency_graph"]) == 3

    assert "debug_traceTransaction" in merged["trace_methods"]


def test_dynamic_deps_artifact_stored_on_first_run(db_session, monkeypatch):
    from db.queue import get_artifact
    from workers.static_worker import StaticWorker

    job = _make_dep_phase_job(db_session)

    fake_dyn = dict(FAKE_DYN_DEPS_OLD)
    _patch_dep_phase_helpers(monkeypatch, lambda *a, **kw: fake_dyn)

    worker = StaticWorker()
    monkeypatch.setattr(worker, "_resolve_proxy", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_scaffold_project", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_run_analysis_phase", lambda *a, **kw: True)
    monkeypatch.setattr(worker, "_run_tracking_plan_phase", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)

    worker.process(db_session, job)

    art = get_artifact(db_session, job.id, "dynamic_dependencies")
    assert isinstance(art, dict)
    assert art["dependencies"] == FAKE_DYN_DEPS_OLD["dependencies"]
    assert len(art["transactions_analyzed"]) == 2


@pytest.mark.parametrize(
    "extra_request",
    [
        pytest.param(None, id="append_only_merge_on_rerun"),
        pytest.param({"static_cached": True}, id="static_cached_source_job_fallback"),
    ],
)
def test_dynamic_deps_append_only_merge_on_rerun(db_session, monkeypatch, extra_request):
    from db.queue import get_artifact, store_artifact
    from workers.static_worker import StaticWorker

    job = _make_dep_phase_job(db_session, extra_request=extra_request)

    store_artifact(db_session, job.id, "dynamic_dependencies", data=FAKE_DYN_DEPS_OLD)

    captured_kwargs = {}

    def mock_find_dyn(*args, **kwargs):
        captured_kwargs.update(kwargs)
        return FAKE_DYN_DEPS_NEW

    _patch_dep_phase_helpers(monkeypatch, mock_find_dyn)

    worker = StaticWorker()
    monkeypatch.setattr(worker, "_resolve_proxy", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_scaffold_project", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_run_analysis_phase", lambda *a, **kw: True)
    monkeypatch.setattr(worker, "_run_tracking_plan_phase", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)

    worker.process(db_session, job)

    assert captured_kwargs.get("start_block") == 201

    art = get_artifact(db_session, job.id, "dynamic_dependencies")
    assert isinstance(art, dict)
    assert "0x0000000000000000000000000000000000000042" in art["dependencies"]
    assert "0x0000000000000000000000000000000000000099" in art["dependencies"]
    tx_hashes = {tx["tx_hash"] for tx in art["transactions_analyzed"]}
    assert tx_hashes == {"0xaaa", "0xbbb", "0xccc"}


def test_dynamic_deps_no_new_transactions_uses_previous(db_session, monkeypatch):
    from db.queue import get_artifact, store_artifact
    from workers.static_worker import StaticWorker

    job = _make_dep_phase_job(db_session)
    store_artifact(db_session, job.id, "dynamic_dependencies", data=FAKE_DYN_DEPS_OLD)

    from services.discovery.dynamic_dependencies import NoNewTransactionsError

    def mock_find_dyn(*args, **kwargs):
        raise NoNewTransactionsError(f"No representative transactions found for {ADDR_A}")

    _patch_dep_phase_helpers(monkeypatch, mock_find_dyn)

    worker = StaticWorker()
    monkeypatch.setattr(worker, "_resolve_proxy", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_scaffold_project", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_run_analysis_phase", lambda *a, **kw: True)
    monkeypatch.setattr(worker, "_run_tracking_plan_phase", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)

    worker.process(db_session, job)

    art = get_artifact(db_session, job.id, "dynamic_dependencies")
    assert isinstance(art, dict)
    assert art["dependencies"] == FAKE_DYN_DEPS_OLD["dependencies"]
    assert len(art["transactions_analyzed"]) == 2


def test_dynamic_deps_explicit_tx_hashes_skip_merge(db_session, monkeypatch):
    from db.queue import get_artifact, store_artifact
    from workers.static_worker import StaticWorker

    job = _make_dep_phase_job(
        db_session,
        extra_request={
            "dynamic_tx_hashes": ["0xddd"],
        },
    )
    store_artifact(db_session, job.id, "dynamic_dependencies", data=FAKE_DYN_DEPS_OLD)

    captured_kwargs = {}

    def mock_find_dyn(*args, **kwargs):
        captured_kwargs.update(kwargs)
        return FAKE_DYN_DEPS_NEW

    _patch_dep_phase_helpers(monkeypatch, mock_find_dyn)

    worker = StaticWorker()
    monkeypatch.setattr(worker, "_resolve_proxy", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_scaffold_project", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_run_analysis_phase", lambda *a, **kw: True)
    monkeypatch.setattr(worker, "_run_tracking_plan_phase", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)

    worker.process(db_session, job)

    assert captured_kwargs.get("start_block") is None
    assert captured_kwargs.get("tx_hashes") == ["0xddd"]

    art = get_artifact(db_session, job.id, "dynamic_dependencies")
    assert isinstance(art, dict)
    assert art["transactions_analyzed"] == FAKE_DYN_DEPS_NEW["transactions_analyzed"]


def test_classifications_stored_on_first_run(db_session, monkeypatch):
    from db.queue import get_artifact
    from workers.static_worker import StaticWorker

    job = _make_dep_phase_job(db_session, extra_request={"chain_id": 1})

    captured_kwargs = {}

    def mock_classify(*args, **kwargs):
        captured_kwargs.update(kwargs)
        return FAKE_CLS_OUTPUT

    monkeypatch.setattr("workers.static_worker.find_dependencies", lambda *a, **kw: FAKE_STATIC_DEPS)
    monkeypatch.setattr(
        "workers.static_worker.find_dynamic_dependencies",
        lambda *a, **kw: None,
    )
    monkeypatch.setattr("workers.static_worker.classify_contracts", mock_classify)
    monkeypatch.setattr(
        "workers.static_worker.build_unified_dependencies",
        lambda *a, **kw: {"target_address": ADDR_A, "dependencies": {}},
    )
    monkeypatch.setattr("workers.static_worker.enrich_dependency_metadata", lambda *a, **kw: None)
    monkeypatch.setattr(
        "workers.static_worker.build_dependency_visualization",
        lambda *a, **kw: {"nodes": [], "edges": [], "metadata": {}},
    )

    worker = StaticWorker()
    monkeypatch.setattr(worker, "_resolve_proxy", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_scaffold_project", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_run_analysis_phase", lambda *a, **kw: True)
    monkeypatch.setattr(worker, "_run_tracking_plan_phase", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)

    worker.process(db_session, job)

    art = get_artifact(db_session, job.id, "classifications")
    assert isinstance(art, dict)
    assert art["classifications"]["0x0000000000000000000000000000000000000042"]["type"] == "regular"
    assert art["classifications"]["0x0000000000000000000000000000000000000043"]["type"] == "proxy"


def test_classifications_reused_via_pre_classified(db_session, monkeypatch):
    from db.queue import get_artifact, store_artifact
    from workers.static_worker import StaticWorker

    job = _make_dep_phase_job(db_session, extra_request={"chain_id": 1})

    store_artifact(db_session, job.id, "classifications", data=FAKE_CLS_OUTPUT)

    captured_kwargs = {}

    def mock_classify(*args, **kwargs):
        captured_kwargs.update(kwargs)
        extended = dict(FAKE_CLS_OUTPUT)
        extended["classifications"] = dict(FAKE_CLS_OUTPUT["classifications"])
        extended["classifications"]["0x0000000000000000000000000000000000000099"] = {"type": "library"}
        return extended

    monkeypatch.setattr("workers.static_worker.find_dependencies", lambda *a, **kw: FAKE_STATIC_DEPS)
    monkeypatch.setattr(
        "workers.static_worker.find_dynamic_dependencies",
        lambda *a, **kw: None,
    )
    monkeypatch.setattr("workers.static_worker.classify_contracts", mock_classify)
    monkeypatch.setattr(
        "workers.static_worker.build_unified_dependencies",
        lambda *a, **kw: {"target_address": ADDR_A, "dependencies": {}},
    )
    monkeypatch.setattr("workers.static_worker.enrich_dependency_metadata", lambda *a, **kw: None)
    monkeypatch.setattr(
        "workers.static_worker.build_dependency_visualization",
        lambda *a, **kw: {"nodes": [], "edges": [], "metadata": {}},
    )

    worker = StaticWorker()
    monkeypatch.setattr(worker, "_resolve_proxy", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_scaffold_project", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_run_analysis_phase", lambda *a, **kw: True)
    monkeypatch.setattr(worker, "_run_tracking_plan_phase", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)

    worker.process(db_session, job)

    pre = captured_kwargs.get("pre_classified")
    assert pre is not None
    assert "0x0000000000000000000000000000000000000042" in pre
    assert "0x0000000000000000000000000000000000000043" in pre

    art = get_artifact(db_session, job.id, "classifications")
    assert isinstance(art, dict)
    assert "0x0000000000000000000000000000000000000099" in art["classifications"]


def test_upgrade_history_append_only_on_rerun(db_session, monkeypatch):
    from db.queue import get_artifact, store_artifact
    from workers.static_worker import StaticWorker

    job = _make_dep_phase_job(db_session)

    store_artifact(db_session, job.id, "upgrade_history", data=FAKE_UH_PREV)

    captured_kwargs = {}

    def mock_build_uh(deps_path, *, enrich=True, from_block=0, chain_id=1):
        captured_kwargs["from_block"] = from_block
        return FAKE_UH_NEW

    monkeypatch.setattr("workers.static_worker.find_dependencies", lambda *a, **kw: FAKE_STATIC_DEPS)
    monkeypatch.setattr("workers.static_worker.find_dynamic_dependencies", lambda *a, **kw: None)
    monkeypatch.setattr("workers.static_worker.classify_contracts", lambda *a, **kw: None)
    monkeypatch.setattr(
        "workers.static_worker.build_unified_dependencies",
        lambda *a, **kw: {"target_address": ADDR_A, "dependencies": {}},
    )
    monkeypatch.setattr("workers.static_worker.enrich_dependency_metadata", lambda *a, **kw: None)
    monkeypatch.setattr(
        "workers.static_worker.build_dependency_visualization",
        lambda *a, **kw: {"nodes": [], "edges": [], "metadata": {}},
    )
    monkeypatch.setattr(
        "services.discovery.upgrade_history.build_upgrade_history",
        mock_build_uh,
    )
    # This test is about the merge; the per-tx receipt read is stubbed to the unfetchable ``None``.
    monkeypatch.setattr("services.discovery.upgrade_history._fetch_receipt", lambda *a, **kw: None)

    worker = StaticWorker()
    monkeypatch.setattr(worker, "_resolve_proxy", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_scaffold_project", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_run_analysis_phase", lambda *a, **kw: True)
    monkeypatch.setattr(worker, "_run_tracking_plan_phase", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)

    worker.process(db_session, job)

    assert captured_kwargs["from_block"] == 51

    art = get_artifact(db_session, job.id, "upgrade_history")
    assert isinstance(art, dict)
    proxy_addr = "0xdac17f958d2ee523a2206206994597c13d831ec7"
    assert len(art["proxies"][proxy_addr]["events"]) == 2
    assert art["total_upgrades"] == 2


def test_upgrade_history_no_new_events_uses_previous(db_session, monkeypatch):
    from db.queue import get_artifact, store_artifact
    from workers.static_worker import StaticWorker

    job = _make_dep_phase_job(db_session)
    store_artifact(db_session, job.id, "upgrade_history", data=FAKE_UH_PREV)

    def mock_build_uh(deps_path, *, enrich=True, from_block=0, chain_id=1):
        return {
            "schema_version": "0.1",
            "target_address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
            "proxies": {},
            "total_upgrades": 0,
        }

    monkeypatch.setattr("workers.static_worker.find_dependencies", lambda *a, **kw: FAKE_STATIC_DEPS)
    monkeypatch.setattr("workers.static_worker.find_dynamic_dependencies", lambda *a, **kw: None)
    monkeypatch.setattr("workers.static_worker.classify_contracts", lambda *a, **kw: None)
    monkeypatch.setattr(
        "workers.static_worker.build_unified_dependencies",
        lambda *a, **kw: {"target_address": ADDR_A, "dependencies": {}},
    )
    monkeypatch.setattr("workers.static_worker.enrich_dependency_metadata", lambda *a, **kw: None)
    monkeypatch.setattr(
        "workers.static_worker.build_dependency_visualization",
        lambda *a, **kw: {"nodes": [], "edges": [], "metadata": {}},
    )
    monkeypatch.setattr(
        "services.discovery.upgrade_history.build_upgrade_history",
        mock_build_uh,
    )
    monkeypatch.setattr("services.discovery.upgrade_history._fetch_receipt", lambda *a, **kw: None)

    worker = StaticWorker()
    monkeypatch.setattr(worker, "_resolve_proxy", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_scaffold_project", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_run_analysis_phase", lambda *a, **kw: True)
    monkeypatch.setattr(worker, "_run_tracking_plan_phase", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)

    worker.process(db_session, job)

    art = get_artifact(db_session, job.id, "upgrade_history")
    assert isinstance(art, dict)
    proxy_addr = "0xdac17f958d2ee523a2206206994597c13d831ec7"
    assert proxy_addr in art["proxies"]
    assert art["total_upgrades"] == 1


def test_enrichment_cache_skips_cached_addresses(db_session, monkeypatch):
    addr_a = "0x0000000000000000000000000000000000000aaa"
    addr_b = "0x0000000000000000000000000000000000000bbb"
    addr_c = "0x0000000000000000000000000000000000000ccc"

    unified = {
        "dependencies": {
            addr_a: {"type": "regular"},
            addr_b: {"type": "regular"},
            addr_c: {"type": "regular"},
        },
        "dependency_graph": {},
    }

    info_cache: dict = {
        addr_a: ("TokenA", {"0xaaaaaaaa": "funcA"}),
        addr_b: ("TokenB", {}),
    }

    call_log = []

    def mock_get_contract_info(addr, *, chain_id=1):
        call_log.append(addr)
        return ("TokenC", {"0xcccccccc": "funcC"})

    monkeypatch.setattr(
        "services.discovery.unified_dependencies.get_contract_info",
        mock_get_contract_info,
    )

    from services.discovery.unified_dependencies import enrich_dependency_metadata

    enrich_dependency_metadata(unified, info_cache=info_cache, chain_id=1)

    assert call_log == [addr_c]

    assert addr_a in info_cache
    assert addr_b in info_cache
    assert addr_c in info_cache
    assert info_cache[addr_c] == ("TokenC", {"0xcccccccc": "funcC"})

    assert unified["dependencies"][addr_a].get("contract_name") == "TokenA"
    assert unified["dependencies"][addr_c].get("contract_name") == "TokenC"


def test_merge_dynamic_deps_duplicate_edge_provenance():
    from workers.static_worker import _merge_dynamic_deps

    old = {
        "address": "0xaaa",
        "rpc": "https://rpc",
        "transactions_analyzed": [{"tx_hash": "0x111", "block_number": 10}],
        "trace_methods": ["debug_traceTransaction"],
        "dependencies": ["0xbbb"],
        "provenance": {"0xbbb": [{"tx_hash": "0x111"}]},
        "dependency_graph": [
            {
                "from": "0xaaa",
                "to": "0xbbb",
                "op": "CALL",
                "provenance": [{"tx_hash": "0x111", "block_number": 10}],
            },
        ],
        "trace_errors": [],
    }
    new = {
        "address": "0xaaa",
        "rpc": "https://rpc",
        "transactions_analyzed": [{"tx_hash": "0x222", "block_number": 20}],
        "trace_methods": ["debug_traceTransaction"],
        "dependencies": ["0xbbb"],
        "provenance": {"0xbbb": [{"tx_hash": "0x222"}]},
        "dependency_graph": [
            {
                "from": "0xaaa",
                "to": "0xbbb",
                "op": "CALL",
                "provenance": [{"tx_hash": "0x222", "block_number": 20}],
            },
        ],
        "trace_errors": [],
    }

    merged = _merge_dynamic_deps(old, new)

    assert len(merged["dependency_graph"]) == 1
    edge = merged["dependency_graph"][0]
    assert len(edge["provenance"]) == 2
    prov_hashes = {p["tx_hash"] for p in edge["provenance"]}
    assert prov_hashes == {"0x111", "0x222"}


def test_merge_upgrade_history_deduplicates_events():
    from workers.static_worker import _merge_upgrade_history

    merged = _merge_upgrade_history(FAKE_UH_PREV, FAKE_UH_PREV)
    proxy_addr = "0xdac17f958d2ee523a2206206994597c13d831ec7"
    events = merged["proxies"][proxy_addr]["events"]
    assert len(events) == 1  # deduplicated
    assert merged["total_upgrades"] == 1


def test_merge_dynamic_deps_trace_errors():
    from workers.static_worker import _merge_dynamic_deps

    old = {
        "address": "0xaaa",
        "rpc": "https://rpc",
        "transactions_analyzed": [],
        "trace_methods": [],
        "dependencies": [],
        "provenance": {},
        "dependency_graph": [],
        "trace_errors": [
            {"tx_hash": "0x111", "error": "timeout"},
        ],
    }
    new = {
        "address": "0xaaa",
        "rpc": "https://rpc",
        "transactions_analyzed": [],
        "trace_methods": [],
        "dependencies": [],
        "provenance": {},
        "dependency_graph": [],
        "trace_errors": [
            {"tx_hash": "0x111", "error": "timeout"},  # duplicate
            {"tx_hash": "0x222", "error": "revert"},
        ],
    }

    merged = _merge_dynamic_deps(old, new)
    assert len(merged["trace_errors"]) == 2
    error_hashes = {e["tx_hash"] for e in merged["trace_errors"]}
    assert error_hashes == {"0x111", "0x222"}


def test_dependency_phase_threads_job_chain_id_to_subphases(db_session, monkeypatch):
    """The txlist/getLogs calls would otherwise silently run on mainnet and return empty for L2 contracts."""
    from workers.static_worker import StaticWorker

    captured: dict[str, int | None] = {}

    def fake_find_dyn(*_a, **kw):
        captured["dyn_chain_id"] = kw.get("chain_id")
        return None

    def fake_build_upgrade_history(*_a, **kw):
        captured["uh_chain_id"] = kw.get("chain_id")
        return {"schema_version": "0.1", "target_address": ADDR_A, "proxies": {}}

    _patch_dep_phase_helpers(monkeypatch, fake_find_dyn)
    # Imported locally inside run_upgrade_history, so patch it at the source module.
    monkeypatch.setattr("services.discovery.upgrade_history.build_upgrade_history", fake_build_upgrade_history)

    # create_job dual-writes jobs.chain_id=8453, which _parent_chain_name reads first.
    job = _make_dep_phase_job(db_session, extra_request={"chain": "base"})

    worker = StaticWorker()
    monkeypatch.setattr(worker, "_resolve_proxy", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_scaffold_project", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "_run_analysis_phase", lambda *a, **kw: True)
    monkeypatch.setattr(worker, "_run_tracking_plan_phase", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)

    worker.process(db_session, job)

    assert captured.get("dyn_chain_id") == 8453  # F2
    assert captured.get("uh_chain_id") == 8453  # F1
