from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from workers.discovery import DiscoveryWorker


def _job(**overrides) -> Any:
    defaults = {
        "id": "job-1",
        "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        "name": None,
        "company": None,
        "protocol_id": None,
        "chain_id": 1,
        "request": {},
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _etherscan_result(**overrides):
    base = {
        "ContractName": "TetherToken",
        "CompilerVersion": "v0.4.18+commit.9cf6e910",
        "SourceCode": "pragma solidity ^0.4.18; contract TetherToken {}",
        "OptimizationUsed": "1",
        "Runs": "200",
        "EVMVersion": "london",
        "LicenseType": "MIT",
    }
    base.update(overrides)
    return base


def _patch_discovery(monkeypatch, etherscan_result):
    monkeypatch.setattr(
        "workers.discovery.fetch",
        lambda _addr, **_kw: etherscan_result,
    )
    monkeypatch.setattr("workers.discovery._batch_get_creators", lambda addresses, **kw: {})

    source_calls: list[tuple] = []
    monkeypatch.setattr(
        "workers.discovery.store_source_files",
        lambda session, job_id, sources: source_calls.append((job_id, sources)),
    )

    artifact_calls: list[tuple] = []
    monkeypatch.setattr(
        "workers.discovery.store_artifact",
        lambda session, job_id, name, data=None, text_data=None: artifact_calls.append((name, data)),
    )

    return source_calls, artifact_calls


def test_happy_path_stores_sources_and_artifacts(monkeypatch):
    result = _etherscan_result()
    source_calls, artifact_calls = _patch_discovery(monkeypatch, result)

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)

    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    worker._process_address(session, job)

    assert len(source_calls) == 1
    stored_job_id, stored_sources = source_calls[0]
    assert stored_job_id == "job-1"
    assert isinstance(stored_sources, dict)
    assert len(stored_sources) > 0
    assert "src/TetherToken.sol" in stored_sources

    session.add.assert_called_once()
    contract = session.add.call_args[0][0]
    assert contract.address == job.address.lower()
    assert contract.contract_name == "TetherToken"
    assert contract.compiler_version == "v0.4.18+commit.9cf6e910"
    assert contract.language == "solidity"
    assert contract.optimization is True
    assert contract.optimization_runs == 200
    assert contract.evm_version == "london"
    assert contract.license == "MIT"
    assert contract.source_file_count == 1

    short = job.address[2:10]
    assert job.name == f"TetherToken_{short}"
    session.commit.assert_called()


def test_happy_path_does_not_overwrite_existing_job_name(monkeypatch):
    result = _etherscan_result()
    _patch_discovery(monkeypatch, result)

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)

    session = MagicMock()
    job = _job(name="AlreadySet")

    worker._process_address(session, job)

    assert job.name == "AlreadySet"


# ``source_format`` sniffs the first 10 chars; Etherscan's double-brace format overflows that window.
_STANDARD_JSON_SOURCE = json.dumps(
    {
        "sources": {"contracts/Token.sol": {"content": "pragma solidity ^0.8.0; contract Token {}"}},
        "language": "Solidity",
        "settings": {"optimizer": {"enabled": True, "runs": 200}, "remappings": []},
    }
)
assert "sources" in _STANDARD_JSON_SOURCE[:10]


@pytest.mark.parametrize(
    "overrides, drop_keys, expected",
    [
        pytest.param(
            {
                "CompilerVersion": "vyper:0.3.7",
                "SourceCode": "# @version 0.3.7\n@external\ndef foo(): pass",
                "ContractName": "VyperVault",
            },
            (),
            {"language": "vyper"},
            id="vyper-from-compiler-version",
        ),
        # This hits the ``# @version`` source-comment fallback.
        pytest.param(
            {
                "CompilerVersion": "v0.3.7+commit.abc",
                "SourceCode": "# @version 0.3.7\n@external\ndef bar(): pass",
                "ContractName": "VyperPool",
            },
            (),
            {"language": "vyper"},
            id="vyper-from-v0-prefix-source-fallback",
        ),
        pytest.param(
            {
                "CompilerVersion": "v0.8.20+commit.a1b2c3",
                "SourceCode": "pragma solidity ^0.8.20; contract Foo {}",
            },
            (),
            {"language": "solidity"},
            id="solidity-when-compiler-not-vyper",
        ),
        pytest.param({"EVMVersion": ""}, (), {"evm_version": None}, id="evm-version-empty-preserves-compiler-default"),
        pytest.param(
            {"EVMVersion": "Default"}, (), {"evm_version": None}, id="evm-version-default-preserves-compiler-default"
        ),
        pytest.param({"EVMVersion": "cancun"}, (), {"evm_version": "cancun"}, id="evm-version-explicit-preserved"),
        pytest.param({}, ("EVMVersion",), {"evm_version": None}, id="evm-version-key-missing"),
        pytest.param(
            {"SourceCode": _STANDARD_JSON_SOURCE, "ContractName": "Token"},
            (),
            {"source_format": "standard_json"},
            id="source-format-standard-json",
        ),
        pytest.param(
            {"SourceCode": "pragma solidity ^0.8.0; contract Flat {}", "ContractName": "Flat"},
            (),
            {"source_format": "flat"},
            id="source-format-flat",
        ),
        pytest.param(
            {"OptimizationUsed": "0"},
            (),
            {"optimization": False, "optimization_runs": 200},
            id="optimization-disabled",
        ),
        pytest.param({"Runs": "10000"}, (), {"optimization_runs": 10000}, id="runs-custom-value"),
    ],
)
def test_process_address_contract_fields(monkeypatch, overrides, drop_keys, expected):
    result = _etherscan_result(**overrides)
    for key in drop_keys:
        del result[key]
    _patch_discovery(monkeypatch, result)

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    worker._process_address(session, job)

    contract = session.add.call_args[0][0]
    for field, value in expected.items():
        assert getattr(contract, field) == value


def test_standard_json_multiple_files_parsed_correctly(monkeypatch):
    inner = json.dumps(
        {
            "sources": {
                "contracts/Token.sol": {"content": "pragma solidity ^0.8.0; contract Token {}"},
                "contracts/Lib.sol": {"content": "pragma solidity ^0.8.0; library Lib {}"},
                "@openzeppelin/contracts/token/ERC20/ERC20.sol": {
                    "content": "pragma solidity ^0.8.0; contract ERC20 {}"
                },
            },
            "language": "Solidity",
            "settings": {"remappings": ["@openzeppelin/=node_modules/@openzeppelin/"]},
        }
    )
    source_code = "{" + inner + "}"

    result = _etherscan_result(SourceCode=source_code, ContractName="Token")
    source_calls, artifact_calls = _patch_discovery(monkeypatch, result)

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    worker._process_address(session, job)

    _, stored_sources = source_calls[0]
    assert len(stored_sources) == 3
    assert "contracts/Token.sol" in stored_sources
    assert "contracts/Lib.sol" in stored_sources

    contract = session.add.call_args[0][0]
    assert contract.source_file_count == 3
    assert "@openzeppelin/=node_modules/@openzeppelin/" in contract.remappings


def test_process_address_fanout_invokes_fetch_and_creators(monkeypatch):
    from services.concurrency import RpcExecutor

    RpcExecutor.reset_for_tests()
    result = _etherscan_result()
    _patch_discovery(monkeypatch, result)

    fetch_calls: list[str] = []
    creators_calls: list[tuple[list[str], int]] = []

    def fake_fetch(addr: str, *, chain_id: int = 1) -> dict:
        fetch_calls.append(addr)
        return result

    def fake_batch_creators(addrs: list[str], *, chain_id: int = 1) -> dict[str, str]:
        creators_calls.append((list(addrs), chain_id))
        return {addrs[0].lower(): "0xc0ffee0000000000000000000000000000000001"}

    monkeypatch.setattr("workers.discovery.fetch", fake_fetch)
    monkeypatch.setattr("workers.discovery._batch_get_creators", fake_batch_creators)

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    # A Base-only address answers nothing on chain 1, which nulled the deployer and starved deployer-cascade adoption.
    job = _job(chain_id=8453)

    worker._process_address(session, job)

    assert fetch_calls == [job.address]
    assert creators_calls == [([job.address], 8453)]
    contract = session.add.call_args[0][0]
    assert contract.deployer == "0xc0ffee0000000000000000000000000000000001"


def test_process_address_fanout_swallows_creators_exception(monkeypatch):
    from services.concurrency import RpcExecutor

    RpcExecutor.reset_for_tests()
    result = _etherscan_result()
    _patch_discovery(monkeypatch, result)

    monkeypatch.setattr("workers.discovery.fetch", lambda _addr, **_kw: result)

    def boom(_addrs, **_kw):
        raise RuntimeError("creators API down")

    monkeypatch.setattr("workers.discovery._batch_get_creators", boom)

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    worker._process_address(session, job)

    contract = session.add.call_args[0][0]
    assert contract.deployer is None


def test_cache_hit_routes_row_through_gate_intake(monkeypatch):
    """The static-cache-hit early return must still enter the membership gate:
    the cache hit reuses ANALYSIS, never protocol membership."""
    from services.concurrency import RpcExecutor

    RpcExecutor.reset_for_tests()
    result = _etherscan_result()
    _patch_discovery(monkeypatch, result)

    monkeypatch.setattr(
        "workers.discovery.find_completed_static_cache",
        lambda session, address, chain=None, **kw: SimpleNamespace(id="cached-job-1"),
    )
    monkeypatch.setattr("workers.discovery.copy_static_cache", lambda session, src, dst: 42)

    cached_row = MagicMock()
    cached_row.protocol_id = None
    cached_row.contract_name = "AtomicQueue"

    intake_calls: list[tuple] = []
    monkeypatch.setattr(
        "workers.discovery._gate_intake",
        lambda session, job, contract, request: intake_calls.append((job, contract, request)),
    )

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.get.return_value = cached_row
    job = _job(protocol_id=1, request={"discovery_sources": ["inventory"]})

    worker._process_address(session, job)

    assert len(intake_calls) == 1
    intake_job, intake_row, intake_request = intake_calls[0]
    assert intake_job is job
    assert intake_row is cached_row
    assert intake_request.get("discovery_sources") == ["inventory"]


def test_fetch_path_routes_existing_row_through_gate_intake(monkeypatch):
    from services.concurrency import RpcExecutor

    RpcExecutor.reset_for_tests()
    result = _etherscan_result()
    _patch_discovery(monkeypatch, result)

    monkeypatch.setattr("workers.discovery.find_completed_static_cache", lambda *a, **kw: None)

    existing_row = MagicMock()
    existing_row.protocol_id = None
    existing_row.deployer = None

    intake_calls: list[tuple] = []
    monkeypatch.setattr(
        "workers.discovery._gate_intake",
        lambda session, job, contract, request: intake_calls.append((contract, request)),
    )

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = existing_row
    job = _job(protocol_id=1, request={"discovery_sources": ["inventory"]})

    worker._process_address(session, job)

    assert len(intake_calls) == 1
    assert intake_calls[0][0] is existing_row
    assert existing_row.protocol_id is None


def test_fetch_path_never_stamps_protocol_id_at_write(monkeypatch):
    """The new-row arm writes ``protocol_id=None`` regardless of the job's
    protocol or its request sources — membership is earned in the gate, never
    conferred by a source's identity."""
    from services.concurrency import RpcExecutor

    RpcExecutor.reset_for_tests()
    result = _etherscan_result()
    _patch_discovery(monkeypatch, result)

    monkeypatch.setattr("workers.discovery.find_completed_static_cache", lambda *a, **kw: None)

    intake_calls: list[tuple] = []
    monkeypatch.setattr(
        "workers.discovery._gate_intake",
        lambda session, job, contract, request: intake_calls.append((contract, request)),
    )

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job(protocol_id=1, request={"discovery_sources": ["defillama", "inventory"]})

    worker._process_address(session, job)

    contract = session.add.call_args[0][0]
    assert contract.protocol_id is None
    assert contract.discovery_sources == ["defillama", "inventory"]
    assert len(intake_calls) == 1
    assert intake_calls[0][0] is contract


def test_process_address_failed_creators_keeps_prior_deployer(monkeypatch):
    """None means the lookup answered nothing, not that there is no deployer."""
    from services.concurrency import RpcExecutor

    RpcExecutor.reset_for_tests()
    result = _etherscan_result()
    _patch_discovery(monkeypatch, result)

    monkeypatch.setattr("workers.discovery.fetch", lambda _addr, **_kw: result)

    def boom(_addrs, **_kw):
        raise RuntimeError("creators API down")

    monkeypatch.setattr("workers.discovery._batch_get_creators", boom)

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    existing_row = MagicMock()
    existing_row.deployer = "0x0463e60c7ce10e57911ab7bd1667eaa21de3e79b"
    existing_row.protocol_id = 1
    existing_row.discovery_sources = ["inventory"]
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = existing_row
    job = _job()

    worker._process_address(session, job)

    assert existing_row.deployer == "0x0463e60c7ce10e57911ab7bd1667eaa21de3e79b"


def test_process_address_fanout_propagates_fetch_exception(monkeypatch):
    from services.concurrency import RpcExecutor

    RpcExecutor.reset_for_tests()
    monkeypatch.setattr(
        "workers.discovery.fetch",
        MagicMock(side_effect=RuntimeError("etherscan rate-limited")),
    )
    monkeypatch.setattr("workers.discovery._batch_get_creators", lambda addrs: {})
    monkeypatch.setattr("workers.discovery.store_source_files", lambda *a, **kw: None)
    monkeypatch.setattr("workers.discovery.store_artifact", lambda *a, **kw: None)

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    import pytest

    with pytest.raises(RuntimeError, match="etherscan rate-limited"):
        worker._process_address(session, job)
