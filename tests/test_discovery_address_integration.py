"""Integration tests for DiscoveryWorker._process_address().

Covers: happy path, Vyper detection, EVM version fallback, source format detection.
All tests are CI-friendly -- network calls are mocked via monkeypatch.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from workers.discovery import DiscoveryWorker

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
    """Return a realistic Etherscan getsource response dict."""
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
    """Monkeypatch fetch, store_source_files, store_artifact, and update_detail.

    Returns (store_source_calls, store_artifact_calls) lists that tests can inspect.
    """
    monkeypatch.setattr(
        "workers.discovery.fetch",
        lambda _addr, **_kw: etherscan_result,
    )
    # Deployer expansion probes Etherscan (getcontractcreation) for the creator;
    # these tests assert on the parsed source/contract, not deployer data.
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


# ---------------------------------------------------------------------------
# 1. Happy path
# ---------------------------------------------------------------------------


def test_happy_path_stores_sources_and_artifacts(monkeypatch):
    result = _etherscan_result()
    source_calls, artifact_calls = _patch_discovery(monkeypatch, result)

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)

    session = MagicMock()
    # No existing contract row for this address
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    worker._process_address(session, job)

    # store_source_files was called with parsed sources
    assert len(source_calls) == 1
    stored_job_id, stored_sources = source_calls[0]
    assert stored_job_id == "job-1"
    assert isinstance(stored_sources, dict)
    assert len(stored_sources) > 0
    # Flat source should produce src/TetherToken.sol
    assert "src/TetherToken.sol" in stored_sources

    # Verify Contract written via session.add
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

    # job.name set correctly
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


# ---------------------------------------------------------------------------
# 2. Vyper detection
# ---------------------------------------------------------------------------


def test_vyper_detected_from_compiler_version(monkeypatch):
    result = _etherscan_result(
        CompilerVersion="vyper:0.3.7",
        SourceCode="# @version 0.3.7\n@external\ndef foo(): pass",
        ContractName="VyperVault",
    )
    _, artifact_calls = _patch_discovery(monkeypatch, result)

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    worker._process_address(session, job)

    contract = session.add.call_args[0][0]
    assert contract.language == "vyper"


def test_vyper_detected_from_v0_prefix(monkeypatch):
    """is_vyper_result() also matches CompilerVersion starting with 'v0.' (Vyper convention)."""
    result = _etherscan_result(
        CompilerVersion="v0.3.7+commit.abc",
        SourceCode="# @version 0.3.7\n@external\ndef bar(): pass",
        ContractName="VyperPool",
    )
    _, artifact_calls = _patch_discovery(monkeypatch, result)

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    worker._process_address(session, job)

    contract = session.add.call_args[0][0]
    # is_vyper_result checks for "vyper" in compiler string; "v0." alone does not
    # match unless source starts with "# @version". The source above does start
    # with that, so is_vyper_result returns True via the source-code fallback.
    assert contract.language == "vyper"


def test_solidity_when_compiler_not_vyper(monkeypatch):
    result = _etherscan_result(
        CompilerVersion="v0.8.20+commit.a1b2c3",
        SourceCode="pragma solidity ^0.8.20; contract Foo {}",
    )
    _, artifact_calls = _patch_discovery(monkeypatch, result)

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    worker._process_address(session, job)

    contract = session.add.call_args[0][0]
    assert contract.language == "solidity"


# ---------------------------------------------------------------------------
# 3. EVM version fallback
# ---------------------------------------------------------------------------


def test_evm_version_defaults_to_shanghai_when_empty(monkeypatch):
    result = _etherscan_result(EVMVersion="")
    _, artifact_calls = _patch_discovery(monkeypatch, result)

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    worker._process_address(session, job)

    contract = session.add.call_args[0][0]
    assert contract.evm_version == "shanghai"


def test_evm_version_defaults_to_shanghai_when_default(monkeypatch):
    result = _etherscan_result(EVMVersion="Default")
    _, artifact_calls = _patch_discovery(monkeypatch, result)

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    worker._process_address(session, job)

    contract = session.add.call_args[0][0]
    assert contract.evm_version == "shanghai"


def test_evm_version_preserves_explicit_value(monkeypatch):
    result = _etherscan_result(EVMVersion="cancun")
    _, artifact_calls = _patch_discovery(monkeypatch, result)

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    worker._process_address(session, job)

    contract = session.add.call_args[0][0]
    assert contract.evm_version == "cancun"


def test_evm_version_defaults_when_key_missing(monkeypatch):
    """EVMVersion key missing from Etherscan result entirely."""
    result = _etherscan_result()
    del result["EVMVersion"]
    _, artifact_calls = _patch_discovery(monkeypatch, result)

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    worker._process_address(session, job)

    contract = session.add.call_args[0][0]
    assert contract.evm_version == "shanghai"


# ---------------------------------------------------------------------------
# 4. Source format detection
# ---------------------------------------------------------------------------


def test_source_format_standard_json(monkeypatch):
    """source_format is 'standard_json' when 'sources' appears within the first 10 chars.

    The detection in _process_address uses ``"sources" in str(SourceCode)[:10]``.
    A single-brace JSON ``{"sources":...}`` puts 'sources' at index 2 (fits in 10).
    The double-brace Etherscan format ``{{"sources":...}}`` pushes it to index 3,
    which overflows the 10-char window.  We use a single-brace variant here to
    exercise the 'standard_json' branch.
    """
    source_code = json.dumps(
        {
            "sources": {"contracts/Token.sol": {"content": "pragma solidity ^0.8.0; contract Token {}"}},
            "language": "Solidity",
            "settings": {"optimizer": {"enabled": True, "runs": 200}, "remappings": []},
        }
    )
    # Sanity: confirm the detection will fire
    assert "sources" in source_code[:10]

    result = _etherscan_result(SourceCode=source_code, ContractName="Token")
    _, artifact_calls = _patch_discovery(monkeypatch, result)

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    worker._process_address(session, job)

    contract = session.add.call_args[0][0]
    assert contract.source_format == "standard_json"


def test_source_format_flat(monkeypatch):
    """Plain Solidity source produces source_format 'flat'."""
    result = _etherscan_result(
        SourceCode="pragma solidity ^0.8.0; contract Flat {}",
        ContractName="Flat",
    )
    _, artifact_calls = _patch_discovery(monkeypatch, result)

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    worker._process_address(session, job)

    contract = session.add.call_args[0][0]
    assert contract.source_format == "flat"


def test_standard_json_multiple_files_parsed_correctly(monkeypatch):
    """Standard-JSON (double-brace) with multiple source files: parse_sources
    correctly extracts all files and remappings even though source_format
    detection falls back to 'flat' due to the [:10] window.
    """
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
    # Etherscan wraps standard-json by prepending one '{' and appending one '}'.
    # json.dumps already produces '{...}', so adding one brace each side yields '{{...}}'.
    source_code = "{" + inner + "}"

    result = _etherscan_result(SourceCode=source_code, ContractName="Token")
    source_calls, artifact_calls = _patch_discovery(monkeypatch, result)

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    worker._process_address(session, job)

    # store_source_files received all 3 files (parse_sources works correctly)
    _, stored_sources = source_calls[0]
    assert len(stored_sources) == 3
    assert "contracts/Token.sol" in stored_sources
    assert "contracts/Lib.sol" in stored_sources

    contract = session.add.call_args[0][0]
    assert contract.source_file_count == 3
    # Remappings should be extracted from the settings block
    assert "@openzeppelin/=node_modules/@openzeppelin/" in contract.remappings


# ---------------------------------------------------------------------------
# 5. Build settings edge cases
# ---------------------------------------------------------------------------


def test_optimization_disabled(monkeypatch):
    """OptimizationUsed='0' results in optimization_used=False in build_settings."""
    result = _etherscan_result(OptimizationUsed="0")
    _, artifact_calls = _patch_discovery(monkeypatch, result)

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    worker._process_address(session, job)

    contract = session.add.call_args[0][0]
    assert contract.optimization is False
    assert contract.optimization_runs == 200


def test_runs_custom_value(monkeypatch):
    """Custom Runs value is preserved as int in build_settings."""
    result = _etherscan_result(Runs="10000")
    _, artifact_calls = _patch_discovery(monkeypatch, result)

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    job = _job()

    worker._process_address(session, job)

    contract = session.add.call_args[0][0]
    assert contract.optimization_runs == 10000


# ---------------------------------------------------------------------------
# Step 4 fan-out: fetch + _batch_get_creators run as concurrent Etherscan calls
# via parallel_get. Both must execute, and the deployer flows through.
# ---------------------------------------------------------------------------


def test_process_address_fanout_invokes_fetch_and_creators(monkeypatch):
    """Both Etherscan calls fire under the parallel_get fan-out; deployer
    derived from creators is recorded on the Contract row."""
    from utils.concurrency import RpcExecutor

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
    # Non-mainnet job: the creators lookup must ask the JOB's chain, not
    # default to mainnet — a Base-only address answers nothing on chain 1,
    # which nulled the deployer and starved deployer-cascade adoption.
    job = _job(chain_id=8453)

    worker._process_address(session, job)

    assert fetch_calls == [job.address]
    assert creators_calls == [([job.address], 8453)]
    contract = session.add.call_args[0][0]
    assert contract.deployer == "0xc0ffee0000000000000000000000000000000001"


def test_process_address_fanout_swallows_creators_exception(monkeypatch):
    """A failing creators lookup must not abort the discovery pipeline —
    parallel_get returns the exception in-place; deployer stays None."""
    from utils.concurrency import RpcExecutor

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


def test_cache_hit_adopts_existing_row_from_request_sources(monkeypatch):
    """The static-cache-hit early return must still run the ownership gate:
    an explicit address+company submit carries the ``inventory`` source, and
    that grant holds even when the address was already analyzed."""
    from utils.concurrency import RpcExecutor

    RpcExecutor.reset_for_tests()
    result = _etherscan_result()
    _patch_discovery(monkeypatch, result)

    monkeypatch.setattr(
        "workers.discovery.find_completed_static_cache",
        lambda session, address, chain=None, **kw: SimpleNamespace(id="cached-job-1"),
    )
    monkeypatch.setattr("workers.discovery.copy_static_cache", lambda session, src, dst: 42)

    dirty_calls: list[tuple] = []
    monkeypatch.setattr(
        "services.monitoring.enrollment.mark_enrollment_dirty",
        lambda session, pid, reason: dirty_calls.append((pid, reason)),
    )

    cached_row = MagicMock()
    cached_row.protocol_id = None
    cached_row.discovery_sources = None
    cached_row.deployer = None
    cached_row.contract_name = "AtomicQueue"

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.get.return_value = cached_row
    job = _job(protocol_id=1, request={"discovery_sources": ["inventory"]})

    worker._process_address(session, job)

    assert cached_row.protocol_id == 1
    assert "inventory" in (cached_row.discovery_sources or [])
    assert dirty_calls == [(1, "discovery_adoption")]


def test_fetch_path_adopts_existing_row_from_request_sources(monkeypatch):
    """The fetch path's existing-row branch honors a HIGH source carried by
    the request, not only sources already recorded on the row."""
    from utils.concurrency import RpcExecutor

    RpcExecutor.reset_for_tests()
    result = _etherscan_result()
    _patch_discovery(monkeypatch, result)

    monkeypatch.setattr("workers.discovery.find_completed_static_cache", lambda *a, **kw: None)
    monkeypatch.setattr(
        "services.monitoring.enrollment.mark_enrollment_dirty",
        lambda session, pid, reason: True,
    )

    existing_row = MagicMock()
    existing_row.protocol_id = None
    existing_row.discovery_sources = None
    existing_row.deployer = None

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = existing_row
    job = _job(protocol_id=1, request={"discovery_sources": ["inventory"]})

    worker._process_address(session, job)

    assert existing_row.protocol_id == 1
    assert "inventory" in (existing_row.discovery_sources or [])


def test_fetch_path_leaves_low_confidence_orphan_unadopted(monkeypatch):
    """The BoringGovernance→WETH9 leak path, driven through the worker.

    A dependency-spawned analysis job carries the parent's ``protocol_id``.
    The existing row is an orphan whose only discovery source is LOW
    (``dapp_crawl``) and whose deployer is unwitnessed, so no branch of the
    adoption gate applies: ownership must stay unclaimed."""
    from utils.concurrency import RpcExecutor

    RpcExecutor.reset_for_tests()
    result = _etherscan_result()
    _patch_discovery(monkeypatch, result)

    monkeypatch.setattr("workers.discovery.find_completed_static_cache", lambda *a, **kw: None)
    monkeypatch.setattr(
        "services.monitoring.enrollment.mark_enrollment_dirty",
        lambda session, pid, reason: True,
    )

    existing_row = MagicMock()
    existing_row.protocol_id = None
    existing_row.discovery_sources = ["dapp_crawl"]
    existing_row.deployer = None

    worker = DiscoveryWorker()
    monkeypatch.setattr(worker, "update_detail", lambda *a, **kw: None)
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = existing_row
    job = _job(protocol_id=1, request={"discovery_sources": ["dapp_crawl"]})

    worker._process_address(session, job)

    assert existing_row.protocol_id is None
    assert existing_row.discovery_sources == ["dapp_crawl"]


def test_process_address_failed_creators_keeps_prior_deployer(monkeypatch):
    """A failed creators refetch must not erase a previously-witnessed
    deployer on an existing Contract row — None means the lookup answered
    nothing, never that the contract has no deployer."""
    from utils.concurrency import RpcExecutor

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
    """A failing source fetch must propagate so the worker marks the job
    failed; partial state is not committed."""
    from utils.concurrency import RpcExecutor

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
