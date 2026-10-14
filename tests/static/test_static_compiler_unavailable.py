"""A static job whose build failed without its solc release on disk is retried; one whose installed compiler rejected
the source fails terminally.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from services.discovery.fetch import CompilerUnavailableError
from tests.support import label_corpus
from workers.retry_policy import classify
from workers.static_worker import StaticWorker

pytestmark = pytest.mark.compile

SOLC = "0.8.27"


def _process(monkeypatch, source: str) -> None:
    worker = StaticWorker()
    session = MagicMock()
    monkeypatch.setattr("workers.static_worker.get_source_files", lambda _s, _j: {"src/C.sol": source})
    monkeypatch.setattr("workers.static_worker.store_artifact", lambda *_a, **_k: None)
    session.execute.return_value.scalar_one_or_none.return_value = SimpleNamespace(
        address="0x" + "c1" * 20,
        contract_name="C",
        compiler_version=f"v{SOLC}+commit.40a35a09",
        language="solidity",
        evm_version="cancun",
        optimization=True,
        optimization_runs=200,
        via_ir=False,
        source_format="flat",
        source_file_count=1,
        remappings=[],
        is_proxy=False,
        source_verified=True,
    )
    monkeypatch.setattr(worker, "_resolve_proxy", lambda *_a, **_k: None)
    monkeypatch.setattr(worker, "_run_dependency_phase", lambda *_a, **_k: None)
    monkeypatch.setattr(worker, "update_detail", lambda *_a, **_k: None)
    job = SimpleNamespace(id="job-1", address="0x" + "c1" * 20, name="C", request={}, chain_id=1)
    worker.process(session, job)  # pyright: ignore[reportArgumentType]


@pytest.fixture()
def _offline(monkeypatch):
    monkeypatch.setenv("FOUNDRY_OFFLINE", "true")


def test_a_build_without_its_compiler_on_disk_is_retried(monkeypatch, tmp_path, _offline):
    monkeypatch.setenv("FOUNDRY_SOLC", str(tmp_path / "missing-solc"))
    with pytest.raises(CompilerUnavailableError) as raised:
        _process(monkeypatch, "pragma solidity ^0.8.20;\ncontract C { uint256 public x; }\n")
    assert classify(raised.value) == "transient"


def test_a_source_the_installed_compiler_rejects_fails_terminally(monkeypatch, _offline):
    binary = label_corpus._solc_select_binary(SOLC)
    if not binary.exists():
        raise AssertionError(f"solc {SOLC} is not provisioned at {binary}; CI installs it in _ci-checks.yml.")
    monkeypatch.setenv("FOUNDRY_SOLC", str(binary))
    with pytest.raises(RuntimeError, match="Contract analysis failed") as raised:
        _process(monkeypatch, "pragma solidity ^0.8.20;\ncontract C { function f( }\n")
    assert not isinstance(raised.value, CompilerUnavailableError)
    assert classify(raised.value) == "terminal"
