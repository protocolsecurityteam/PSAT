"""The production boundary publishes formulas, while input failures abort it."""

import importlib
from types import SimpleNamespace

import pytest

from services.logic import deployment
from services.logic.model import ReadError


def test_missing_source_is_not_verified_not_an_empty_complete_result(monkeypatch):
    monkeypatch.setattr(importlib.import_module("services.discovery.fetch"), "fetch", lambda *a, **kw: None)
    monkeypatch.setattr("services.clients.rpc.rpc_request", lambda *a, **kw: "0x7b")
    session = SimpleNamespace(execute=lambda *a, **kw: SimpleNamespace(first=lambda: None))
    result = deployment.deployment_formulas(session, "0x" + "01" * 20, 1, "http://127.0.0.1")
    assert result["schema"] == 2 and result["block"] == 123
    assert result["status"] == "not_verified" and result["functions"] == {}


def test_source_transport_failure_does_not_publish_not_verified(monkeypatch, tmp_path):
    def source(address):
        raise ReadError("source server unavailable")

    builds = deployment.Builds(source, lambda address: None, tmp_path)
    with pytest.raises(ReadError):
        builds.get(1)
    assert builds._built == {}


def test_a_build_error_is_not_silently_converted_to_missing_source(monkeypatch, tmp_path):
    monkeypatch.setattr(importlib.import_module("services.discovery.fetch"), "scaffold", lambda *a: None)

    def parse(*a):
        raise KeyError("compiler failure")

    monkeypatch.setattr(deployment, "parse_project", parse)
    builds = deployment.Builds(
        lambda address: {"ContractName": "C", "SourceCode": "code"}, lambda address: None, tmp_path
    )
    with pytest.raises(KeyError, match="compiler failure"):
        builds.get(1)
    assert builds._built == {}


def test_resolution_uses_the_new_artifact_producer(monkeypatch):
    from workers import resolution_worker

    calls = []
    session = SimpleNamespace(__enter__=lambda self: self, __exit__=lambda *a: None)

    class Session:
        def __enter__(self):
            return session

        def __exit__(self, *args):
            return False

    monkeypatch.setattr("db.models.SessionLocal", Session)
    monkeypatch.setattr(deployment, "deployment_formulas", lambda *args: calls.append(args) or {"schema": 2})
    assert resolution_worker._logic_verdicts_isolated("0xABC", 1, "local") == {"schema": 2}
    assert calls == [(session, "0xabc", 1, "local")]


def test_runtime_has_no_execution_or_override_rpc():
    import ast
    from pathlib import Path

    root = Path(deployment.__file__).parent
    forbidden = {"eth_call", "anvil_setStorageAt", "evm_snapshot", "evm_revert"}
    for path in [*root.glob("*.py"), root.parent / "clients" / "logic_reads.py"]:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                assert not any(
                    isinstance(a, ast.Constant) and isinstance(a.value, str) and a.value in forbidden for a in node.args
                ), (path, node.lineno)
