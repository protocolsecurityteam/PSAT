"""DB-free parity for the parallel ``_apply_equivalence_http`` path, with both HTTP calls stubbed."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from services.audits.coverage import CoverageMatch, _apply_equivalence_http, _EquivalenceInputs
from services.concurrency import RpcExecutor
from tests.support.isolation import _reset_executor  # noqa: F401  (fixture, registered by import)


def _make_match(audit_id: int, contract_id: int, name: str = "MyPool") -> CoverageMatch:
    return CoverageMatch(
        audit_report_id=audit_id,
        contract_id=contract_id,
        protocol_id=1,
        matched_name=name,
        match_type="direct",
        match_confidence="medium",
    )


def _make_inputs(audit_id: int, contract_id: int, address: str) -> _EquivalenceInputs:
    return _EquivalenceInputs(
        audit_report_id=audit_id,
        contract_id=contract_id,
        contract_chain="ethereum",
        contract_address=address,
        reviewed_commits=("abc1234",),
        scope_contracts=("MyPool",),
        source_repo="example/repo",
        referenced_repos=(),
        classified_commits=(),
        db_impl_source=None,
    )


def _stub_etherscan_and_github(monkeypatch, *, etherscan_calls=None, github_calls=None):
    """The imports happen inside the function body, so patch the source module."""
    from services.audits import source_equivalence

    fake_fetch = source_equivalence.EtherscanFetch(
        source=source_equivalence.VerifiedSource(
            contract_name="MyPool",
            compiler_version="0.8.27",
            files={"src/MyPool.sol": "deadbeef"},
        ),
        status="ok",
        detail="",
    )

    def fake_fetch_etherscan(addr, **_kw):
        if etherscan_calls is not None:
            etherscan_calls.append(addr)
        return fake_fetch

    fake_outcome = MagicMock()
    fake_outcome.status = "proven"
    fake_outcome.reason = "all hashes match"
    fake_outcome.matches = [MagicMock(commit="abc1234")]

    def fake_verify(**kwargs):
        if github_calls is not None:
            github_calls.append(kwargs.get("scope_name"))
        return fake_outcome

    monkeypatch.setattr(source_equivalence, "fetch_etherscan_source_files", fake_fetch_etherscan)
    monkeypatch.setattr(source_equivalence, "verify_audit_covers_impl", fake_verify)


def _run(monkeypatch, fanout: str, n_matches: int, shared_address: str | None = None) -> list[Any]:
    monkeypatch.setenv("PSAT_RPC_FANOUT", fanout)
    RpcExecutor.reset_for_tests()
    matches = [_make_match(audit_id=i, contract_id=i) for i in range(n_matches)]
    inputs = {
        (m.audit_report_id, m.contract_id): _make_inputs(
            m.audit_report_id,
            m.contract_id,
            shared_address or f"0x{i:040x}",
        )
        for i, m in enumerate(matches)
    }
    _stub_etherscan_and_github(monkeypatch)
    return _apply_equivalence_http(matches, inputs)


def _canonical(stamped):
    return [
        (
            r.audit_report_id,
            r.contract_id,
            r.equivalence_status,
            r.equivalence_reason,
            r.match_type,
            r.match_confidence,
            r.proof_kind,
            r.matched_commit_sha,
        )
        for r in stamped
    ]


def test_apply_equivalence_http_parity_parallel_vs_sequential(monkeypatch):
    seq = _run(monkeypatch, "1", n_matches=12)
    par = _run(monkeypatch, "8", n_matches=12)
    assert _canonical(seq) == _canonical(par)


def test_apply_equivalence_http_caches_etherscan_per_address(monkeypatch):
    monkeypatch.setenv("PSAT_RPC_FANOUT", "8")
    RpcExecutor.reset_for_tests()

    addr = "0x" + "ab" * 20
    matches = [_make_match(audit_id=i, contract_id=i) for i in range(8)]
    inputs = {(m.audit_report_id, m.contract_id): _make_inputs(m.audit_report_id, m.contract_id, addr) for m in matches}

    etherscan_calls: list[str] = []
    _stub_etherscan_and_github(monkeypatch, etherscan_calls=etherscan_calls)

    stamped = _apply_equivalence_http(matches, inputs)

    # The lock + setdefault discards a first-write race loser.
    assert len(etherscan_calls) <= 2, (
        f"expected ≤2 Etherscan calls for one shared address, got {len(etherscan_calls)}: {etherscan_calls}"
    )
    assert all(s.equivalence_status == "proven" for s in stamped)


def test_apply_equivalence_http_per_match_crash_does_not_abort_siblings(monkeypatch):
    monkeypatch.setenv("PSAT_RPC_FANOUT", "8")
    RpcExecutor.reset_for_tests()

    matches = [_make_match(audit_id=i, contract_id=i) for i in range(6)]
    inputs = {
        (m.audit_report_id, m.contract_id): _make_inputs(m.audit_report_id, m.contract_id, f"0x{i:040x}")
        for i, m in enumerate(matches)
    }

    from services.audits import source_equivalence

    fake_fetch = source_equivalence.EtherscanFetch(
        source=source_equivalence.VerifiedSource(
            contract_name="MyPool",
            compiler_version="0.8",
            files={"src/MyPool.sol": "deadbeef"},
        ),
        status="ok",
        detail="",
    )

    monkeypatch.setattr(source_equivalence, "fetch_etherscan_source_files", lambda _addr, **_kw: fake_fetch)

    fake_outcome = MagicMock()
    fake_outcome.status = "proven"
    fake_outcome.reason = "ok"
    fake_outcome.matches = [MagicMock(commit="abc1234")]

    bad_audit_id = matches[2].audit_report_id

    def fake_verify(**kwargs):
        commits = kwargs.get("reviewed_commits") or []
        if commits and commits[0] == "boom":
            raise RuntimeError("github fetch crashed")
        return fake_outcome

    monkeypatch.setattr(source_equivalence, "verify_audit_covers_impl", fake_verify)

    inputs[(bad_audit_id, matches[2].contract_id)] = _EquivalenceInputs(
        audit_report_id=bad_audit_id,
        contract_id=matches[2].contract_id,
        contract_chain="ethereum",
        contract_address=f"0x{2:040x}",
        reviewed_commits=("boom",),
        scope_contracts=("MyPool",),
        source_repo="example/repo",
        referenced_repos=(),
        classified_commits=(),
        db_impl_source=None,
    )

    stamped = _apply_equivalence_http(matches, inputs)

    by_audit = {s.audit_report_id: s for s in stamped}
    assert by_audit[bad_audit_id].equivalence_status == "github_fetch_failed"
    assert "github fetch crashed" in (by_audit[bad_audit_id].equivalence_reason or "")
    for m in matches:
        if m.audit_report_id == bad_audit_id:
            continue
        assert by_audit[m.audit_report_id].equivalence_status == "proven"
