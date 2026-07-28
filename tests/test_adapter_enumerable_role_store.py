"""EnumerableRoleStoreAdapter — resolves a delegated ``registry.onlyX(msg.sender)``
gate to its real controllers by folding the role-store standard's indexed events
and confirming each candidate against the live gate (pinned-block probe).

Wire-stubbed the way the offline suite requires: ``rpc_request`` is stubbed (the
Multicall3 gate-probe rides it), NOT the adapter or repo classes; indexed events +
cursors are seeded into the real Postgres via the real ``PostgresEventLogRepo``.
Standard detection's ``get_code`` is stubbed in ``role_store_standards`` and the
proxy→impl hop comes from a seeded ``Contract`` row (mirrors the Stage-1 enroll
tests).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest
from eth_abi.abi import decode as abi_decode
from eth_abi.abi import encode as abi_encode
from eth_utils.crypto import keccak

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import services.resolution.role_store_standards as rss  # noqa: E402
from services.policy.capability_surface import project_capability_surface  # noqa: E402
from services.resolution.adapters import AdapterRegistry, EvaluationContext  # noqa: E402
from services.resolution.adapters.enumerable_role_store import (  # noqa: E402
    _NEGATIVE_CONTROL_ADDR,
    EnumerableRoleStoreAdapter,
)
from services.resolution.adapters.event_indexed import EventIndexedAdapter  # noqa: E402
from services.resolution.adapters.solmate_roles import SolmateRolesAuthorityAdapter  # noqa: E402
from services.resolution.capability_resolver import capability_to_dict  # noqa: E402
from services.resolution.repos.event_logs_pg import PostgresEventLogRepo  # noqa: E402
from services.resolution.role_store_standards import (  # noqa: E402
    OZ_ACCESS_CONTROL_ENUMERABLE,
    SOLADY_ENUMERABLE_ROLES,
)
from utils.logging import stage_metrics_var  # noqa: E402

_PROXY = "0x" + "62" * 20  # registry proxy — where RoleSet is emitted
_IMPL = "0x" + "3b" * 20  # role-store impl behind the proxy
_MULTISIG = "0x2aca71020de61bb532008049e1bd41e451ae8adc"  # OPERATION_MULTISIG holder (ground truth)
_TIMELOCK = "0xcd425f44758a08baab3c4908f3e3de5776e45d7a"
_STRANGER = "0x" + "99" * 20  # granted then revoked / never a member
_CURSOR_BLOCK = 25_000_000
_PROBE_BLOCK = 24_900_000  # <= cursor so the fold is exact-covered

_ROLE_SET = SOLADY_ENUMERABLE_ROLES.grant_events[0].topic0
_OZ_GRANTED = OZ_ACCESS_CONTROL_ENUMERABLE.grant_events[0].topic0
_OZ_REVOKED = OZ_ACCESS_CONTROL_ENUMERABLE.grant_events[1].topic0
_ROLE_1 = 1  # OPERATION_MULTISIG_ROLE (Solady uint256 id)

_CALLEE_SIG = "onlyOperatingMultisig(address)"
_CALLEE_SELECTOR = "0x" + keccak(text=_CALLEE_SIG).hex()[:8]


# The adapter itself does not branch on earned-public, but every behavior-bearing
# test runs under both flag states; this makes that explicit.
@pytest.fixture(params=["1", "0"], ids=["earned_on", "earned_off"])
def both_flags(request, monkeypatch):
    monkeypatch.setenv("PSAT_AUTHORITY_EARNED_PUBLIC", request.param)
    return request.param


# ---------------------------------------------------------------------------
# DB session
# ---------------------------------------------------------------------------

_DB_URL: str = os.environ.get("TEST_DATABASE_URL", os.environ.get("DATABASE_URL", "")) or ""


def _can_connect() -> bool:
    if not _DB_URL:
        return False
    try:
        from sqlalchemy import create_engine, text

        engine = create_engine(_DB_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


requires_postgres = pytest.mark.skipif(not _can_connect(), reason="PostgreSQL not available")


@pytest.fixture()
def session():
    if not _can_connect():
        pytest.skip("PostgreSQL not available")
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from db.models import Contract, ControllerValue, IndexedEventCursor, IndexedEventLog

    engine = create_engine(_DB_URL)
    s = Session(engine, expire_on_commit=False)

    def _wipe():
        for model in (IndexedEventLog, IndexedEventCursor, ControllerValue, Contract):
            s.query(model).delete()
        s.commit()

    _wipe()
    try:
        yield s
    finally:
        s.rollback()
        _wipe()
        s.close()
        engine.dispose()


# ---------------------------------------------------------------------------
# Seeding helpers
# ---------------------------------------------------------------------------


def _word(value: int) -> str:
    return "0x" + format(value, "064x")


def _addr_word(address: str) -> str:
    return "0x" + address.lower().removeprefix("0x").rjust(64, "0")


def _roleset_topics(holder: str, role: int, active: bool) -> list[str]:
    # RoleSet(address indexed holder, uint256 indexed role, bool indexed active)
    return [_ROLE_SET, _addr_word(holder), _word(role), _word(1 if active else 0)]


def _oz_topics(topic0: str, role: int, account: str) -> list[str]:
    # RoleGranted/RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)
    return [topic0, _word(role), _addr_word(account), _addr_word("0x" + "01" * 20)]


def _seed_log(session, *, topics: list[str], block: int, log_index: int) -> None:
    from db.models import IndexedEventLog

    session.add(
        IndexedEventLog(
            chain_id=1,
            event_address=_PROXY.lower(),
            topic0=topics[0].lower(),
            tx_hash=(block * 10_000 + log_index).to_bytes(32, "big"),
            log_index=log_index,
            block_number=block,
            block_hash=block.to_bytes(32, "big"),
            transaction_index=0,
            topics=topics,
            data_words=[],
        )
    )


def _seed_cursor(session, topic0: str, *, complete: bool = True, block: int = _CURSOR_BLOCK) -> None:
    from db.models import IndexedEventCursor

    session.add(
        IndexedEventCursor(
            chain_id=1,
            event_address=_PROXY.lower(),
            topic0=topic0.lower(),
            last_indexed_block=block,
            backfill_complete=complete,
        )
    )


def _seed_proxy_impl(session) -> None:
    from db.models import Contract

    session.add(Contract(address=_PROXY, implementation=_IMPL, is_proxy=True, chain="ethereum"))


def _code_with(*selectors: str) -> str:
    return "0x" + "".join("63" + s.removeprefix("0x") for s in selectors)


def _stub_probe_code(monkeypatch, code_for_impl: str) -> None:
    """resolve_probe_code's ``get_code`` returns ``code_for_impl`` at the impl; the
    DB Contract row supplies the proxy→impl hop so no slot read fires."""

    def _fake_get_code(rpc_url, address, *, chain_id=None):
        return code_for_impl if address.lower() == _IMPL.lower() else "0x00"

    monkeypatch.setattr(rss, "get_code", _fake_get_code)
    # Disable the EIP-1967 slot fallback hop (the DB Contract row is the proxy→impl
    # linkage) so detection never reaches for the wire.
    monkeypatch.setattr(rss, "rpc_request", lambda *a, **k: None)


# ---------------------------------------------------------------------------
# Multicall3 rpc_request stub — decodes aggregate3 calldata, answers per sub-call
# ---------------------------------------------------------------------------


def _install_probe_stub(
    monkeypatch,
    *,
    members: set[str],
    control_passes: bool = False,
    transport_fail: bool = False,
    getter_holders: dict[int, list[str]] | None = None,
    head_block: int = _CURSOR_BLOCK,
    blocknumber_fail: bool = False,
) -> None:
    gate_sel = keccak(text=_CALLEE_SIG).hex()[:8]
    getter = SOLADY_ENUMERABLE_ROLES.enumerable_getter
    assert getter is not None
    count_sel = getter.count_selector.removeprefix("0x")
    at_sel = getter.at_selector.removeprefix("0x")
    members_l = {m.lower() for m in members}
    control_l = _NEGATIVE_CONTROL_ADDR.lower()

    def _stub(rpc_url, method, params=None, **kwargs):
        if method == "eth_blockNumber":
            # Pin-once height read for the ctx.block-None path.
            if blocknumber_fail:
                raise RuntimeError("stubbed eth_blockNumber failure")
            return hex(head_block)
        if transport_fail:
            raise RuntimeError("stubbed transport failure")
        assert method == "eth_call"
        assert params is not None
        data = params[0]["data"]
        body = bytes.fromhex(data[10:])  # strip 0x + 4-byte aggregate3 selector
        calls = abi_decode(["(address,bool,bytes)[]"], body)[0]
        results: list[tuple[bool, bytes]] = []
        for _target, _allow, calldata in calls:
            sel = calldata[:4].hex()
            arg0 = calldata[4:36]
            addr = "0x" + arg0[-20:].hex()
            if sel == gate_sel:
                if addr == control_l:
                    results.append((control_passes, b""))
                else:
                    results.append((addr in members_l, b""))
            elif sel == count_sel:
                role = int.from_bytes(arg0, "big")
                n = len((getter_holders or {}).get(role, []))
                results.append((True, n.to_bytes(32, "big")))
            elif sel == at_sel:
                role = int.from_bytes(arg0, "big")
                idx = int.from_bytes(calldata[36:68], "big")
                holders = (getter_holders or {}).get(role, [])
                addr_h = holders[idx] if idx < len(holders) else "0x" + "00" * 20
                results.append((True, bytes(12) + bytes.fromhex(addr_h.removeprefix("0x"))))
            else:
                results.append((False, b""))
        encoded = abi_encode(["(bool,bytes)[]"], [results])
        return "0x" + encoded.hex()

    # Patch the wire only: the real ``multicall3_aggregate3`` (its aggregate3
    # encode/decode) runs against this stubbed ``rpc_request``. Patch the adapter's
    # imported reference too so the pin-once eth_blockNumber read is stubbed.
    import services.resolution.adapters.enumerable_role_store as _ers
    import utils.rpc as _rpc

    monkeypatch.setattr(_rpc, "rpc_request", _stub)
    monkeypatch.setattr(_ers, "rpc_request", _stub)


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------


def _descriptor(*, callee_sig: str = _CALLEE_SIG, key_source: str = "msg_sender", authority: str | None = _PROXY):
    desc: dict[str, Any] = {
        "kind": "external_set",
        "callee_signature": callee_sig,
        "key_sources": [{"source": key_source, "state_variable_name": "owner"}],
        "authority_contract": ({"address": authority} if authority else {}),
    }
    return desc


def _extra(cap) -> dict:
    assert cap.check is not None
    return cap.check.extra or {}


def _ctx(session, *, block: int | None = _PROBE_BLOCK) -> EvaluationContext:
    return EvaluationContext(
        chain_id=1,
        contract_address="0x" + "11" * 20,
        block=block,
        event_log_repo=PostgresEventLogRepo(session),
        rpc_url="http://stub.invalid",
        state_var_values={},
        session=session,
        meta={"live_read_memo": {}},
    )


# ---------------------------------------------------------------------------
# matches()
# ---------------------------------------------------------------------------


@requires_postgres
def test_matches_recognized_standard_scores_90(session, monkeypatch):
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    session.commit()
    assert EnumerableRoleStoreAdapter.matches(_descriptor(), _ctx(session)) == 90


@requires_postgres
def test_matches_markerless_authority_scores_0(session, monkeypatch):
    # The guard's no-adapter anchor: no recognized store behind the proxy → the
    # adapter declines to match, so the :1976 guard remains the backstop.
    _stub_probe_code(monkeypatch, "0x00")
    _seed_proxy_impl(session)
    session.commit()
    assert EnumerableRoleStoreAdapter.matches(_descriptor(), _ctx(session)) == 0


@requires_postgres
def test_matches_non_caller_arg_scores_0(session, monkeypatch):
    # onlyX(owner) — the arg is a state var, not the caller → not this adapter's
    # gate (short-circuits before any wire touch).
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    session.commit()
    desc = _descriptor(key_source="state_variable")
    assert EnumerableRoleStoreAdapter.matches(desc, _ctx(session)) == 0


@requires_postgres
def test_matches_non_single_address_signature_scores_0(session, monkeypatch):
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    session.commit()
    desc = _descriptor(callee_sig="canCall(address,address,bytes4)")
    assert EnumerableRoleStoreAdapter.matches(desc, _ctx(session)) == 0


@requires_postgres
def test_matches_proxy_hop_detection(session, monkeypatch):
    # The proxy stub carries no getter selectors; detection must hop proxy→impl.
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)  # proxy→impl linkage in the DB
    session.commit()
    assert EnumerableRoleStoreAdapter.matches(_descriptor(), _ctx(session)) == 90


# ---------------------------------------------------------------------------
# enumerate()
# ---------------------------------------------------------------------------


@requires_postgres
def test_warm_fold_probe_returns_finite_set(session, monkeypatch, both_flags):
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    _seed_cursor(session, _ROLE_SET)
    _seed_log(session, topics=_roleset_topics(_MULTISIG, _ROLE_1, True), block=100, log_index=0)
    session.commit()
    _install_probe_stub(monkeypatch, members={_MULTISIG})

    cap = EnumerableRoleStoreAdapter().enumerate(_descriptor(), _ctx(session))
    assert cap.kind == "finite_set"
    assert cap.members == [_MULTISIG.lower()]
    assert cap.membership_quality == "exact"
    assert cap.last_indexed_block == _CURSOR_BLOCK
    assert any(step.get("step") == "enumerable_role_store" for step in cap.trace)


@requires_postgres
def test_pin_once_block_none_resolves_via_blocknumber(session, monkeypatch, both_flags):
    # Unpinned pass (ctx.block None): the adapter reads ONE eth_blockNumber height
    # and uses it for the fold read + probe + trace, so the enumeration still lands.
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    _seed_cursor(session, _ROLE_SET)
    _seed_log(session, topics=_roleset_topics(_MULTISIG, _ROLE_1, True), block=100, log_index=0)
    session.commit()
    _install_probe_stub(monkeypatch, members={_MULTISIG}, head_block=_CURSOR_BLOCK)

    cap = EnumerableRoleStoreAdapter().enumerate(_descriptor(), _ctx(session, block=None))
    assert cap.kind == "finite_set"
    assert cap.members == [_MULTISIG.lower()]
    step = next(s for s in cap.trace if s.get("step") == "enumerable_role_store")
    assert step["probe_block"] == _CURSOR_BLOCK


@requires_postgres
def test_pin_once_blocknumber_failure_settles_probe_unavailable(session, monkeypatch, both_flags):
    # Unpinned pass AND the height read fails → probe_unavailable (fail-closed),
    # never a fold/probe/trace read at three different (or unpinned) heights.
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    _seed_cursor(session, _ROLE_SET)
    _seed_log(session, topics=_roleset_topics(_MULTISIG, _ROLE_1, True), block=100, log_index=0)
    session.commit()
    _install_probe_stub(monkeypatch, members={_MULTISIG}, blocknumber_fail=True)

    cap = EnumerableRoleStoreAdapter().enumerate(_descriptor(), _ctx(session, block=None))
    assert cap.kind == "external_check_only"
    assert _extra(cap).get("basis") == ["probe_unavailable"]
    assert "deferred_pending_index" not in _extra(cap)


@requires_postgres
def test_trace_carries_fold_frontier(session, monkeypatch, both_flags):
    # The drift arm keys on fold_frontier == the folded cursor height.
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    _seed_cursor(session, _ROLE_SET)
    _seed_log(session, topics=_roleset_topics(_MULTISIG, _ROLE_1, True), block=100, log_index=0)
    session.commit()
    _install_probe_stub(monkeypatch, members={_MULTISIG})

    cap = EnumerableRoleStoreAdapter().enumerate(_descriptor(), _ctx(session))
    step = next(s for s in cap.trace if s.get("step") == "enumerable_role_store")
    assert step["fold_frontier"] == _CURSOR_BLOCK


@requires_postgres
def test_finite_set_projects_principal_type_controller(session, monkeypatch, both_flags):
    # Acceptance: the enumerated controllers render principal_type="controller"
    # THROUGH project_capability_surface, carrying the trace for auditability.
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    _seed_cursor(session, _ROLE_SET)
    _seed_log(session, topics=_roleset_topics(_MULTISIG, _ROLE_1, True), block=100, log_index=0)
    session.commit()
    _install_probe_stub(monkeypatch, members={_MULTISIG})

    cap = EnumerableRoleStoreAdapter().enumerate(_descriptor(), _ctx(session))
    surface = project_capability_surface(capability_to_dict(cap))
    assert [r["address"] for r in surface.principal_rows] == [_MULTISIG.lower()]
    assert all(r["principal_type"] == "controller" for r in surface.principal_rows)


@requires_postgres
def test_settled_decline_records_metric(session, monkeypatch, both_flags):
    # Adapter-site decline counter: a settled probe_unavailable is observable at the
    # adapter (its persisted basis is superseded by the :1976 guard downstream).
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    _seed_cursor(session, _ROLE_SET)
    _seed_log(session, topics=_roleset_topics(_MULTISIG, _ROLE_1, True), block=100, log_index=0)
    session.commit()
    _install_probe_stub(monkeypatch, members={_MULTISIG}, transport_fail=True)

    import services.resolution.adapters.enumerable_role_store as ers

    ers._DECLINE_COUNTS.clear()  # module counter is process-lived; isolate this run
    metrics: dict = {}
    token = stage_metrics_var.set(metrics)
    try:
        cap = EnumerableRoleStoreAdapter().enumerate(_descriptor(), _ctx(session))
    finally:
        stage_metrics_var.reset(token)
    assert cap.kind == "external_check_only"
    assert _extra(cap).get("basis") == ["probe_unavailable"]
    assert metrics.get("role_store_decline_probe_unavailable") == 1


@requires_postgres
def test_probe_transport_failure_not_memoized_cross_capability(session, monkeypatch, both_flags):
    # F3: a transport blip must NOT poison the shared pass memo — a second enumerate
    # for the same (authority, selector, block) re-probes and can succeed. (Pre-fix
    # the failure was cached and settled the whole family to probe_unavailable.)
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    _seed_cursor(session, _ROLE_SET)
    _seed_log(session, topics=_roleset_topics(_MULTISIG, _ROLE_1, True), block=100, log_index=0)
    session.commit()

    calls = {"n": 0}
    gate_sel = keccak(text=_CALLEE_SIG).hex()[:8]
    members_l = {_MULTISIG.lower()}
    control_l = _NEGATIVE_CONTROL_ADDR.lower()

    def _stub(rpc_url, method, params=None, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("stubbed one-shot transport blip")
        assert params
        body = bytes.fromhex(params[0]["data"][10:])
        decoded = abi_decode(["(address,bool,bytes)[]"], body)[0]
        results = []
        for _t, _a, calldata in decoded:
            addr = "0x" + calldata[4:36][-20:].hex()
            if calldata[:4].hex() == gate_sel:
                results.append((False if addr == control_l else (addr in members_l), b""))
            else:
                results.append((False, b""))
        return "0x" + abi_encode(["(bool,bytes)[]"], [results]).hex()

    import utils.rpc as _rpc

    monkeypatch.setattr(_rpc, "rpc_request", _stub)

    ctx = _ctx(session)  # one ctx → one shared live_read_memo across both calls
    first = EnumerableRoleStoreAdapter().enumerate(_descriptor(), ctx)
    assert first.kind == "external_check_only"
    assert _extra(first).get("basis") == ["probe_unavailable"]
    second = EnumerableRoleStoreAdapter().enumerate(_descriptor(), ctx)
    assert second.kind == "finite_set"
    assert second.members == [_MULTISIG.lower()]


@requires_postgres
def test_cold_index_defers_pending_index(session, monkeypatch, both_flags):
    # Events present but NO warm cursor → cold. Defer for self-heal, never probe.
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    _seed_log(session, topics=_roleset_topics(_MULTISIG, _ROLE_1, True), block=100, log_index=0)
    session.commit()

    cap = EnumerableRoleStoreAdapter().enumerate(_descriptor(), _ctx(session))
    assert cap.kind == "external_check_only"
    assert _extra(cap).get("basis") == ["no_index_cursor"]
    assert _extra(cap).get("deferred_pending_index") is True


@requires_postgres
def test_warm_zero_events_settles_unconfirmed(session, monkeypatch, both_flags):
    # Warm cursor, but the store emitted no role events → cannot confirm it speaks
    # the standard we'd fold; settle to a probe (NOT an exact-empty false nobody).
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    _seed_cursor(session, _ROLE_SET)
    session.commit()

    cap = EnumerableRoleStoreAdapter().enumerate(_descriptor(), _ctx(session))
    assert cap.kind == "external_check_only"
    assert _extra(cap).get("basis") == ["authority_unconfirmed_no_role_events"]
    assert "deferred_pending_index" not in _extra(cap)


@requires_postgres
def test_negative_control_passes_declines(session, monkeypatch, both_flags):
    # A gate that passes a random control address is not an allowlist → decline.
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    _seed_cursor(session, _ROLE_SET)
    _seed_log(session, topics=_roleset_topics(_MULTISIG, _ROLE_1, True), block=100, log_index=0)
    session.commit()
    _install_probe_stub(monkeypatch, members={_MULTISIG}, control_passes=True)

    cap = EnumerableRoleStoreAdapter().enumerate(_descriptor(), _ctx(session))
    assert cap.kind == "external_check_only"
    assert _extra(cap).get("basis") == ["negative_control_passed"]


@requires_postgres
def test_probe_transport_failure_is_indeterminate(session, monkeypatch, both_flags):
    # A wire failure is NOT a membership failure: settle to probe_unavailable and
    # classify nobody (no finite_set, no exact-empty).
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    _seed_cursor(session, _ROLE_SET)
    _seed_log(session, topics=_roleset_topics(_MULTISIG, _ROLE_1, True), block=100, log_index=0)
    session.commit()
    _install_probe_stub(monkeypatch, members={_MULTISIG}, transport_fail=True)

    cap = EnumerableRoleStoreAdapter().enumerate(_descriptor(), _ctx(session))
    assert cap.kind == "external_check_only"
    assert _extra(cap).get("basis") == ["probe_unavailable"]
    assert "deferred_pending_index" not in _extra(cap)


@requires_postgres
def test_probe_filters_non_members(session, monkeypatch, both_flags):
    # Two active holders in the events, but the gate only passes one — the probe is
    # the ground truth, so the non-passing candidate is dropped.
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    _seed_cursor(session, _ROLE_SET)
    _seed_log(session, topics=_roleset_topics(_MULTISIG, _ROLE_1, True), block=100, log_index=0)
    _seed_log(session, topics=_roleset_topics(_TIMELOCK, _ROLE_1, True), block=101, log_index=0)
    session.commit()
    _install_probe_stub(monkeypatch, members={_MULTISIG})  # timelock NOT passed

    cap = EnumerableRoleStoreAdapter().enumerate(_descriptor(), _ctx(session))
    assert cap.kind == "finite_set"
    assert cap.members == [_MULTISIG.lower()]


@requires_postgres
def test_oz_polarity_grant_then_revoke_not_member(session, monkeypatch, both_flags):
    # OZ AccessControlEnumerable fold: RoleGranted then RoleRevoked for the same
    # (holder, role) folds to not-a-member; a distinct still-granted holder stays.
    _stub_probe_code(monkeypatch, _code_with(*OZ_ACCESS_CONTROL_ENUMERABLE.marker_selectors))
    _seed_proxy_impl(session)
    for topic0 in OZ_ACCESS_CONTROL_ENUMERABLE.topic0s():
        _seed_cursor(session, topic0)
    _seed_log(session, topics=_oz_topics(_OZ_GRANTED, _ROLE_1, _STRANGER), block=100, log_index=0)
    _seed_log(session, topics=_oz_topics(_OZ_REVOKED, _ROLE_1, _STRANGER), block=101, log_index=0)
    _seed_log(session, topics=_oz_topics(_OZ_GRANTED, _ROLE_1, _MULTISIG), block=102, log_index=0)
    session.commit()
    _install_probe_stub(monkeypatch, members={_MULTISIG, _STRANGER})  # gate would pass both if asked

    cap = EnumerableRoleStoreAdapter().enumerate(_descriptor(), _ctx(session))
    assert cap.kind == "finite_set"
    # Stranger was revoked → never a candidate → never probed → absent.
    assert cap.members == [_MULTISIG.lower()]


@requires_postgres
def test_all_revoked_provably_nobody_empty_exact(session, monkeypatch, both_flags):
    # Warm, events present, but every holder revoked and the negative control
    # reverts → provably nobody: exact-empty finite_set (blocks OR'd public siblings).
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    _seed_cursor(session, _ROLE_SET)
    _seed_log(session, topics=_roleset_topics(_MULTISIG, _ROLE_1, True), block=100, log_index=0)
    _seed_log(session, topics=_roleset_topics(_MULTISIG, _ROLE_1, False), block=101, log_index=0)
    session.commit()
    _install_probe_stub(monkeypatch, members=set())

    cap = EnumerableRoleStoreAdapter().enumerate(_descriptor(), _ctx(session))
    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "exact"


@requires_postgres
def test_getter_crosscheck_mismatch_declines(session, monkeypatch, both_flags):
    # With the getter cross-check on, a getter holder set that disagrees with the
    # event fold declines LOUD rather than emitting a contradicted set.
    monkeypatch.setenv("PSAT_ROLE_STORE_GETTER_CROSSCHECK", "1")
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    _seed_cursor(session, _ROLE_SET)
    _seed_log(session, topics=_roleset_topics(_MULTISIG, _ROLE_1, True), block=100, log_index=0)
    session.commit()
    # Fold says {_MULTISIG}; getter says {_TIMELOCK} → mismatch.
    _install_probe_stub(monkeypatch, members={_MULTISIG}, getter_holders={_ROLE_1: [_TIMELOCK]})

    cap = EnumerableRoleStoreAdapter().enumerate(_descriptor(), _ctx(session))
    assert cap.kind == "external_check_only"
    assert _extra(cap).get("basis") == ["role_fold_getter_mismatch"]


@requires_postgres
def test_getter_crosscheck_match_returns_set(session, monkeypatch, both_flags):
    monkeypatch.setenv("PSAT_ROLE_STORE_GETTER_CROSSCHECK", "1")
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    _seed_cursor(session, _ROLE_SET)
    _seed_log(session, topics=_roleset_topics(_MULTISIG, _ROLE_1, True), block=100, log_index=0)
    session.commit()
    _install_probe_stub(monkeypatch, members={_MULTISIG}, getter_holders={_ROLE_1: [_MULTISIG]})

    cap = EnumerableRoleStoreAdapter().enumerate(_descriptor(), _ctx(session))
    assert cap.kind == "finite_set"
    assert cap.members == [_MULTISIG.lower()]


# ---------------------------------------------------------------------------
# Dispatch order — the adapter pre-empts the generic EventIndexedAdapter
# ---------------------------------------------------------------------------


@requires_postgres
def test_dispatch_order_adapter_preempts_generic(session, monkeypatch, both_flags):
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    _seed_cursor(session, _ROLE_SET)
    _seed_log(session, topics=_roleset_topics(_MULTISIG, _ROLE_1, True), block=100, log_index=0)
    session.commit()
    _install_probe_stub(monkeypatch, members={_MULTISIG})

    registry = AdapterRegistry()
    registry.register(SolmateRolesAuthorityAdapter)
    registry.register(EnumerableRoleStoreAdapter)
    registry.register(EventIndexedAdapter)

    picked = registry.pick(_descriptor(), _ctx(session))
    assert picked is EnumerableRoleStoreAdapter

    cap = registry.enumerate(_descriptor(), _ctx(session))
    assert cap.kind == "finite_set"
    assert cap.members == [_MULTISIG.lower()]
    assert any(step.get("step") == "enumerable_role_store" for step in cap.trace)


# ---------------------------------------------------------------------------
# Unwitnessed empties decline; registry context is chain-scoped
# and an error there is never "no candidates".
# ---------------------------------------------------------------------------


@requires_postgres
def test_zero_survivors_over_nonempty_candidates_declines_not_exact_empty(session, monkeypatch, both_flags):
    # A live holder exists (candidate universe non-empty) but the real gate
    # rejects every candidate: either the gate's one role is unheld or the gate
    # admits callers outside the role model (hybrid msg.sender== gate). The two
    # are indistinguishable, so an exact-empty "provably nobody" is unwitnessed.
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    _seed_cursor(session, _ROLE_SET)
    _seed_log(session, topics=_roleset_topics(_MULTISIG, _ROLE_1, True), block=100, log_index=0)
    session.commit()
    _install_probe_stub(monkeypatch, members=set())  # gate passes nobody

    cap = EnumerableRoleStoreAdapter().enumerate(_descriptor(), _ctx(session))
    assert cap.kind == "external_check_only"
    assert "no_candidate_passed_gate" in (_extra(cap).get("basis") or [])
    assert not _extra(cap).get("deferred_pending_index")


@requires_postgres
def test_registry_context_db_error_declines_not_empty_candidates(session, monkeypatch, both_flags):
    # A DB error while reading the registry's own controllers must never
    # shrink the candidate universe into a (possibly empty) member set.
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    _seed_cursor(session, _ROLE_SET)
    _seed_log(session, topics=_roleset_topics(_MULTISIG, _ROLE_1, True), block=100, log_index=0)
    session.commit()
    _install_probe_stub(monkeypatch, members={_MULTISIG})

    from services.resolution.adapters import enumerable_role_store as ers

    monkeypatch.setattr(ers, "_registry_controller_context", lambda ctx, authority: None)
    cap = EnumerableRoleStoreAdapter().enumerate(_descriptor(), _ctx(session))
    assert cap.kind == "external_check_only"
    assert "registry_context_error" in (_extra(cap).get("basis") or [])


@requires_postgres
def test_registry_controller_context_is_chain_scoped(session, monkeypatch, both_flags):
    # A same-address twin registry on another chain carries a controller value
    # that must NOT leak into this chain's candidate universe (cross-chain twin
    # aliasing inside the caller-set computation).
    from db.models import Contract, ControllerValue
    from services.resolution.adapters.enumerable_role_store import _registry_controller_context

    twin_owner = "0x" + "77" * 20
    mainnet_owner = "0x" + "88" * 20

    session.add(Contract(address=_PROXY, implementation=_IMPL, is_proxy=True, chain="ethereum"))
    twin = Contract(address=_PROXY, implementation=_IMPL, is_proxy=True, chain="scroll")
    session.add(twin)
    session.flush()
    mainnet = session.query(Contract).filter(Contract.chain == "ethereum").one()
    session.add(ControllerValue(contract_id=mainnet.id, controller_id="state_variable:owner", value=mainnet_owner))
    session.add(ControllerValue(contract_id=twin.id, controller_id="state_variable:owner", value=twin_owner))
    session.commit()

    context = _registry_controller_context(_ctx(session), _PROXY.lower())
    assert context is not None
    controller_addrs, _labels = context
    assert mainnet_owner in controller_addrs
    assert twin_owner not in controller_addrs
