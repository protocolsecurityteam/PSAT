"""Folds the role-store's events and confirms each candidate against the live gate.

Only the Multicall3 wire is stubbed; events and cursors are seeded into real Postgres.
"""

from __future__ import annotations

from typing import Any

import pytest
from eth_abi.abi import decode as abi_decode
from eth_abi.abi import encode as abi_encode
from eth_utils.crypto import keccak

import services.resolution.role_store_standards as rss
from services.resolution.adapters import EvaluationContext
from services.resolution.adapters.enumerable_role_store import (
    _NEGATIVE_CONTROL_ADDR,
    EnumerableRoleStoreAdapter,
)
from services.resolution.repos.event_logs_pg import PostgresEventLogRepo
from services.resolution.role_store_standards import (
    SOLADY_ENUMERABLE_ROLES,
)
from tests.conftest import DATABASE_URL as _DB_URL
from tests.conftest import _can_connect, requires_postgres
from utils.logging import stage_metrics_var

_PROXY = "0x" + "62" * 20  # registry proxy — where RoleSet is emitted
_IMPL = "0x" + "3b" * 20  # role-store impl behind the proxy
_MULTISIG = "0x2aca71020de61bb532008049e1bd41e451ae8adc"  # OPERATION_MULTISIG holder (ground truth)
_TIMELOCK = "0xcd425f44758a08baab3c4908f3e3de5776e45d7a"
_CURSOR_BLOCK = 25_000_000
_PROBE_BLOCK = 24_900_000  # <= cursor so the fold is exact-covered

_ROLE_SET = SOLADY_ENUMERABLE_ROLES.grant_events[0].topic0
_ROLE_1 = 1  # OPERATION_MULTISIG_ROLE (Solady uint256 id)

_CALLEE_SIG = "onlyOperatingMultisig(address)"


# The adapter doesn't branch on the flag.
@pytest.fixture(params=["1", "0"], ids=["earned_on", "earned_off"])
def both_flags(request, monkeypatch):
    monkeypatch.setenv("PSAT_AUTHORITY_EARNED_PUBLIC", request.param)
    return request.param


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


def _word(value: int) -> str:
    return "0x" + format(value, "064x")


def _addr_word(address: str) -> str:
    return "0x" + address.lower().removeprefix("0x").rjust(64, "0")


def _roleset_topics(holder: str, role: int, active: bool) -> list[str]:
    return [_ROLE_SET, _addr_word(holder), _word(role), _word(1 if active else 0)]


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
            first_indexed_block=0,
            first_indexed_block_basis="creation_block_minus_one",
        )
    )


def _seed_proxy_impl(session) -> None:
    from db.models import Contract

    session.add(Contract(address=_PROXY, implementation=_IMPL, is_proxy=True, chain="ethereum"))


def _code_with(*selectors: str) -> str:
    return "0x" + "".join("63" + s.removeprefix("0x") for s in selectors)


def _stub_probe_code(monkeypatch, code_for_impl: str) -> None:

    def _fake_get_code(rpc_url, address, *, chain_id=None):
        return code_for_impl if address.lower() == _IMPL.lower() else "0x00"

    monkeypatch.setattr(rss, "get_code", _fake_get_code)
    # The DB row is the linkage, so detection never hits the wire.
    monkeypatch.setattr(rss, "rpc_request", lambda *a, **k: None)


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

    # Patch only the wire, plus the adapter's imported reference for the pin-once read.
    import services.clients.rpc as _rpc
    import services.resolution.adapters.enumerable_role_store as _ers

    monkeypatch.setattr(_rpc, "rpc_request", _stub)
    monkeypatch.setattr(_ers, "rpc_request", _stub)


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


@requires_postgres
def test_matches_markerless_authority_scores_0(session, monkeypatch):
    # No recognized store, so the :1976 guard stays the backstop.
    _stub_probe_code(monkeypatch, "0x00")
    _seed_proxy_impl(session)
    session.commit()
    assert EnumerableRoleStoreAdapter.matches(_descriptor(), _ctx(session)) == 0


@requires_postgres
@pytest.mark.parametrize(
    "descriptor_kwargs",
    [
        pytest.param({"key_source": "state_variable"}, id="non_caller_arg"),
        pytest.param({"callee_sig": "canCall(address,address,bytes4)"}, id="non_single_address_signature"),
    ],
)
def test_matches_declines_scores_0(session, monkeypatch, descriptor_kwargs):
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    session.commit()
    desc = _descriptor(**descriptor_kwargs)
    assert EnumerableRoleStoreAdapter.matches(desc, _ctx(session)) == 0


@requires_postgres
def test_pin_once_blocknumber_failure_settles_probe_unavailable(session, monkeypatch, both_flags):
    # Never reads at different heights.
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
def test_settled_decline_records_metric(session, monkeypatch, both_flags):
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
def test_cold_index_defers_pending_index(session, monkeypatch, both_flags):
    # Cold: defer for self-heal, never probe.
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
    # Can't confirm the store speaks the standard, so probe rather than claim exact-empty.
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
def test_getter_crosscheck_mismatch_declines(session, monkeypatch, both_flags):
    monkeypatch.setenv("PSAT_ROLE_STORE_GETTER_CROSSCHECK", "1")
    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    _seed_cursor(session, _ROLE_SET)
    _seed_log(session, topics=_roleset_topics(_MULTISIG, _ROLE_1, True), block=100, log_index=0)
    session.commit()
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


@requires_postgres
def test_zero_survivors_over_nonempty_candidates_declines_not_exact_empty(session, monkeypatch, both_flags):
    # The role is unheld or the gate admits outsiders; indistinguishable, so exact-empty is unwitnessed.
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


# ---------------------------------------------------------------------------
# Coverage gate: a cursor behind the pinned block is completed by a tail or defers
# ---------------------------------------------------------------------------

_TAIL_PIN = _CURSOR_BLOCK + 100


def _raw_roleset(holder: str, active: bool, block: int) -> dict[str, Any]:
    from tests.support.tail_wire import raw_log

    return raw_log(_PROXY, _roleset_topics(holder, _ROLE_1, active), block)


@requires_postgres
def test_grant_past_the_cursor_reaches_the_probe_through_the_tail(session, monkeypatch):
    from tests.support.tail_wire import install_tail_wire

    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    _seed_cursor(session, _ROLE_SET)
    _seed_log(session, topics=_roleset_topics(_MULTISIG, _ROLE_1, True), block=100, log_index=0)
    session.commit()
    wire = install_tail_wire(monkeypatch, [_raw_roleset(_TIMELOCK, True, _CURSOR_BLOCK + 50)])
    _install_probe_stub(monkeypatch, members={_MULTISIG, _TIMELOCK})

    cap = EnumerableRoleStoreAdapter().enumerate(_descriptor(), _ctx(session, block=_TAIL_PIN))

    assert wire.calls == [(_CURSOR_BLOCK + 1, _TAIL_PIN)]
    assert (cap.kind, cap.membership_quality) == ("finite_set", "exact")
    assert cap.members == sorted([_MULTISIG.lower(), _TIMELOCK.lower()])
    step = cap.trace[0]
    assert step["candidates_from_events"] == sorted([_MULTISIG.lower(), _TIMELOCK.lower()])
    assert step["fold_frontier"] == _TAIL_PIN
    assert (step["scan_from_block"], step["scan_to_block"], step["floor_basis"]) == (
        _CURSOR_BLOCK + 1,
        _TAIL_PIN,
        "durable_frontier_tail",
    )


@requires_postgres
@pytest.mark.parametrize("tail_fails", [True, False], ids=["tail_failed", "tail_ok"])
def test_behind_cursor_is_never_exact_without_a_complete_tail(session, monkeypatch, tail_fails):
    from tests.support.tail_wire import install_tail_wire

    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    _seed_cursor(session, _ROLE_SET)
    _seed_log(session, topics=_roleset_topics(_MULTISIG, _ROLE_1, True), block=100, log_index=0)
    session.commit()
    install_tail_wire(monkeypatch, [_raw_roleset(_TIMELOCK, True, _CURSOR_BLOCK + 50)], fail=tail_fails)
    _install_probe_stub(monkeypatch, members={_MULTISIG, _TIMELOCK})

    cap = EnumerableRoleStoreAdapter().enumerate(_descriptor(), _ctx(session, block=_TAIL_PIN))

    if tail_fails:
        assert cap.kind == "external_check_only"
        assert _extra(cap)["basis"] == ["cursor_behind_block"]
        assert _extra(cap)["deferred_pending_index"] is True
    else:
        assert _TIMELOCK.lower() in (cap.members or [])


@requires_postgres
def test_unpinned_pass_behind_the_head_defers_instead_of_tailing_to_head(session, monkeypatch):
    from tests.support.tail_wire import install_tail_wire

    _stub_probe_code(monkeypatch, _code_with(*SOLADY_ENUMERABLE_ROLES.marker_selectors))
    _seed_proxy_impl(session)
    _seed_cursor(session, _ROLE_SET)
    _seed_log(session, topics=_roleset_topics(_MULTISIG, _ROLE_1, True), block=100, log_index=0)
    session.commit()
    wire = install_tail_wire(monkeypatch, [_raw_roleset(_TIMELOCK, True, _CURSOR_BLOCK + 50)])
    _install_probe_stub(monkeypatch, members={_MULTISIG, _TIMELOCK}, head_block=_TAIL_PIN)

    cap = EnumerableRoleStoreAdapter().enumerate(_descriptor(), _ctx(session, block=None))

    assert wire.calls == []
    assert cap.kind == "external_check_only"
    assert _extra(cap)["basis"] == ["cursor_behind_block"]
    assert _extra(cap)["deferred_pending_index"] is True
