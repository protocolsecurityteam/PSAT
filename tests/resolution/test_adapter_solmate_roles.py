"""Solmate ``RolesAuthority`` resolves ``canCall`` from real events.

The fixture holds etherfi RolesAuthority ``0x3994741a…``'s logs. Ground truth, verified on-chain:

    pause / unpause        -> role 9 -> 4/6 Safe 0xcea8039076…
    addAsset / removeAsset -> role 8 -> 4/6 Safe 0xcea8039076…
    setShareLockPeriod     -> no role + owner renounced -> genuinely empty
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from services.resolution.adapters import AdapterRegistry, CallFrame, EvaluationContext
from services.resolution.adapters.event_indexed import EventIndexedAdapter
from services.resolution.adapters.solmate_roles import (
    _OTHER_CANCALL_STANDARD_SELECTORS,
    _ROLES_AUTHORITY_MARKER_SELECTORS,
    CANCALL_SIGNATURE,
    SolmateRolesAuthorityAdapter,
)
from services.resolution.capabilities import CapabilityExpr

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "solmate" / "roles_authority_3994741a.json"
SAFE_4_6 = "0xcea8039076e35a825854c5c2f85659430b06ec96"
PAUSE = "0x8456cb59"
ADD_ASSET = "0x298410e5"
SET_SHARE_LOCK = "0x12056e2d"


def _load() -> dict:
    return json.loads(FIXTURE.read_text())


def _rows(fixture: dict) -> list[SimpleNamespace]:
    rows: list[SimpleNamespace] = []
    for log in fixture["logs"]:
        data = log["data"]
        body = data[2:] if isinstance(data, str) and data.startswith("0x") else ""
        data_words = ["0x" + body[i : i + 64] for i in range(0, len(body), 64)] if body else []
        rows.append(
            SimpleNamespace(
                topic0=log["topics"][0],
                topics=log["topics"],
                data_words=data_words,
                block_number=log["blockNumber"],
                transaction_index=log["transactionIndex"],
                log_index=log["logIndex"],
            )
        )
    return rows


class FixtureRepo:
    def __init__(self, rows: list[SimpleNamespace], indexed_block: int | None = 21_000_000):
        self.rows = rows
        self.indexed_block = indexed_block

    def iter_event_rows(self, *, chain_id, event_address, topic0s, block=None):
        del chain_id, event_address, block
        wanted = {t.lower() for t in topic0s}
        return [r for r in self.rows if str(r.topic0).lower() in wanted]

    def min_indexed_block(self, *, chain_id, event_address, topic0s):
        del chain_id, event_address, topic0s
        return self.indexed_block


def _ctx(fixture: dict, repo, selector: str) -> EvaluationContext:
    return EvaluationContext(
        chain_id=1,
        contract_address=fixture["teller"],
        # Covered by FixtureRepo's cursor (21_000_000).
        block=20_999_000,
        meta={"event_log_repo": repo},
        state_var_values={"authority": fixture["authority"]},
        call_frame=CallFrame.root(
            contract_address=fixture["teller"], function_signature=None, function_selector=selector
        ),
    )


def _descriptor() -> dict:
    return {
        "kind": "external_set",
        "callee_signature": CANCALL_SIGNATURE,
        "authority_contract": {"address_source": {"source": "state_variable", "state_variable_name": "authority"}},
    }


@pytest.mark.parametrize(
    "selector",
    [
        pytest.param(PAUSE, id="pause_role_9"),
        pytest.param(ADD_ASSET, id="add_asset_role_8"),
    ],
)
def test_solmate_selector_resolves_to_governing_safe(selector):
    fixture = _load()
    cap = SolmateRolesAuthorityAdapter().enumerate(_descriptor(), _ctx(fixture, FixtureRepo(_rows(fixture)), selector))
    assert cap.kind == "finite_set"
    assert cap.members == [SAFE_4_6]
    assert cap.membership_quality == "exact"


def test_solmate_unroled_function_is_exact_empty_not_unknown():
    fixture = _load()
    cap = SolmateRolesAuthorityAdapter().enumerate(
        _descriptor(), _ctx(fixture, FixtureRepo(_rows(fixture)), SET_SHARE_LOCK)
    )
    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "exact"


def test_solmate_unindexed_events_defer_to_probe_not_false_empty():
    fixture = _load()
    cap = SolmateRolesAuthorityAdapter().enumerate(
        _descriptor(), _ctx(fixture, FixtureRepo(_rows(fixture), indexed_block=None), SET_SHARE_LOCK)
    )
    assert cap.kind == "external_check_only"


def test_solmate_unconfirmed_authority_fails_closed_not_false_empty():
    # Only a confirmed RolesAuthority may assert exact-empty.
    fixture = _load()

    class IndexedButNoRoleEventsRepo:
        def iter_event_rows(self, *, chain_id, event_address, topic0s, block=None):
            return []

        def min_indexed_block(self, *, chain_id, event_address, topic0s):
            return 21_000_000

    cap = SolmateRolesAuthorityAdapter().enumerate(_descriptor(), _ctx(fixture, IndexedButNoRoleEventsRepo(), PAUSE))
    assert cap.kind == "external_check_only"
    assert cap.check is not None
    assert "authority_unconfirmed_no_role_events" in cap.check.extra["basis"]


def test_solmate_renounced_zero_authority_settles_not_deferred():
    # No 0x0 cursor will ever exist, so a deferral would never clear; no cursor proves the short-circuit fires first.
    fixture = _load()
    ctx = EvaluationContext(
        chain_id=1,
        contract_address=fixture["teller"],
        meta={"event_log_repo": FixtureRepo(_rows(fixture), indexed_block=None)},
        state_var_values={"authority": "0x" + "0" * 40},
        call_frame=CallFrame.root(contract_address=fixture["teller"], function_signature=None, function_selector=PAUSE),
    )
    cap = SolmateRolesAuthorityAdapter().enumerate(_descriptor(), ctx)
    assert cap.kind == "external_check_only"
    assert cap.check is not None
    assert "authority_unresolved" in cap.check.extra["basis"]
    assert "deferred_pending_index" not in cap.check.extra


_AUTHORITY = "0x" + "a1" * 20


class _FakeBytecode:
    def __init__(self, *, selectors):
        self._selectors = {s.lower() for s in selectors}

    def has_selector(self, *, chain_id, contract_address, selector):
        del chain_id, contract_address
        return selector.lower() in self._selectors

    def declares_event(self, *, chain_id, contract_address, topic0):
        del chain_id, contract_address, topic0
        return False


def _descriptor_with_authority() -> dict:
    return {
        "kind": "external_set",
        "callee_signature": CANCALL_SIGNATURE,
        "authority_contract": {"address_source": {"source": "state_variable", "state_variable_name": "authority"}},
    }


def _ctx_for_matches(bytecode=None) -> EvaluationContext:
    return EvaluationContext(chain_id=1, state_var_values={"authority": _AUTHORITY}, bytecode=bytecode)


@pytest.mark.parametrize(
    "bytecode,score",
    [
        pytest.param(_FakeBytecode(selectors=_ROLES_AUTHORITY_MARKER_SELECTORS), 90, id="confirmed_rolesauthority"),
        # OZ AccessManager shares the selector, so Solmate declines.
        pytest.param(_FakeBytecode(selectors=_OTHER_CANCALL_STANDARD_SELECTORS), 0, id="different_cancall_standard"),
        pytest.param(None, 40, id="provisional_when_unprobeable"),
    ],
)
def test_matches_score(bytecode, score):
    assert SolmateRolesAuthorityAdapter.matches(_descriptor_with_authority(), _ctx_for_matches(bytecode)) == score


def test_registry_prefers_confirmed_solmate_over_generic_event_adapter():
    registry = AdapterRegistry()
    registry.register(EventIndexedAdapter)
    registry.register(SolmateRolesAuthorityAdapter)
    bc = _FakeBytecode(selectors=_ROLES_AUTHORITY_MARKER_SELECTORS)
    assert registry.pick(_descriptor_with_authority(), _ctx_for_matches(bc)) is SolmateRolesAuthorityAdapter


def test_second_cancall_standard_not_starved_when_solmate_declines():
    # F1: two standards sharing canCall can coexist in the registry.
    class _ConfirmedAccessManagerAdapter:
        @classmethod
        def matches(cls, descriptor, ctx):
            del ctx
            return 90 if descriptor.get("callee_signature") == CANCALL_SIGNATURE else 0

        @classmethod
        def supports_external_check_only(cls):
            return True

        def enumerate(self, descriptor, ctx):
            del descriptor, ctx
            return CapabilityExpr.unsupported("access_manager_stub")

    registry = AdapterRegistry()
    registry.register(SolmateRolesAuthorityAdapter)  # registered first
    registry.register(_ConfirmedAccessManagerAdapter)
    bc = _FakeBytecode(selectors=_OTHER_CANCALL_STANDARD_SELECTORS)  # an AccessManager authority
    assert registry.pick(_descriptor_with_authority(), _ctx_for_matches(bc)) is _ConfirmedAccessManagerAdapter
