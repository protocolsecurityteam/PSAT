"""Solmate ``RolesAuthority`` adapter — resolves ``canCall`` from REAL events.

Fixture ``tests/fixtures/solmate/roles_authority_3994741a.json`` holds the
actual ``RoleCapabilityUpdated`` / ``UserRoleUpdated`` /
``PublicCapabilityUpdated`` logs of etherfi's RolesAuthority
``0x3994741a…`` (the authority for ``TellerWithMultiAssetSupport``
``0xe2acf9f8…``). Ground truth was verified on-chain via ``canCall``:

    pause / unpause      -> role 9 -> 4/6 Safe 0xcea8039076…
    addAsset / removeAsset -> role 8 -> 4/6 Safe 0xcea8039076…
    setShareLockPeriod   -> no role + owner renounced -> genuinely empty

Before this adapter these functions resolved to an empty ``finite_set`` /
unresolved ``OR`` (no caller) — see RECALL/under-resolution audit. This
test pins that the adapter now recovers the real controller and does not
fall back to a heuristic.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.resolution.adapters import AdapterRegistry, CallFrame, EvaluationContext  # noqa: E402
from services.resolution.adapters.event_indexed import EventIndexedAdapter  # noqa: E402
from services.resolution.adapters.solmate_roles import (  # noqa: E402
    CANCALL_SIGNATURE,
    SolmateRolesAuthorityAdapter,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "solmate" / "roles_authority_3994741a.json"
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
    """In-memory ``iter_event_rows`` over the captured logs (already in log order)."""

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


def test_solmate_pause_resolves_to_governing_safe():
    fixture = _load()
    cap = SolmateRolesAuthorityAdapter().enumerate(_descriptor(), _ctx(fixture, FixtureRepo(_rows(fixture)), PAUSE))
    assert cap.kind == "finite_set"
    assert cap.members == [SAFE_4_6]
    assert cap.membership_quality == "exact"


def test_solmate_add_asset_resolves_to_governing_safe():
    fixture = _load()
    cap = SolmateRolesAuthorityAdapter().enumerate(_descriptor(), _ctx(fixture, FixtureRepo(_rows(fixture)), ADD_ASSET))
    assert cap.kind == "finite_set"
    assert cap.members == [SAFE_4_6]


def test_solmate_unroled_function_is_exact_empty_not_unknown():
    # No role capability + renounced owner => genuinely callable by nobody.
    # Must be an EXACT empty set (a true negative), not a heuristic miss.
    fixture = _load()
    cap = SolmateRolesAuthorityAdapter().enumerate(
        _descriptor(), _ctx(fixture, FixtureRepo(_rows(fixture)), SET_SHARE_LOCK)
    )
    assert cap.kind == "finite_set"
    assert cap.members == []
    assert cap.membership_quality == "exact"


def test_solmate_unindexed_events_defer_to_probe_not_false_empty():
    # When the authority's events aren't durably indexed, an empty result must
    # NOT be reported as exact "nobody" — fall back to a probe.
    fixture = _load()
    cap = SolmateRolesAuthorityAdapter().enumerate(
        _descriptor(), _ctx(fixture, FixtureRepo(_rows(fixture), indexed_block=None), SET_SHARE_LOCK)
    )
    assert cap.kind == "external_check_only"


def test_solmate_unconfirmed_authority_fails_closed_not_false_empty():
    # The authority IS indexed (cursor present) but emitted NONE of the three
    # RolesAuthority role events — e.g. a custom Authority exposing canCall with
    # different internal logic. The adapter must not assert an exact-empty
    # "nobody"; it can only be correct-by-construction for a confirmed
    # RolesAuthority, so it fails closed to a probe.
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


def test_registry_prefers_solmate_over_generic_event_adapter():
    registry = AdapterRegistry()
    registry.register(EventIndexedAdapter)
    registry.register(SolmateRolesAuthorityAdapter)
    descriptor = {
        "kind": "external_set",
        "callee_signature": CANCALL_SIGNATURE,
        "enumeration_hint": [{"topic0": "0xaa", "direction": "add"}],
    }
    assert registry.pick(descriptor, EvaluationContext()) is SolmateRolesAuthorityAdapter
