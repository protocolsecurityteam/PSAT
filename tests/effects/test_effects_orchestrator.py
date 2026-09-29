"""Tier-0 code-upgrade current-state check.

An indexed UpgradeEvent proves only PAST capability; a present-tense claim also needs a non-zero
impl slot AND a resolved, non-renounced upgrade authority (freezing does not zero the slot).
Drives ``_code_upgrade_plans`` against a stubbed session; no anvil, no RPC.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from db.models import Contract
from services.effects.config import (
    EFFECT_CLASS_CODE_UPGRADE,
    VERDICT_PROVEN,
    VERDICT_UNKNOWN,
)
from services.effects.orchestrator import ProbeContext, _code_upgrade_plans
from services.effects.selection import Candidate
from tests.support.effects_stubs import RecordingStore

IMPL = "0x" + "d1" * 20
PROXY = "0x" + "35" * 20
PRINCIPAL = "0x" + "22" * 20
ZERO = "0x" + "0" * 40


class _FakeResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class _FakeSession:
    """Returns queued ``scalar_one_or_none`` values in call order: the prober's
    two reads are (proxy Contract, then the UpgradeEvent id)."""

    def __init__(self, *values):
        self._values = list(values)
        self._i = 0

    def execute(self, *_a, **_k):
        v = self._values[self._i]
        self._i += 1
        return _FakeResult(v)


def _proxy_contract() -> Contract:
    return Contract(is_proxy=True, implementation=IMPL, proxy_type="transparent")


def _candidate(principals: tuple[str, ...]) -> Candidate:
    return Candidate(
        function_id=1,
        contract_id=1,
        contract_address=IMPL,
        selector="0x3659cfe6",
        function_name="upgradeTo",
        authority_public=False,
        principal_addresses=principals,
        deployment_address=PROXY,
    )


def _ctx() -> ProbeContext:
    # A MagicMock that raises if called: simulate must never be touched on the Tier-0 path.
    return ProbeContext(
        chain_id=1,
        block=21_000_000,
        hardfork="prague",
        simulate=MagicMock(side_effect=AssertionError("Tier-0 must not touch the wire")),
        simulate_supported=True,
        transcript_store=RecordingStore(),
    )


def _run_plan(principals: tuple[str, ...]):
    session: Any = _FakeSession(_proxy_contract(), 1)  # proxy row, then an UpgradeEvent id
    plans = _code_upgrade_plans(session, _candidate(principals), _ctx())
    assert len(plans) == 1
    assert plans[0].effect_class == EFFECT_CLASS_CODE_UPGRADE
    return plans[0].run()


def test_impl_nonzero_with_resolved_principal_is_proven_now():
    eff = _run_plan((PRINCIPAL,))
    assert eff.verdict == VERDICT_PROVEN
    assert eff.reason == "indexed_upgrade_plus_current_state"
    assert eff.concrete["current_check_passed"] is True


# A historically-upgraded proxy with NO resolved upgrade authority (renounced/frozen) must
# WITHHOLD: unknown, never proven. A renounced authority resolves to the zero address, which
# counts as no authority.
@pytest.mark.parametrize(
    "principals",
    [
        pytest.param((), id="without-principals"),
        pytest.param((ZERO,), id="zero-address-principal"),
    ],
)
def test_impl_nonzero_without_a_live_authority_is_unknown_not_proven(principals):
    eff = _run_plan(principals)
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "historical_only_current_check_failed"
    assert eff.concrete["current_check_passed"] is False
