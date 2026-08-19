"""Tier-0 code-upgrade current-state check.

An indexed UpgradeEvent proves only PAST capability; a present-tense "upgradeable
now" claim requires the current capability be present NOW — impl slot still
non-zero AND a resolved, non-renounced upgrade authority. A proxy that was
upgraded historically but has since renounced its upgrade authority (impl slot
stays non-zero — freezing does not zero it) must NOT mint a proven verdict.

Off the wire: the current check is a static/DB read; these tests drive
``_code_upgrade_plans`` against a stubbed session (a proxy Contract row + an
UpgradeEvent) and execute the returned plan's ``run`` — no anvil, no RPC.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from db.models import Contract  # noqa: E402
from services.effects.config import (  # noqa: E402
    EFFECT_CLASS_CODE_UPGRADE,
    VERDICT_PROVEN,
    VERDICT_UNKNOWN,
)
from services.effects.orchestrator import ProbeContext, _code_upgrade_plans  # noqa: E402
from services.effects.selection import Candidate  # noqa: E402
from tests.support.effects_stubs import RecordingStore  # noqa: E402

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
    # simulate is never touched on the Tier-0 path (it returns before any sim);
    # a MagicMock that would raise if called guards that invariant.
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
    """impl non-zero + a resolved non-zero upgrade authority ⇒ present-tense
    capability proven (current-state check passed)."""
    eff = _run_plan((PRINCIPAL,))
    assert eff.verdict == VERDICT_PROVEN
    assert eff.reason == "indexed_upgrade_plus_current_state"
    assert eff.concrete["current_check_passed"] is True


def test_impl_nonzero_without_principals_is_unknown_not_proven():
    """The bug being fixed: a historically-upgraded proxy with NO resolved
    upgrade authority (renounced/frozen) must WITHHOLD — unknown, never proven."""
    eff = _run_plan(())
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "historical_only_current_check_failed"
    assert eff.concrete["current_check_passed"] is False


def test_impl_nonzero_with_zero_address_principal_is_unknown():
    """A renounced authority resolves to the zero address — treated as no
    authority, so the current-state check fails ⇒ unknown, not proven."""
    eff = _run_plan((ZERO,))
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "historical_only_current_check_failed"
    assert eff.concrete["current_check_passed"] is False
