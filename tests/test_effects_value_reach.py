"""§5b downstream value-reach: which address the money is keyed on, and which
execution the reach is read from.

Every one of the six proven ``value_out`` rows on the 2026-07-25 live run carried
``observed_reach_value_usd: 0.0`` with ``reach_indeterminate: true`` — the
fallback firing at 100%, and its floor computing to zero on deployments holding
billions. Two independent causes, both here:

1. ``contract_balances`` is FETCHED for the proxy (``resolution_worker`` reads
   ``proxy_address or address``) but STORED on the implementation's contract row.
   Keying the holder set and the acting floor on ``contracts.address`` therefore
   named an address that holds nothing and that no ``Transfer`` log can mention.
2. The reach was read off the UNSEEDED call, which on every seeded verdict is the
   one that reverted and carries no logs at all.
"""

from __future__ import annotations

from services.effects import recipes
from services.effects.config import VERDICT_PROVEN
from services.effects.harness import SimContext
from services.effects.selection import build_authority_graph, select_candidates
from services.effects.simulate import SimCallResult, SimResult
from tests.conftest import ADDR, requires_postgres
from tests.test_effects_harness import RecordingStore, transfer_log
from tests.test_effects_selection import _balance, _contract, _fn, _principal, _protocol

CTX = SimContext(chain_id=1, block=1000, hardfork="prague")


# ---------------------------------------------------------------------------
# 1. which address the balances are keyed on
# ---------------------------------------------------------------------------


@requires_postgres
def test_balances_are_keyed_on_the_address_that_holds_them(db_session):
    """The implementation's row carries the proxy's money. Only the proxy can
    appear in a ``Transfer`` log, so only the proxy may key the reach inputs."""
    p = _protocol(db_session, "reach-keying")
    impl = _contract(db_session, p.id, ADDR(0x2001))
    deployment = ADDR(0x2002)
    _fn(
        db_session, impl.id, name="withdraw", selector="0xbbbb0001", effect_targets=["S"], deployment_address=deployment
    )
    _balance(db_session, impl.id, 1_000.0)
    db_session.flush()

    graph = build_authority_graph(db_session, p.id)
    assert graph.deployment_balance[deployment.lower()] == 1_000.0
    # The code-plane key stays put: the control closure is keyed on it.
    assert graph.balance[impl.address.lower()] == 1_000.0


@requires_postgres
def test_two_implementations_behind_one_proxy_do_not_double_count(db_session):
    """Each code row carries a copy of the SAME deployment's holdings."""
    p = _protocol(db_session, "reach-dedup")
    deployment = ADDR(0x2102)
    for n, addr in enumerate((ADDR(0x2100), ADDR(0x2101))):
        c = _contract(db_session, p.id, addr)
        _fn(
            db_session,
            c.id,
            name=f"f{n}",
            selector=f"0xbbbb010{n}",
            effect_targets=["S"],
            deployment_address=deployment,
        )
        _balance(db_session, c.id, 500.0)
    db_session.flush()

    assert build_authority_graph(db_session, p.id).deployment_balance[deployment.lower()] == 500.0


@requires_postgres
def test_candidate_floor_and_holder_set_use_the_holding_address(db_session):
    p = _protocol(db_session, "reach-candidate")
    impl = _contract(db_session, p.id, ADDR(0x2201))
    deployment = ADDR(0x2202)
    fn = _fn(
        db_session,
        impl.id,
        name="withdraw",
        selector="0xbbbb0201",
        effect_targets=["S"],
        deployment_address=deployment,
    )
    _principal(db_session, fn.id, ADDR(0x2203))
    _balance(db_session, impl.id, 7_500.0)
    db_session.flush()

    cand = next(c for c in select_candidates(db_session, p.id) if c.selector == "0xbbbb0201")
    assert cand.acting_balance_usd == 7_500.0
    assert (deployment.lower(), 7_500.0) in cand.value_holders


# ---------------------------------------------------------------------------
# 2. which execution the reach is read from
# ---------------------------------------------------------------------------

CONTRACT = "0x" + "c0" * 20
PRINCIPAL = "0x" + "22" * 20
PAYEE = "0x" + "33" * 20
HOLDER = "0x" + "44" * 20


def _value_out(blocks, *, seeding=None, holders=((CONTRACT, 100.0),), floor=100.0):
    remaining = list(blocks)

    def simulate(calls, block_tag=None, overrides=None):
        return remaining.pop(0)

    return recipes.value_out(
        simulate=simulate,
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata="0x" + "de" * 4,
        simulate_supported=True,
        value_holders=holders,
        acting_balance_usd=floor,
        seeder=(lambda _req: seeding),
        seeded_calldata={18: "0x" + "de" * 4},
        target_payable=True,
    )


def test_reach_is_read_from_the_execution_the_verdict_came_from():
    """The unseeded call reverted and has no logs; reading reach off it made
    every seeded verdict indeterminate no matter what the seeded call moved."""
    from services.effects.seeding import Seeding

    reverted = SimResult(calls=(SimCallResult(False, "0x", "0x", ()),))
    seeded = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(CONTRACT, CONTRACT, PAYEE, 5),)),))
    eff = _value_out(
        [reverted, seeded],
        seeding=Seeding(overrides={}, readback_calls=(), readback_expected=(), tokens=(), decimals=18),
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.concrete["observed_reach_holders"] == [CONTRACT]
    assert eff.concrete["observed_reach_value_usd"] == 100.0
    assert "reach_indeterminate" not in eff.concrete


def test_a_holder_that_moved_nothing_still_floors_and_stays_indeterminate():
    """``reach_indeterminate`` keeps meaning "unmeasured here" — the floor is the
    acting deployment's own balance, never a claim that reach is zero."""
    moved = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(CONTRACT, CONTRACT, PAYEE, 5),)),))
    eff = _value_out([moved], holders=((HOLDER, 42.0),), floor=250.0)
    assert eff.concrete["observed_reach_value_usd"] == 250.0
    assert eff.concrete["reach_indeterminate"] is True


def test_a_zero_balance_deployment_publishes_zero_reach_AND_says_it_is_unmeasured():
    """W0-7 fixture 8 — the shape that makes ``observed_reach_value_usd: 0.0``
    ambiguous, and the flag that resolves it.

    The acting deployment holds nothing, so the floor IS zero. Published alone,
    ``0.0`` is indistinguishable from "we measured downstream reach and it was
    nothing" — a proven absence — when what happened is that nothing was measured
    and the floor happened to be empty. Both keys must travel together, and this
    is the only test in which the floor's own value is zero: every other one
    floors to 250.0 or 100.0, so a consumer reading the number without the flag
    still looked right.
    """
    moved_nothing = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(CONTRACT, CONTRACT, PAYEE, 5),)),))
    eff = _value_out([moved_nothing], holders=((HOLDER, 42.0),), floor=0.0)

    assert eff.verdict == VERDICT_PROVEN
    # The value_out itself is PROVEN — value left — while its reach is unknown.
    # A row that pairs a proven outflow with a zero reach and no flag reads as
    # "moves money, reaches nothing".
    assert eff.concrete["observed_reach_value_usd"] == 0.0
    assert eff.concrete["reach_indeterminate"] is True
    assert "observed_reach_holders" not in eff.concrete


def test_zero_reach_without_the_flag_is_a_measured_zero_not_a_floor():
    """The discriminating sibling: the SAME published number, earned. The holder
    moved value, the sum of what moved is genuinely 0.0 USD, and no flag is set.
    Without this row, "0.0 always carries the flag" would be indistinguishable
    from "the flag is unconditional"."""
    moved = SimResult(
        calls=(
            SimCallResult(
                True,
                "0x",
                None,
                (transfer_log(CONTRACT, CONTRACT, PAYEE, 5), transfer_log(CONTRACT, HOLDER, PAYEE, 7)),
            ),
        )
    )
    eff = _value_out([moved], holders=((HOLDER, 0.0),), floor=250.0)

    assert eff.concrete["observed_reach_value_usd"] == 0.0
    assert eff.concrete["observed_reach_holders"] == [HOLDER.lower()]
    assert "reach_indeterminate" not in eff.concrete
