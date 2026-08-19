"""Downstream value-reach: which address the money is keyed on, and which
execution the reach is read from.

Every one of the six proven ``value_out`` rows on the 2026-07-25 live run carried
``observed_reach_value_usd: 0.0`` with ``reach_indeterminate: true`` — the
fallback firing at 100%, and its floor computing to zero on deployments holding
billions. Two independent causes, both here (and a third the shape itself carried:
publishing the floor under the key that means MEASURED reach, fixed since):

1. ``contract_balances`` is FETCHED for the proxy (``resolution_worker`` reads
   ``proxy_address or address``) but STORED on the implementation's contract row.
   Keying the holder set and the acting floor on ``contracts.address`` therefore
   named an address that holds nothing and that no ``Transfer`` log can mention.
2. The reach was read off the UNSEEDED call, which on every seeded verdict is the
   one that reverted and carries no logs at all.
"""

from __future__ import annotations

from services.effects import recipes
from services.effects.config import NATIVE_ASSET_LOG_EMITTER, VERDICT_PROVEN  # noqa: F401
from services.effects.harness import SimContext
from services.effects.selection import (
    HOLDINGS_COMPLETENESS_AT_PAGE_CAP,
    AssetHolding,
    build_authority_graph,
    select_candidates,
)
from services.effects.simulate import SimCallResult, SimResult
from tests.conftest import ADDR, requires_postgres
from tests.support.effects_builders import _balance, _contract, _fn, _principal, _protocol
from tests.support.effects_stubs import RecordingStore, transfer_log
from utils.execution_record import PROVING_EXECUTION_KEY

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
    # Per ASSET: ``_balance`` writes a NATIVE row, so the holding is keyed on the
    # emitter ``eth_simulateV1`` uses for a native move — the address a synthetic
    # Transfer log for it actually carries.
    assert AssetHolding(deployment.lower(), NATIVE_ASSET_LOG_EMITTER, 7_500.0) in cand.value_holders


@requires_postgres
def test_a_contract_with_no_balance_row_carries_no_floor_not_a_zero(db_session):
    """The absence the INNER join produces must survive the candidate build.

    ``build_authority_graph`` joins ``contract_balances`` INNER precisely so a
    contract with no current row yields NO ``deployment_balance`` key — "holds
    nothing", "not fetched" and "fetch failed" are one shape on that plane, so
    none of them may be published as a bound. The candidate now carries that as
    ``None``; it used to read the key with ``.get(acting, _ZERO_USD)`` and hand
    ``_add_reach`` a ``0.0`` floor for a deployment nobody had ever priced.
    """
    p = _protocol(db_session, "reach-no-balance")
    impl = _contract(db_session, p.id, ADDR(0x2301))
    deployment = ADDR(0x2302)
    _fn(
        db_session,
        impl.id,
        name="route",
        selector="0xbbbb0301",
        effect_targets=["S"],
        deployment_address=deployment,
    )
    db_session.flush()

    graph = build_authority_graph(db_session, p.id)
    assert deployment.lower() not in graph.deployment_balance

    cand = next(c for c in select_candidates(db_session, p.id) if c.selector == "0xbbbb0301")
    assert cand.acting_balance_usd is None


@requires_postgres
def test_a_priced_zero_balance_row_carries_a_floor_of_zero(db_session):
    """The discriminating sibling: a row EXISTS and prices to $0.00, which is a
    witness — weak, but read — so the candidate carries ``0.0`` and not ``None``.

    Without this row, "``None`` whenever the floor is zero" would be
    indistinguishable from the three-state carry, and the fix would have traded
    one collapse for another.
    """
    p = _protocol(db_session, "reach-priced-zero")
    impl = _contract(db_session, p.id, ADDR(0x2401))
    deployment = ADDR(0x2402)
    _fn(
        db_session,
        impl.id,
        name="route",
        selector="0xbbbb0401",
        effect_targets=["S"],
        deployment_address=deployment,
    )
    _balance(db_session, impl.id, 0.0)
    db_session.flush()

    graph = build_authority_graph(db_session, p.id)
    assert graph.deployment_balance[deployment.lower()] == 0

    cand = next(c for c in select_candidates(db_session, p.id) if c.selector == "0xbbbb0401")
    assert cand.acting_balance_usd == 0.0
    assert cand.acting_balance_usd is not None


# ---------------------------------------------------------------------------
# 2. which execution the reach is read from
# ---------------------------------------------------------------------------

CONTRACT = "0x" + "c0" * 20
PRINCIPAL = "0x" + "22" * 20
PAYEE = "0x" + "33" * 20
HOLDER = "0x" + "44" * 20
# The asset every ``transfer_log`` below is emitted BY, so a holding of it is the
# holding that moved. Reach matching is per asset.
TOKEN = "0x" + "7a" * 20


def _value_out(
    blocks, *, seeding=None, holders=(AssetHolding(CONTRACT, TOKEN, 100.0),), floor: float | None = 100.0, tvl=None
):
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
        protocol_tvl_usd=tvl,
        seeder=(lambda _req: seeding),
        seeded_calldata={18: "0x" + "de" * 4},
        target_payable=True,
    )


def test_reach_is_read_from_the_execution_the_verdict_came_from():
    """The unseeded call reverted and has no logs; reading reach off it made
    every seeded verdict indeterminate no matter what the seeded call moved."""
    from services.effects.seeding import Seeding

    reverted = SimResult(calls=(SimCallResult(False, "0x", "0x", ()),))
    seeded = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5),)),))
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
    acting deployment's own balance, never a claim that reach is zero.

    KEPT deliberately: this test exercises a LIVE branch. Only the key names moved —
    the producer now publishes the floor as ``observed_reach_floor_usd`` and withholds
    ``observed_reach_value_usd``, because the floor being read AS the reach is the
    defect. The branch, the holder set and the intent are untouched."""
    moved = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5),)),))
    eff = _value_out([moved], holders=(AssetHolding(HOLDER, TOKEN, 42.0),), floor=250.0)
    assert eff.concrete["observed_reach_floor_usd"] == 250.0
    assert eff.concrete["reach_determined"] is False
    assert eff.concrete["reach_indeterminate"] is True
    assert "observed_reach_value_usd" not in eff.concrete


def test_a_zero_balance_deployment_publishes_no_reach_number_at_all():
    """INVERTED, to gate the floor/measured-reach key split.

    The acting deployment holds nothing, so the floor IS zero. This branch fires for
    every zap / router / adapter that moves value it does not hold — 18 armed
    ``flow.out`` functions on 6 zero-balance contracts locally — and it used to
    publish that zero as ``observed_reach_value_usd``. A consumer reading the number
    and ignoring the flag therefore got **"$0 reach" for a function that may move
    millions**: a proven absence minted out of a non-observation, which is exactly
    what the flag beside it was supposed to prevent and could not, because nothing
    forces a consumer to read two keys.

    The number is now simply not there. ``reach_determined: False`` is the answer,
    and the floor keeps its own name — this is the only test where that floor is
    zero, so it is also the one place where the old shape's ambiguity was total.
    """
    moved_nothing = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5),)),))
    eff = _value_out([moved_nothing], holders=(AssetHolding(HOLDER, TOKEN, 42.0),), floor=0.0)

    assert eff.verdict == VERDICT_PROVEN
    # The value_out itself is PROVEN — value left — while its reach is unknown.
    assert "observed_reach_value_usd" not in eff.concrete
    assert eff.concrete["reach_determined"] is False
    assert eff.concrete["reach_indeterminate"] is True
    assert eff.concrete["observed_reach_floor_usd"] == 0.0
    assert "observed_reach_holders" not in eff.concrete


def test_an_unwitnessed_acting_balance_publishes_no_floor_key():
    """The whole recipe, not just ``_add_reach``: an acting deployment with NO
    current balance row reaches ``value_out`` as ``acting_balance_usd=None`` and
    comes out the other side with the floor key ABSENT.

    The sibling of the test above, and the pair is the point. There the acting
    deployment's sheet was READ and summed to zero, which is a (weak) witness and
    keeps its key. Here nothing was read at all, and a ``0.0`` in its place would
    be a bound minted out of a failed or never-attempted fetch — the defect the
    INNER join in ``build_authority_graph`` exists to prevent and that
    ``selection.py``'s old ``.get(acting, _ZERO_USD)`` undid one line later.
    """
    moved_nothing = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5),)),))
    eff = _value_out([moved_nothing], holders=(AssetHolding(HOLDER, TOKEN, 42.0),), floor=None)

    assert eff.verdict == VERDICT_PROVEN
    assert eff.concrete["reach_determined"] is False
    assert eff.concrete["reach_indeterminate"] is True
    # Not present-and-null: the key does not exist. ``in`` is the assertion,
    # because a ``null`` is what a naive "carry the None through" would produce
    # and it reads as a value to every consumer that does a bare ``is not None``
    # on ``.get()``.
    assert "observed_reach_floor_usd" not in eff.concrete
    assert "observed_reach_value_usd" not in eff.concrete
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
                (transfer_log(TOKEN, CONTRACT, PAYEE, 5), transfer_log(TOKEN, HOLDER, PAYEE, 7)),
            ),
        )
    )
    eff = _value_out([moved], holders=(AssetHolding(HOLDER, TOKEN, 0.0),), floor=250.0)

    assert eff.concrete["observed_reach_value_usd"] == 0.0
    assert eff.concrete["observed_reach_holders"] == [HOLDER.lower()]
    assert eff.concrete["reach_determined"] is True
    assert "reach_indeterminate" not in eff.concrete
    # THE DISCRIMINATION THE KEY SPLIT BUYS: a MEASURED zero and an unmeasured one are now two
    # different payloads. Before, both published ``observed_reach_value_usd: 0.0``
    # and differed only by a flag a consumer had to remember to read.
    assert "observed_reach_floor_usd" not in eff.concrete


# ---------------------------------------------------------------------------
# 3. The reach figure is per ASSET, and an asset we cannot value says so
# ---------------------------------------------------------------------------

EETH = "0x" + "e1" * 20
NATIVE = NATIVE_ASSET_LOG_EMITTER
# The measured shape of the asset-blind over-claim: WeETH's proxy holds $3,488,954,369 of
# eETH (99.99% of its sheet) and NO native balance row at all, and the probe's
# contract-balance seed made it move synthetic native ETH.
WEETH_SHEET = (
    AssetHolding(CONTRACT, EETH, 3_488_954_369.29),
    AssetHolding(CONTRACT, TOKEN, 759.15),
)


def _native_transfer_out(holder: str = CONTRACT) -> SimResult:
    """One synthetic native Transfer out of ``holder``, exactly as
    ``eth_simulateV1``'s ``traceTransfers`` emits it (emitter measured live)."""
    return SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(NATIVE, holder, PAYEE, 10**18),)),))


def test_a_native_move_does_not_reach_a_holders_token_balance_sheet():
    """The reproduction. Asset-blind matching attributed a holder's ENTIRE USD to
    whichever asset happened to move: the weETH proxy moved seeded native ETH and the
    row published $3.489B of reach — 64.96% of ALL published reach USD in the DB came
    from two rows of this shape, both truly $0.

    The holder DID move value, so this is not the not-witnessed branch: it is
    witnessed and NOT valued. We hold no native balance row for this deployment, and
    absence there is "holds nothing" / "not fetched" / "fetch failed" collapsed into
    one shape — so the only honest USD is unknown."""
    eff = _value_out([_native_transfer_out()], holders=WEETH_SHEET, floor=3_488_955_156.06)

    assert eff.verdict == VERDICT_PROVEN
    assert eff.concrete["reach_determined"] is False
    assert "observed_reach_value_usd" not in eff.concrete
    assert eff.concrete["observed_reach_holders"] == [CONTRACT]
    assert eff.concrete["observed_reach_assets"] == [NATIVE]
    assert eff.concrete["observed_reach_unvalued_assets"] == [NATIVE]
    # Nothing priced moved, so not even a partial floor is published.
    assert "observed_reach_priced_usd" not in eff.concrete
    # And the eETH figure appears NOWHERE on the row.
    assert "3488954369" not in str(eff.concrete)


def test_the_asset_that_moved_contributes_its_own_holding_and_only_it():
    """The positive control: the SAME sheet, and this time the token we hold priced is
    the one that moves. The reach is that holding — not the sheet total, and not
    nothing."""
    moved = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5),)),))
    eff = _value_out([moved], holders=WEETH_SHEET, floor=3_488_955_156.06)

    assert eff.concrete["reach_determined"] is True
    assert eff.concrete["observed_reach_value_usd"] == 759.15
    assert eff.concrete["observed_reach_assets"] == [TOKEN.lower()]
    assert eff.concrete["observed_reach_holders"] == [CONTRACT]


def test_a_priced_native_holding_is_matched_by_the_emitter_the_node_uses():
    """The other half of the native fix, and the reason the refuted ``only_asset``
    proposal would have under-claimed 100%: a native holding IS matchable, as long as
    it is keyed on the pseudo-address ``traceTransfers`` puts in the log's ``address``
    field. Measured against the live node (3 reads + a pinned read at 25619159)."""
    holdings = (AssetHolding(CONTRACT, NATIVE, 4_200.0), AssetHolding(CONTRACT, EETH, 3_488_954_369.29))
    eff = _value_out([_native_transfer_out()], holders=holdings, floor=1.0)

    assert eff.concrete["reach_determined"] is True
    assert eff.concrete["observed_reach_value_usd"] == 4_200.0
    assert eff.concrete["observed_reach_assets"] == [NATIVE]


def test_an_unpriced_holding_that_moves_makes_the_total_not_determined():
    """1001 of 1376 local ``contract_balances`` rows carry ``price_usd = 0``, which the
    producer writes for "no price known"; ``usd_value`` is NULL on them. Reading that
    as $0 is a CONFIDENT LOW value where the answer is unknown — "unknown" must rank
    worse than a proven-benign figure, in its numeric form. The priced part survives as an explicit partial floor."""
    unpriced = "0x" + "9d" * 20
    holdings = (AssetHolding(CONTRACT, TOKEN, 759.15), AssetHolding(CONTRACT, unpriced, None))
    moved = SimResult(
        calls=(
            SimCallResult(
                True,
                "0x",
                None,
                (transfer_log(TOKEN, CONTRACT, PAYEE, 5), transfer_log(unpriced, CONTRACT, PAYEE, 9)),
            ),
        )
    )
    eff = _value_out([moved], holders=holdings, floor=1.0)

    assert eff.concrete["reach_determined"] is False
    assert "observed_reach_value_usd" not in eff.concrete
    assert eff.concrete["observed_reach_unvalued_assets"] == [unpriced]
    assert eff.concrete["observed_reach_priced_usd"] == 759.15
    assert eff.concrete["observed_reach_assets"] == sorted([TOKEN.lower(), unpriced])


def test_two_holders_moving_two_assets_sum_only_those_two_holdings():
    """The multi-holder sum still works, and it is a sum over (holder, asset) pairs —
    each holder contributes only the asset it was observed moving."""
    other = "0x" + "b1" * 20
    holdings = (
        AssetHolding(CONTRACT, TOKEN, 100.0),
        AssetHolding(CONTRACT, EETH, 999_999.0),
        AssetHolding(other, EETH, 25.0),
    )
    moved = SimResult(
        calls=(
            SimCallResult(
                True,
                "0x",
                None,
                (transfer_log(TOKEN, CONTRACT, PAYEE, 5), transfer_log(EETH, other, PAYEE, 7)),
            ),
        )
    )
    eff = _value_out([moved], holders=holdings, floor=1.0)

    assert eff.concrete["reach_determined"] is True
    assert eff.concrete["observed_reach_value_usd"] == 125.0
    assert eff.concrete["observed_reach_holders"] == sorted([CONTRACT, other])


# ---------------------------------------------------------------------------
# 4. the corroborating ceiling: reach can never exceed the protocol's own TVL
# ---------------------------------------------------------------------------


def test_a_reach_above_protocol_tvl_is_refused_not_published():
    """The bad row published $3.489B against a protocol TVL of $3.297B and nothing
    checked. A sum above the ceiling is not clamped — a clamp invents a number nothing
    measured — it is REFUSED, with both figures recorded so the contradiction is
    inspectable."""
    holdings = (AssetHolding(CONTRACT, TOKEN, 3_488_955_156.06),)
    moved = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5),)),))
    eff = _value_out([moved], holders=holdings, floor=1.0, tvl=3_297_344_734.00)

    assert eff.concrete["reach_tvl_check"] == "exceeds_protocol_tvl"
    assert eff.concrete["reach_determined"] is False
    assert "observed_reach_value_usd" not in eff.concrete
    assert eff.concrete["observed_reach_rejected_usd"] == 3_488_955_156.06
    assert eff.concrete["protocol_tvl_usd"] == 3_297_344_734.00


def test_a_reach_within_protocol_tvl_passes_and_says_it_was_checked():
    holdings = (AssetHolding(CONTRACT, TOKEN, 100.0),)
    moved = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5),)),))
    eff = _value_out([moved], holders=holdings, floor=1.0, tvl=1_000.0)

    assert eff.concrete["reach_tvl_check"] == "within_protocol_tvl"
    assert eff.concrete["reach_determined"] is True
    assert eff.concrete["observed_reach_value_usd"] == 100.0


def test_no_tvl_snapshot_skips_the_ceiling_out_loud():
    """The skip is a PUBLISHED state. An absent ceiling that looked like a passed
    one would be a mitigation that never fires and cannot be told from one that does —
    exactly the shape being ruled out."""
    holdings = (AssetHolding(CONTRACT, TOKEN, 100.0),)
    moved = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5),)),))
    eff = _value_out([moved], holders=holdings, floor=1.0, tvl=None)

    assert eff.concrete["reach_tvl_check"] == "skipped_no_tvl"
    assert eff.concrete["reach_determined"] is True
    assert eff.concrete["observed_reach_value_usd"] == 100.0


def _partial_floor(*, floor_usd: float, tvl: float | None):
    """One ``value_out`` on the PARTIAL-FLOOR branch: two assets leave the holder,
    only one of them has a priced holding, so the total is not determined and
    ``observed_reach_priced_usd`` is the floor. ``floor_usd`` is that floor."""
    logs = (transfer_log(TOKEN, CONTRACT, PAYEE, 5), transfer_log(EETH, CONTRACT, PAYEE, 5))
    moved = SimResult(calls=(SimCallResult(True, "0x", None, logs),))
    return _value_out([moved], holders=(AssetHolding(CONTRACT, TOKEN, floor_usd),), floor=0.0, tvl=tvl)


def test_a_priced_floor_above_protocol_tvl_is_refused_like_a_measured_figure():
    """The ceiling used to guard only the measured branch: the unvalued branch
    set ``observed_reach_priced_usd`` and RETURNED above ``_reach_tvl_state``, so a
    floor above the protocol's own measured TVL was publishable with no
    ``reach_tvl_check`` at all — the same contradiction the ceiling exists to catch,
    on the sibling key, and worse here than on a measured total: the floor is a LOWER
    bound over a SUBSET of the assets that moved, so exceeding the ceiling cannot be
    explained away by an upper bound being loose.

    The unvalued-asset disclosure is an INDEPENDENT fact and survives the refusal —
    value did leave the holder; what was refused is the priced part's USD."""
    eff = _partial_floor(floor_usd=3_488_955_156.06, tvl=3_297_344_734.00)

    assert eff.concrete["reach_determined"] is False
    assert eff.concrete["reach_tvl_check"] == "exceeds_protocol_tvl"
    assert "observed_reach_priced_usd" not in eff.concrete
    assert eff.concrete["observed_reach_rejected_usd"] == 3_488_955_156.06
    assert eff.concrete["protocol_tvl_usd"] == 3_297_344_734.00
    assert eff.concrete["observed_reach_unvalued_assets"] == [EETH]
    assert eff.concrete["observed_reach_unvalued_reasons"] == ["asset_not_in_recorded_holdings"]
    # NOT the measured key, and not the never-witnessed floor either: this row's three
    # states stay exactly where they were.
    assert "observed_reach_value_usd" not in eff.concrete
    assert "reach_indeterminate" not in eff.concrete


def test_a_priced_floor_within_protocol_tvl_is_published_and_says_it_was_checked():
    """POSITIVE CONTROL for the refusal above: the floor branch keeps publishing its
    floor, and the ceiling's outcome is now visible on it (it was absent entirely)."""
    eff = _partial_floor(floor_usd=100.0, tvl=1_000.0)

    assert eff.concrete["reach_determined"] is False
    assert eff.concrete["reach_tvl_check"] == "within_protocol_tvl"
    assert eff.concrete["observed_reach_priced_usd"] == 100.0
    assert eff.concrete["observed_reach_unvalued_assets"] == [EETH]


def test_a_priced_floor_with_no_tvl_snapshot_skips_the_ceiling_out_loud():
    """The same on this branch: no ``defillama_tvl`` means the ceiling did not run, and
    the floor is published with the skip beside it rather than looking checked."""
    eff = _partial_floor(floor_usd=100.0, tvl=None)

    assert eff.concrete["reach_tvl_check"] == "skipped_no_tvl"
    assert eff.concrete["observed_reach_priced_usd"] == 100.0


def test_an_unvalued_branch_with_nothing_priced_publishes_no_ceiling_outcome():
    """The fourth input shape, and the one that must NOT gain a key: no asset that
    moved had a priced holding, so there is no figure for a ceiling to bear on.
    ``within_protocol_tvl`` over an absent number would read as a check that passed
    on a figure nobody published."""
    logs = (transfer_log(TOKEN, CONTRACT, PAYEE, 5), transfer_log(EETH, CONTRACT, PAYEE, 5))
    moved = SimResult(calls=(SimCallResult(True, "0x", None, logs),))
    # A holding row exists for TOKEN but carries no price (usd_value None) → unpriced,
    # and EETH has no row at all. Nothing priced.
    eff = _value_out([moved], holders=(AssetHolding(CONTRACT, TOKEN, None),), floor=0.0, tvl=1_000.0)

    assert eff.concrete["reach_determined"] is False
    assert "reach_tvl_check" not in eff.concrete
    assert "observed_reach_priced_usd" not in eff.concrete
    assert "observed_reach_rejected_usd" not in eff.concrete
    assert eff.concrete["observed_reach_unvalued_assets"] == sorted([TOKEN, EETH])
    assert eff.concrete["observed_reach_unvalued_reasons"] == sorted(
        ["unpriced_holding", "asset_not_in_recorded_holdings"]
    )


def test_a_truncated_holdings_list_names_truncation_as_the_reason():
    """Consumer rule for a capped holdings fetch: it must LOWER CONFIDENCE, never produce a
    confident low value. An asset absent from a capped list may simply never have been
    fetched.

    INVERTED: the control arm used to assert ``unrecorded_asset`` for a
    holder whose list was "whole". Nothing can establish that — the stored rows are the
    fetch's output AFTER its zero-balance filter, so a below-cap count is consistent
    with a full page — so the below-cap reason now says only that the asset is not in
    the holdings we RECORDED. The old name asserted a proven absence derived from a
    count whose input had already discarded rows."""
    holdings = (AssetHolding(CONTRACT, TOKEN, 100.0, completeness=HOLDINGS_COMPLETENESS_AT_PAGE_CAP),)
    moved = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(EETH, CONTRACT, PAYEE, 5),)),))
    eff = _value_out([moved], holders=holdings, floor=1.0)

    assert eff.concrete["reach_determined"] is False
    assert eff.concrete["observed_reach_unvalued_reasons"] == ["holdings_at_page_cap"]
    # The below-cap arm: still a confidence gap, and the reason no longer claims the
    # holder does not hold the asset.
    eff2 = _value_out([moved], holders=(AssetHolding(CONTRACT, TOKEN, 100.0),), floor=1.0)
    assert eff2.concrete["observed_reach_unvalued_reasons"] == ["asset_not_in_recorded_holdings"]
    # NEGATIVE CONTROL, both arms: an asset the holder DOES hold priced is valued, so
    # neither reason is a blanket refusal to value anything.
    held = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5),)),))
    assert _value_out([held], holders=holdings, floor=1.0).concrete["observed_reach_value_usd"] == 100.0


def test_two_logs_of_one_asset_out_of_one_holder_attribute_that_holding_once():
    """The attributed figure is a holder's WHOLE recorded balance for an asset, so a
    second ``Transfer`` log of the same asset out of the same holder must contribute
    nothing.

    Summing per LOG published a MULTIPLE of the entire balance under
    ``observed_reach_value_usd`` — the field whose own docstring calls it "a
    conservative upper bound (a holder's full on-chain balance attributed when value
    provably leaves it)". Two logs made a $100 holding read as $200 of reach: not an
    upper bound, a new over-claim on a published money figure, in the same field and
    the same direction as the asset-blind over-claim above. The triggering shape is the
    one ``_resolve_destination_shape`` names verbatim — "a withdrawal that emits
    several Transfer logs (burn + send, or send + fee to the same address)"."""
    holdings = (AssetHolding(CONTRACT, TOKEN, 100.0),)
    one_log = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5),)),))
    send_and_fee = SimResult(
        calls=(
            SimCallResult(
                True,
                "0x",
                None,
                (transfer_log(TOKEN, CONTRACT, PAYEE, 5), transfer_log(TOKEN, CONTRACT, HOLDER, 1)),
            ),
        )
    )
    single = _value_out([one_log], holders=holdings, floor=0.0)
    doubled = _value_out([send_and_fee], holders=holdings, floor=0.0)

    assert single.concrete["observed_reach_value_usd"] == 100.0
    assert doubled.concrete["observed_reach_value_usd"] == 100.0, (
        "a second log of the same asset added the balance again"
    )
    assert doubled.concrete["observed_reach_holders"] == [CONTRACT]
    assert doubled.concrete["observed_reach_assets"] == [TOKEN]
    # POSITIVE CONTROL: distinct (holder, asset) pairs DO sum — the dedup is on the
    # pair, not a cap on the total.
    two_assets = SimResult(
        calls=(
            SimCallResult(
                True,
                "0x",
                None,
                (transfer_log(TOKEN, CONTRACT, PAYEE, 5), transfer_log(EETH, CONTRACT, PAYEE, 5)),
            ),
        )
    )
    summed = _value_out(
        [two_assets],
        holders=(AssetHolding(CONTRACT, TOKEN, 100.0), AssetHolding(CONTRACT, EETH, 25.0)),
        floor=0.0,
    )
    assert summed.concrete["observed_reach_value_usd"] == 125.0
    assert summed.concrete["observed_reach_assets"] == sorted([TOKEN, EETH])


def test_the_partial_floor_and_the_tvl_ceiling_both_read_the_deduped_sum():
    """Two knock-ons of the per-log sum, pinned so neither returns.

    (a) ``observed_reach_priced_usd`` is published as a partial FLOOR on the unvalued
    branch and inherited the same inflation. (b) An inflated sum can trip the TVL
    ceiling, publishing ``exceeds_protocol_tvl`` + ``reach_determined: false`` for a
    row that is legitimately within TVL — the envelope refusing a figure only its own
    arithmetic broke."""
    logs = (
        transfer_log(TOKEN, CONTRACT, PAYEE, 5),
        transfer_log(TOKEN, CONTRACT, HOLDER, 1),
        transfer_log(EETH, CONTRACT, PAYEE, 5),
    )
    moved = SimResult(calls=(SimCallResult(True, "0x", None, logs),))
    # EETH has no holding row at all → the total is not determined and the priced part
    # is the floor. It must be the TOKEN holding once, not twice.
    partial = _value_out([moved], holders=(AssetHolding(CONTRACT, TOKEN, 100.0),), floor=0.0)
    assert partial.concrete["reach_determined"] is False
    assert partial.concrete["observed_reach_priced_usd"] == 100.0

    # The ceiling: $100 of reach under a $150 TVL is within it. Per-log summing made
    # the same call read as $200 and the row was refused.
    priced = SimResult(
        calls=(
            SimCallResult(
                True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5), transfer_log(TOKEN, CONTRACT, HOLDER, 1))
            ),
        )
    )
    within = _value_out([priced], holders=(AssetHolding(CONTRACT, TOKEN, 100.0),), floor=0.0, tvl=150.0)
    assert within.concrete["reach_tvl_check"] == "within_protocol_tvl"
    assert within.concrete["reach_determined"] is True
    assert within.concrete["observed_reach_value_usd"] == 100.0
    # NEGATIVE CONTROL: the ceiling still fires on a sum that genuinely exceeds TVL.
    over = _value_out([priced], holders=(AssetHolding(CONTRACT, TOKEN, 100.0),), floor=0.0, tvl=50.0)
    assert over.concrete["reach_tvl_check"] == "exceeds_protocol_tvl"
    assert over.concrete["reach_determined"] is False


# ---------------------------------------------------------------------------
# 5. The disclosure is keyed the way the arithmetic is: per (holder, asset)
# ---------------------------------------------------------------------------

# PR-161 verdict 198 in miniature — PriorityWithdrawalQueue.requestWithdrawWithWeETH
# (0x35e7d6fe…/0x27957a42, value_out/proven). weETH left TWO holders in one call: the
# queue, which has three recorded balance rows and none for weETH, and the BoringVault,
# whose weETH row is $8,471,736.29. The published residue named weETH as the only asset
# that moved AND as the only asset that could not be valued, beside
# ``observed_reach_priced_usd: 8471736.29`` — the vault's row, under a disclosure that
# said no such row existed. Replay of the persisted row reproduced it byte-identically.
_VAULT_WEETH_USD = 8_471_736.29


def _two_holders_move_one_asset(vault_usd: float | None, tvl: float | None = 3_322_211_996.00):
    """``CONTRACT`` (no recorded row for ``TOKEN``) and ``HOLDER`` both move ``TOKEN``."""
    logs = (transfer_log(TOKEN, CONTRACT, PAYEE, 5), transfer_log(TOKEN, HOLDER, PAYEE, 7))
    moved = SimResult(calls=(SimCallResult(True, "0x", None, logs),))
    holdings = (AssetHolding(CONTRACT, EETH, 0.0), AssetHolding(HOLDER, TOKEN, vault_usd))
    return _value_out([moved], holders=holdings, floor=0.0, tvl=tvl)


def test_an_asset_one_holder_prices_is_not_published_as_unvaluable_for_every_holder():
    """The reproduction. One asset, two holders, one priced row: the row must not say
    "this asset could not be valued" while publishing a figure made of it."""
    eff = _two_holders_move_one_asset(_VAULT_WEETH_USD)

    assert eff.concrete["reach_determined"] is False
    assert eff.concrete["observed_reach_assets"] == [TOKEN]
    assert eff.concrete["observed_reach_holders"] == sorted([CONTRACT, HOLDER])
    # The disclosure, keyed on the pair the arithmetic used: ONE pair is unvalued, and
    # it is the holder with no row — not the asset.
    assert eff.concrete["observed_reach_unvalued_pairs"] == [
        {"holder": CONTRACT, "asset": TOKEN, "reason": "asset_not_in_recorded_holdings"}
    ]
    assert eff.concrete["observed_reach_unvalued_reasons"] == ["asset_not_in_recorded_holdings"]
    # EARNED EMPTY, published rather than omitted: every asset that moved was priced
    # for at least one holder. This is the key that carried the contradiction.
    assert eff.concrete["observed_reach_unvalued_assets"] == []
    # The figure now names its own subjects.
    assert eff.concrete["observed_reach_priced_usd"] == _VAULT_WEETH_USD
    assert eff.concrete["observed_reach_priced_holders"] == [HOLDER]
    assert eff.concrete["reach_tvl_check"] == "within_protocol_tvl"
    # The invariant the published row broke, asserted directly: no asset is
    # simultaneously named as moved-and-priced and as unvaluable.
    assert not set(eff.concrete["observed_reach_assets"]) & set(eff.concrete["observed_reach_unvalued_assets"])


def test_a_fully_priced_two_holder_move_is_untouched_by_the_pair_keying():
    """NEGATIVE CONTROL — the same two holders and the same asset, and this time BOTH
    have a priced row. Every pair that moved is priced, so this is the measured branch
    and the payload is exactly what it was before the keying changed: neither new key
    appears, because ``reach_determined: True`` already says every named holder was
    priced. Asserted as a whole-dict equality so a new key cannot slip in unnoticed.

    The proving execution is popped rather than listed: it is not a REACH key and
    is written on every proven value_out row whatever branch the reach took, so
    folding it into the dict below would make this control assert the presence of
    something that is not this branch's own output."""
    logs = (transfer_log(TOKEN, CONTRACT, PAYEE, 5), transfer_log(TOKEN, HOLDER, PAYEE, 7))
    moved = SimResult(calls=(SimCallResult(True, "0x", None, logs),))
    holdings = (AssetHolding(CONTRACT, TOKEN, 100.0), AssetHolding(HOLDER, TOKEN, _VAULT_WEETH_USD))
    eff = _value_out([moved], holders=holdings, floor=0.0, tvl=3_322_211_996.00)

    reach = dict(eff.concrete)
    assert reach.pop(PROVING_EXECUTION_KEY)["target"] == CONTRACT.lower()
    assert reach == {
        "destination": PAYEE,
        "observed_reach_holders": sorted([CONTRACT, HOLDER]),
        "observed_reach_assets": [TOKEN],
        "reach_determined": True,
        "reach_tvl_check": "within_protocol_tvl",
        "observed_reach_value_usd": 100.0 + _VAULT_WEETH_USD,
    }


def test_an_asset_no_holder_could_value_is_still_named_as_unvaluable():
    """POSITIVE CONTROL for the narrowed key: it must still fire. Both holders move the
    asset and NEITHER has a priced row for it, so the asset genuinely contributed
    nothing to any figure and is named — and with nothing priced there is no figure,
    no priced holders, and no ceiling outcome."""
    eff = _two_holders_move_one_asset(None)

    assert eff.concrete["observed_reach_unvalued_assets"] == [TOKEN]
    assert eff.concrete["observed_reach_unvalued_pairs"] == [
        {"holder": HOLDER, "asset": TOKEN, "reason": "unpriced_holding"},
        {"holder": CONTRACT, "asset": TOKEN, "reason": "asset_not_in_recorded_holdings"},
    ]
    assert eff.concrete["observed_reach_unvalued_reasons"] == sorted(
        ["unpriced_holding", "asset_not_in_recorded_holdings"]
    )
    assert "observed_reach_priced_usd" not in eff.concrete
    assert "observed_reach_priced_holders" not in eff.concrete
    assert "reach_tvl_check" not in eff.concrete


def test_a_refused_partial_floor_still_names_the_holders_the_figure_came_from():
    """The ceiling refuses the figure; the refusal records a contradiction, and a
    contradiction whose subjects are not named cannot be inspected. ``priced_holders``
    is published on the refused arm too, beside ``observed_reach_rejected_usd``."""
    eff = _two_holders_move_one_asset(_VAULT_WEETH_USD, tvl=1_000.0)

    assert eff.concrete["reach_tvl_check"] == "exceeds_protocol_tvl"
    assert eff.concrete["observed_reach_rejected_usd"] == _VAULT_WEETH_USD
    assert "observed_reach_priced_usd" not in eff.concrete
    assert eff.concrete["observed_reach_priced_holders"] == [HOLDER]
    assert eff.concrete["observed_reach_unvalued_pairs"] == [
        {"holder": CONTRACT, "asset": TOKEN, "reason": "asset_not_in_recorded_holdings"}
    ]


def test_the_single_holder_partial_floor_publishes_the_pair_it_could_not_value():
    """The common shape (one holder, two assets, one priced) gains the pair key and
    keeps the asset key: with one holder the two say the same thing, and the asset-level
    negative is earned because that holder is the only one who moved it."""
    logs = (transfer_log(TOKEN, CONTRACT, PAYEE, 5), transfer_log(EETH, CONTRACT, PAYEE, 5))
    moved = SimResult(calls=(SimCallResult(True, "0x", None, logs),))
    eff = _value_out([moved], holders=(AssetHolding(CONTRACT, TOKEN, 100.0),), floor=0.0, tvl=1_000.0)

    assert eff.concrete["observed_reach_unvalued_pairs"] == [
        {"holder": CONTRACT, "asset": EETH, "reason": "asset_not_in_recorded_holdings"}
    ]
    assert eff.concrete["observed_reach_unvalued_assets"] == [EETH]
    assert eff.concrete["observed_reach_priced_usd"] == 100.0
    assert eff.concrete["observed_reach_priced_holders"] == [CONTRACT]


def test_every_reach_key_the_producer_publishes_reaches_the_row_and_the_claim():
    """The two allowlists are the only path these keys have to a published surface:
    ``workers.effects_worker._RESIDUE_JSON_KEYS`` gates what lands in
    ``effect_verdicts.observed_residue`` and ``claims_bridge._REACH_KEYS`` gates what
    the claim's witness carries. A key the producer publishes but neither list names is
    computed and then dropped — silently, and indistinguishably from never computed.
    Pinned over ALL FOUR branches so the next key added has to travel."""
    from services.effects.claims_bridge import _REACH_KEYS
    from workers.effects_worker import _RESIDUE_JSON_KEYS

    branches = (
        _two_holders_move_one_asset(_VAULT_WEETH_USD),  # partial floor, figure published
        _two_holders_move_one_asset(_VAULT_WEETH_USD, tvl=1_000.0),  # partial floor, refused
        _two_holders_move_one_asset(None),  # partial floor, nothing priced
        _value_out([_native_transfer_out()], holders=(AssetHolding(CONTRACT, NATIVE, 42.0),), floor=1.0),  # measured
        _value_out([SimResult(calls=(SimCallResult(True, "0x", None, ()),))], floor=7.0),  # indeterminate
    )
    published = {
        key for eff in branches for key in eff.concrete if key.startswith(("observed_reach", "reach_", "protocol_tvl"))
    }
    assert {"observed_reach_unvalued_pairs", "observed_reach_priced_holders"} <= published
    assert published - set(_RESIDUE_JSON_KEYS) == set()
    assert published - set(_REACH_KEYS) == set()
