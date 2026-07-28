"""§5b downstream value-reach: which address the money is keyed on, and which
execution the reach is read from.

Every one of the six proven ``value_out`` rows on the 2026-07-25 live run carried
``observed_reach_value_usd: 0.0`` with ``reach_indeterminate: true`` — the
fallback firing at 100%, and its floor computing to zero on deployments holding
billions. Two independent causes, both here (and a third the shape itself carried:
publishing the floor under the key that means MEASURED reach — D3, fixed since):

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
from services.effects.selection import AssetHolding, build_authority_graph, select_candidates
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
    # Per ASSET (A2): ``_balance`` writes a NATIVE row, so the holding is keyed on the
    # emitter ``eth_simulateV1`` uses for a native move — the address a synthetic
    # Transfer log for it actually carries.
    assert AssetHolding(deployment.lower(), NATIVE_ASSET_LOG_EMITTER, 7_500.0) in cand.value_holders


# ---------------------------------------------------------------------------
# 2. which execution the reach is read from
# ---------------------------------------------------------------------------

CONTRACT = "0x" + "c0" * 20
PRINCIPAL = "0x" + "22" * 20
PAYEE = "0x" + "33" * 20
HOLDER = "0x" + "44" * 20
# The asset every ``transfer_log`` below is emitted BY, so a holding of it is the
# holding that moved. Reach matching is per asset since A2.
TOKEN = "0x" + "7a" * 20


def _value_out(blocks, *, seeding=None, holders=(AssetHolding(CONTRACT, TOKEN, 100.0),), floor=100.0, tvl=None):
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

    KEPT, deliberately (handoff §11's standing correction: this test exercises a
    LIVE branch and the criticism of it was withdrawn). Only the key names moved:
    D3 publishes the floor as ``observed_reach_floor_usd`` and withholds
    ``observed_reach_value_usd``, because the floor being read AS the reach is the
    defect. The branch, the holder set and the intent are untouched."""
    moved = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5),)),))
    eff = _value_out([moved], holders=(AssetHolding(HOLDER, TOKEN, 42.0),), floor=250.0)
    assert eff.concrete["observed_reach_floor_usd"] == 250.0
    assert eff.concrete["reach_determined"] is False
    assert eff.concrete["reach_indeterminate"] is True
    assert "observed_reach_value_usd" not in eff.concrete


def test_a_zero_balance_deployment_publishes_no_reach_number_at_all():
    """W0-7 fixture 8, and the D3 fix it was written to gate. INVERTED.

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
    # THE DISCRIMINATION D3 BUYS: a MEASURED zero and an unmeasured one are now two
    # different payloads. Before, both published ``observed_reach_value_usd: 0.0``
    # and differed only by a flag a consumer had to remember to read.
    assert "observed_reach_floor_usd" not in eff.concrete


# ---------------------------------------------------------------------------
# 3. A2 — the reach figure is per ASSET, and an asset we cannot value says so
# ---------------------------------------------------------------------------

EETH = "0x" + "e1" * 20
NATIVE = NATIVE_ASSET_LOG_EMITTER
# The measured shape of the A2 over-claim: WeETH's proxy holds $3,488,954,369 of
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
    """A2, the reproduction. Asset-blind matching attributed a holder's ENTIRE USD to
    whichever asset happened to move: the weETH proxy moved seeded native ETH and the
    row published $3.489B of reach — 64.96% of ALL published reach USD in the DB came
    from two rows of this shape, both truly $0.

    The holder DID move value, so this is not the not-witnessed branch: it is
    witnessed and NOT valued. We hold no native balance row for this deployment, and
    absence there is "holds nothing" / "not fetched" / "fetch failed" collapsed into
    one shape (G6-11) — so the only honest USD is unknown."""
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
    as $0 is a CONFIDENT LOW value where the answer is unknown — inv. 1's ranking rule
    in its numeric form. The priced part survives as an explicit partial floor."""
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
    """R2: the skip is a PUBLISHED state. An absent ceiling that looked like a passed
    one would be a mitigation that never fires and cannot be told from one that does —
    the shape this whole effort exists to remove."""
    holdings = (AssetHolding(CONTRACT, TOKEN, 100.0),)
    moved = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5),)),))
    eff = _value_out([moved], holders=holdings, floor=1.0, tvl=None)

    assert eff.concrete["reach_tvl_check"] == "skipped_no_tvl"
    assert eff.concrete["reach_determined"] is True
    assert eff.concrete["observed_reach_value_usd"] == 100.0


def test_a_truncated_holdings_list_names_truncation_as_the_reason():
    """G6-11 consumer rule: a truncated fetch must LOWER CONFIDENCE, never produce a
    confident low value. 7 local contracts sit exactly at the fetcher's one-page cap,
    one of them holding $8.6B, and an asset absent from a capped list may simply never
    have been fetched."""
    holdings = (AssetHolding(CONTRACT, TOKEN, 100.0, holdings_complete=False),)
    moved = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(EETH, CONTRACT, PAYEE, 5),)),))
    eff = _value_out([moved], holders=holdings, floor=1.0)

    assert eff.concrete["reach_determined"] is False
    assert eff.concrete["observed_reach_unvalued_reasons"] == ["holdings_possibly_truncated"]
    # The COMPLETE control: the same unrecorded asset, from a holder whose list is
    # whole, is a genuine absence and says so instead.
    eff2 = _value_out([moved], holders=(AssetHolding(CONTRACT, TOKEN, 100.0),), floor=1.0)
    assert eff2.concrete["observed_reach_unvalued_reasons"] == ["unrecorded_asset"]


def test_two_logs_of_one_asset_out_of_one_holder_attribute_that_holding_once():
    """The attributed figure is a holder's WHOLE recorded balance for an asset, so a
    second ``Transfer`` log of the same asset out of the same holder must contribute
    nothing.

    Summing per LOG published a MULTIPLE of the entire balance under
    ``observed_reach_value_usd`` — the field whose own docstring calls it "a
    conservative upper bound (a holder's full on-chain balance attributed when value
    provably leaves it)". Two logs made a $100 holding read as $200 of reach: not an
    upper bound, a new over-claim on a published money figure, in the same field and
    the same direction as the defect A2 exists to remove. The triggering shape is the
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
