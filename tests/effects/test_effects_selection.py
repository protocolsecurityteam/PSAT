"""The optional real-protocol funnel test skips without the dev ``psat`` DB, so CI never depends on dev data."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from db.models import (
    EDGE_RELATION_CONTROLLER_VALUE,
    EDGE_RELATION_EXTERNAL_CALL_TARGET,
    Artifact,
    Contract,
    ContractBalance,
    ContractBalanceFetch,
    ControlGraphEdge,
    EffectiveFunction,
    EffectsPlanMarker,
    EffectVerdict,
    Job,
    JobStage,
    JobStatus,
    Protocol,
)
from services.effects.config import EFFECT_CLASS_SUPPLY, EFFECT_CLASS_VALUE_OUT, NATIVE_ASSET_LOG_EMITTER
from services.effects.selection import (
    JobScope,
    _has_effect_evidence,
    _proven_array_len,
    _token_holdings_by_contract,
    build_authority_graph,
    select_candidates,
)
from tests.conftest import ADDR, requires_postgres
from tests.support.effects_builders import _balance, _contract, _fn, _principal, _protocol
from utils.balance_status import (
    ASSET_SET_STATUS_AT_PAGE_CAP,
    ASSET_SET_STATUS_RETURNED_ASSETS,
    BALANCE_WRITER_TVL,
    USD_CRUMB_THRESHOLD,
)

pytestmark = requires_postgres


def _token_balance(
    session: Session,
    contract_id: int,
    token: str | None,
    usd: float | Decimal | str | None,
    *,
    fetch: Any = None,
) -> None:
    """``usd=None`` is the unpriced shape; without ``fetch`` it is the legacy shape (``fetch_id IS NULL``)."""
    session.add(
        ContractBalance(
            contract_id=contract_id,
            token_address=token,
            raw_balance="1",
            decimals=18,
            usd_value=usd,
            fetch_id=(fetch.id if fetch is not None else None),
            observed_address=(fetch.observed_address if fetch is not None else None),
        )
    )


def _edge(
    session: Session,
    contract_id: int,
    controlled_contract: str,
    controller: str,
    relation: str = EDGE_RELATION_CONTROLLER_VALUE,
) -> None:
    session.add(
        ControlGraphEdge(
            contract_id=contract_id,
            from_node_id=f"address:{controlled_contract.lower()}",
            to_node_id=f"address:{controller.lower()}",
            relation=relation,
        )
    )


def test_cascade_filters_sink_claim_and_public(db_session):
    """Blankness keys on ``claims``, not ``effect_labels``; rows with no evidence written are unmeasured and kept."""
    p = _protocol(db_session, "cascade-proto")
    c = _contract(db_session, p.id, ADDR(0x1000))

    kept = _fn(
        db_session,
        c.id,
        name="pause",
        selector="0xaaaa0001",
        effect_targets=["SLOT"],
        state_changing=True,
        state_writes=[{"var": "paused", "declared_type": "bool", "origin": "body"}],
        sinks=[{"kind": "state_write", "target": "paused", "origin": "body"}],
    )
    # Gated on purpose, so (c) isn't what excludes it.
    inert_view = _fn(
        db_session,
        c.id,
        name="view",
        selector="0xaaaa0002",
        effect_targets=None,
        state_changing=False,
        state_writes=[],
        sinks=[],
        writer_selectors=[],
    )
    unmeasured = _fn(db_session, c.id, name="view2", selector="0xaaaa0003", effect_targets=[])
    claimed = _fn(
        db_session,
        c.id,
        name="mint",
        selector="0xaaaa0004",
        effect_targets=["SLOT"],
        state_changing=True,
        state_writes=[{"var": "totalSupply", "origin": "body"}],
        sinks=[{"kind": "state_write", "target": "totalSupply", "origin": "body"}],
        claims=[{"claim_id": "supply_up", "tier": "fact"}],
    )
    public = _fn(
        db_session,
        c.id,
        name="poke",
        selector="0xaaaa0005",
        effect_targets=["SLOT"],
        state_changing=True,
        state_writes=[{"var": "x", "origin": "body"}],
        sinks=[{"kind": "state_write", "target": "x", "origin": "body"}],
        authority_public=True,
    )
    db_session.commit()

    got = {cand.function_id for cand in select_candidates(db_session, p.id)}
    assert kept.id in got
    assert inert_view.id not in got
    assert unmeasured.id in got
    assert claimed.id not in got
    assert public.id not in got


def test_filter_a_keeps_the_three_evidence_states_apart(db_session):
    """The input-shape -> candidacy table of ``_has_effect_evidence``.

    Filter (a) used to read the display field ``effect_targets``. Each arm pins the disjunct that solely admits its
    shape; ``sink_only_view`` and ``write_only_view`` exist because every other arm is also admitted elsewhere.
    """
    p = _protocol(db_session, "evidence-plane")
    c = _contract(db_session, p.id, ADDR(0x1100))
    sw = [{"var": "balanceOf", "declared_type": "mapping(address => uint256)", "origin": "body"}]

    # A write reached only through a modifier: ``effect_targets`` is body-origin only.
    guard_writer = _fn(
        db_session,
        c.id,
        name="init",
        selector="0xbb000001",
        effect_targets=[],
        state_changing=True,
        state_writes=sw,
        sinks=[{"kind": "state_write", "target": "balanceOf", "origin": "guard"}],
    )
    # The 156-function class: kept by the ABI-mutability disjunct, not sink evidence.
    external_call_only = _fn(
        db_session,
        c.id,
        name="harvest",
        selector="0xbb000002",
        effect_targets=["oracle.latestAnswer"],
        state_changing=True,
        state_writes=[],
        sinks=[{"kind": "external_call", "target": "oracle.latestAnswer"}],
    )
    # The ABI proves mutability but the extractor found no sink; unsettled is not inert.
    abi_mutator = _fn(
        db_session,
        c.id,
        name="asmWrite",
        selector="0xbb000003",
        effect_targets=[],
        state_changing=True,
        state_writes=[],
        sinks=[],
        writer_selectors=[],
    )
    # Sole pin for the sinks ground (modelled on ``shouldSubmitReport(address)``): a gated view that moves protocol
    # money must not read as inert.
    sink_only_view = _fn(
        db_session,
        c.id,
        name="shouldSubmitReport",
        selector="0xbb000006",
        effect_targets=["etherFiAdmin.lastHandledReportRefSlot"],
        state_changing=False,
        state_writes=[],
        sinks=[{"kind": "external_call", "target": "etherFiAdmin.lastHandledReportRefSlot", "origin": "body"}],
        writer_selectors=[],
    )
    # Sole pin for the state_writes ground. No producer path today, but writers bypassing the view-contradiction rule
    # exist, and disagreement is a reason to probe.
    write_only_view = _fn(
        db_session,
        c.id,
        name="previewMint",
        selector="0xbb000007",
        effect_targets=[],
        state_changing=False,
        state_writes=sw,
        sinks=[],
        writer_selectors=[],
    )
    # Sole pin for ``state_changing IS NULL``: unselectored entry points (WETH9's fallback) withhold the ABI flag.
    mutability_withheld = _fn(
        db_session,
        c.id,
        name="unselectoredEntry",
        selector="0xbb000008",
        effect_targets=[],
        state_changing=None,
        state_writes=[],
        sinks=[],
        writer_selectors=[],
    )
    # Withheld is not proven-absent.
    withheld = _fn(
        db_session,
        c.id,
        name="previewDeposit",
        selector="0xbb000004",
        effect_targets=["asset.balanceOf"],
        state_changing=False,
        state_writes=None,
        sinks=None,
        writer_selectors=None,
    )
    inert = _fn(
        db_session,
        c.id,
        name="paused",
        selector="0xbb000005",
        effect_targets=[],
        state_changing=False,
        state_writes=[],
        sinks=[],
        writer_selectors=[],
    )
    # The filter doesn't read ``writer_selectors``, so a fabricated selector can't mint candidacy.
    fabricated_selector = _fn(
        db_session,
        c.id,
        name="fallback",
        selector="",
        effect_targets=[],
        state_changing=False,
        state_writes=[],
        sinks=[],
        writer_selectors=["0x552079dc"],
    )
    db_session.commit()

    got = {cand.function_id for cand in select_candidates(db_session, p.id)}
    assert guard_writer.id in got
    assert external_call_only.id in got
    assert abi_mutator.id in got
    assert sink_only_view.id in got
    assert write_only_view.id in got
    assert mutability_withheld.id in got
    assert withheld.id in got
    assert inert.id not in got
    assert fabricated_selector.id not in got


def test_filter_a_is_total_over_every_persisted_jsonb_shape(db_session):
    """``jsonb_array_length`` raises on a scalar, which would kill selection for the whole protocol; such rows are
    not-determined and admit.
    """
    p = _protocol(db_session, "jsonb-shapes")
    c = _contract(db_session, p.id, ADDR(0x1200))
    written_null = _fn(db_session, c.id, name="a", selector="0xbc000001", effect_targets=[], state_changing=False)
    malformed = _fn(db_session, c.id, name="b", selector="0xbc000002", effect_targets=[], state_changing=False)
    db_session.commit()
    db_session.execute(
        text("update effective_functions set state_writes='null'::jsonb, sinks='null'::jsonb where id=:i"),
        {"i": written_null.id},
    )
    db_session.execute(
        text("update effective_functions set state_writes='\"nope\"'::jsonb, sinks='{}'::jsonb where id=:i"),
        {"i": malformed.id},
    )
    db_session.commit()

    got = {cand.function_id for cand in select_candidates(db_session, p.id)}
    assert {written_null.id, malformed.id} <= got

    # No row may evaluate to SQL NULL and drop out of the ``or_``.
    admitted = db_session.execute(
        select(func.count())
        .select_from(EffectiveFunction)
        .where(EffectiveFunction.contract_id == c.id, _has_effect_evidence())
    ).scalar_one()
    assert admitted == 2

    # SQL doesn't promise to short-circuit an AND, so the length guard is asserted on its own.
    lengths = db_session.execute(
        select(
            EffectiveFunction.id,
            _proven_array_len(EffectiveFunction.state_writes),
            _proven_array_len(EffectiveFunction.sinks),
        )
        .where(EffectiveFunction.contract_id == c.id)
        .order_by(EffectiveFunction.id)
    ).all()
    assert [(sw, sk) for _id, sw, sk in lengths] == [(0, 0), (0, 0)]


def test_a_public_payout_or_mint_is_admitted_to_the_candidate_set(db_session):
    """A permissionless payout or mint is where "anyone can call this" is the finding; public inflow-only functions
    stay out.
    """
    p = _protocol(db_session, "public-admission-proto")
    c = _contract(db_session, p.id, ADDR(0x7000))

    def public(name, selector, claim_id):
        return _fn(
            db_session,
            c.id,
            name=name,
            selector=selector,
            effect_targets=["SLOT"],
            authority_public=True,
            claims=[{"claim_id": claim_id, "tier": "standard_exact"}] if claim_id else None,
        )

    payout = public("redeem", "0xdddd0001", "flow.out")
    minted = public("mintShares", "0xdddd0002", "supply.mint")
    deposit = public("deposit", "0xdddd0003", "flow.in")
    routed = public("bridge", "0xdddd0004", "value_router")
    blank = public("poke", "0xdddd0005", None)
    paused = public("pause", "0xdddd0006", "pause.set")
    db_session.commit()

    got = {cand.function_id: cand for cand in select_candidates(db_session, p.id)}

    assert payout.id in got
    assert minted.id in got
    assert deposit.id not in got
    assert routed.id not in got
    assert paused.id not in got
    # The exception keys on the claim, never publicness alone.
    assert blank.id not in got

    assert got[payout.id].restrict_families == frozenset({EFFECT_CLASS_VALUE_OUT})
    assert got[minted.id].restrict_families == frozenset({EFFECT_CLASS_SUPPLY})
    # Public routes the synthesizer onto the neutral caller.
    assert got[payout.id].authority_public is True
    assert got[payout.id].principal_addresses == ()


def test_the_public_admission_predicate_survives_every_claims_shape(db_session):
    """``claims`` is not always an array, and ``jsonb_array_elements`` raises on a scalar."""
    p = _protocol(db_session, "claims-shape-proto")
    c = _contract(db_session, p.id, ADDR(0x7200))

    for i, claims in enumerate([None, [], "null", 5, "not-a-list", {"claim_id": "flow.out"}]):
        _fn(
            db_session,
            c.id,
            name=f"odd{i}",
            selector=f"0xffff000{i}",
            effect_targets=["SLOT"],
            authority_public=True,
            claims=claims,
        )
    admitted = _fn(
        db_session,
        c.id,
        name="redeem",
        selector="0xffff00ff",
        effect_targets=["SLOT"],
        authority_public=True,
        claims=[{"claim_id": "flow.out", "tier": "standard_exact"}],
    )
    db_session.commit()

    got = {cand.function_id for cand in select_candidates(db_session, p.id)}
    assert got == {admitted.id}


def test_a_public_payout_reaches_a_synthesized_probe(db_session):
    """An earlier fix satisfied the synthesizer alone and was dead code."""
    from services.effects.calldata import NEUTRAL_CALLER, FunctionFacts, synthesize_value_out

    p = _protocol(db_session, "public-probe-proto")
    c = _contract(db_session, p.id, ADDR(0x7100))
    fn = _fn(
        db_session,
        c.id,
        name="redeem",
        selector="0xeeee0001",
        effect_targets=["SLOT"],
        authority_public=True,
        claims=[{"claim_id": "flow.out", "tier": "standard_exact"}],
    )
    db_session.commit()

    candidate = next(x for x in select_candidates(db_session, p.id) if x.function_id == fn.id)
    facts = FunctionFacts(
        full_name="redeem(uint256)",
        selector="0xeeee0001",
        canonical_signature="redeem(uint256)",
        effect_info={
            "value_flows": [{"direction": "out", "kind": "native_transfer_send", "origin": "body"}],
            "payable": False,
        },
        tree=None,
        legacy_value_flows=(),
    )

    plan = synthesize_value_out(candidate, facts)

    assert plan is not None, "a public value-mover must reach a probe plan"
    assert plan.principal == NEUTRAL_CALLER
    assert plan.calldata.startswith("0xeeee0001")


def test_gate_lift_enrolls_flow_and_supply_claims_scoped(db_session):
    """Other claims stay dropped; blank functions keep full synthesis."""
    p = _protocol(db_session, "gate-lift-proto")
    c = _contract(db_session, p.id, ADDR(0x3000))

    blank = _fn(db_session, c.id, name="pauseUntil", selector="0xcccc0001", effect_targets=["SLOT"])
    flow = _fn(
        db_session,
        c.id,
        name="withdrawEther",
        selector="0xcccc0002",
        effect_targets=["SLOT"],
        claims=[{"claim_id": "flow.out", "tier": "idiom_structural"}],
    )
    mint = _fn(
        db_session,
        c.id,
        name="mint",
        selector="0xcccc0003",
        effect_targets=["SLOT"],
        claims=[{"claim_id": "supply.mint", "tier": "standard_exact"}],
    )
    both = _fn(
        db_session,
        c.id,
        name="enter",
        selector="0xcccc0004",
        effect_targets=["SLOT"],
        claims=[{"claim_id": "flow.in", "tier": "idiom_structural"}, {"claim_id": "supply.mint", "tier": "fact"}],
    )
    upgraded = _fn(
        db_session,
        c.id,
        name="upgradeTo",
        selector="0xcccc0005",
        effect_targets=["SLOT"],
        claims=[{"claim_id": "upgrade.implementation", "tier": "standard_exact"}],
    )
    db_session.commit()

    by_id = {cand.function_id: cand for cand in select_candidates(db_session, p.id)}
    assert by_id[blank.id].restrict_families is None
    assert by_id[flow.id].restrict_families == frozenset({"value_out"})
    assert by_id[mint.id].restrict_families == frozenset({"supply"})
    assert by_id[both.id].restrict_families == frozenset({"value_out", "supply"})
    assert upgraded.id not in by_id


def test_a_fact_claim_never_removes_a_function_from_the_candidate_set(db_session):
    """``rate_limit.consume`` and ``delegatecall.execute`` explain nothing, so they must not drop a blank row (13
    measured local rows would leave the set).
    """
    p = _protocol(db_session, "fact-transparency-proto")
    c = _contract(db_session, p.id, ADDR(0x7300))

    rate_only = _fn(
        db_session,
        c.id,
        name="queueETHWithdrawal",
        selector="0xab110001",
        effect_targets=["SLOT"],
        claims=[{"claim_id": "rate_limit.consume", "tier": "idiom_structural"}],
    )
    dc_only = _fn(
        db_session,
        c.id,
        name="depositToStrategy",
        selector="0xab110002",
        effect_targets=["SLOT"],
        claims=[{"claim_id": "delegatecall.execute", "tier": "idiom_structural"}],
    )
    both_facts = _fn(
        db_session,
        c.id,
        name="requestConsolidation",
        selector="0xab110003",
        effect_targets=["SLOT"],
        claims=[
            {"claim_id": "rate_limit.consume", "tier": "idiom_structural"},
            {"claim_id": "delegatecall.execute", "tier": "idiom_structural"},
        ],
    )
    # Transparency must not launder.
    fact_and_flow = _fn(
        db_session,
        c.id,
        name="withdraw",
        selector="0xab110004",
        effect_targets=["SLOT"],
        claims=[
            {"claim_id": "rate_limit.consume", "tier": "idiom_structural"},
            {"claim_id": "flow.out", "tier": "idiom_structural"},
        ],
    )
    fact_and_pause = _fn(
        db_session,
        c.id,
        name="pauseAll",
        selector="0xab110005",
        effect_targets=["SLOT"],
        claims=[
            {"claim_id": "rate_limit.consume", "tier": "idiom_structural"},
            {"claim_id": "pause.set", "tier": "standard_exact"},
        ],
    )
    db_session.commit()

    by_id = {cand.function_id: cand for cand in select_candidates(db_session, p.id)}
    assert by_id[rate_only.id].restrict_families is None
    assert by_id[dc_only.id].restrict_families is None
    assert by_id[both_facts.id].restrict_families is None
    assert by_id[fact_and_flow.id].restrict_families == frozenset({EFFECT_CLASS_VALUE_OUT})
    assert fact_and_pause.id not in by_id


def test_candidate_carries_witnessed_value_holders_and_acting_floor(db_session):
    p = _protocol(db_session, "reach-inputs-proto")
    acting = _contract(db_session, p.id, ADDR(0x9001))
    lp = _contract(db_session, p.id, ADDR(0x9002))
    empty = _contract(db_session, p.id, ADDR(0x9003))
    _balance(db_session, acting.id, 221_000_000.0)
    _balance(db_session, lp.id, 55_200_000.0)
    _balance(db_session, empty.id, 0.0)  # zero-balance holder is excluded
    f = _fn(db_session, acting.id, name="invalidate", selector="0x99990001", effect_targets=["S"])
    _principal(db_session, f.id, ADDR(0xE0A2))
    db_session.commit()

    cand = {c.function_id: c for c in select_candidates(db_session, p.id)}[f.id]
    # Keyed on (holder, asset); native rows use the emitter a synthetic native Transfer log carries.
    holders = {(h.holder, h.asset): h.usd_value for h in cand.value_holders}
    native = NATIVE_ASSET_LOG_EMITTER
    assert holders[(ADDR(0x9001).lower(), native)] == pytest.approx(221_000_000.0)
    assert holders[(ADDR(0x9002).lower(), native)] == pytest.approx(55_200_000.0)
    # A measured zero is evidence; dropping it made "moved an asset worth nothing" read as "moved nothing".
    assert holders[(ADDR(0x9003).lower(), native)] == pytest.approx(0.0)
    assert cand.acting_balance_usd == pytest.approx(221_000_000.0)


@requires_postgres
def test_the_tvl_ceiling_reads_defillama_tvl_and_never_total_usd(db_session):
    """``total_usd`` and ``contract_breakdown`` are NULL on every local row; a total_usd-only row means no ceiling."""
    from datetime import datetime, timedelta, timezone

    from db.models import TvlSnapshot

    p = _protocol(db_session, "tvl-ceiling")
    c = _contract(db_session, p.id, ADDR(0x9500))
    f = _fn(db_session, c.id, name="withdraw", selector="0x95000001", effect_targets=["S"])
    _principal(db_session, f.id, ADDR(0x9501))
    now = datetime.now(timezone.utc)
    db_session.add(TvlSnapshot(protocol_id=p.id, timestamp=now - timedelta(hours=2), total_usd=999.0, source="x"))
    db_session.commit()
    cand = {x.function_id: x for x in select_candidates(db_session, p.id)}[f.id]
    assert cand.protocol_tvl_usd is None  # skipped, loudly — never 999.0 and never 0

    db_session.add(
        TvlSnapshot(protocol_id=p.id, timestamp=now - timedelta(hours=1), defillama_tvl=100.0, source="defillama")
    )
    db_session.add(TvlSnapshot(protocol_id=p.id, timestamp=now, defillama_tvl=3_297_344_734.00, source="defillama"))
    db_session.commit()
    cand = {x.function_id: x for x in select_candidates(db_session, p.id)}[f.id]
    assert cand.protocol_tvl_usd == 3_297_344_734.00


@requires_postgres
def test_holdings_the_fetch_recorded_at_the_page_cap_are_marked_incomplete(db_session):
    """The witness is the FETCH's ``asset_set_status``, and nothing else.

    An at-cap holder is marked ``at_page_cap`` so the reach probe names it as the reason an asset
    could not be valued. THE LENGTH ARM IS GONE: the fetch pages to exhaustion,
    so a list longer than ``TOKEN_BALANCE_PAGE_SIZE`` is a routine COMPLETE list and comparing a
    count to the cap flagged every large sheet. ``not_determined`` is still the below-cap answer
    (there is no ``complete`` state). ``at_page_cap`` fires on ZERO local holders (U2 de-capping
    retired every truncated list), so it is covered here by construction, not measured."""
    from services.clients.etherscan import TOKEN_BALANCE_PAGE_SIZE

    p = _protocol(db_session, "holdings-cap")
    capped = _contract(db_session, p.id, ADDR(0x9600))
    whole = _contract(db_session, p.id, ADDR(0x9601))
    _fn(db_session, capped.id, name="a", selector="0x96000001", effect_targets=["S"])
    _fn(db_session, whole.id, name="b", selector="0x96000002", effect_targets=["S"])
    capped_fetch = ContractBalanceFetch(
        contract_id=capped.id,
        chain_id=1,
        observed_address=capped.address,
        native_status="not_determined",
        asset_set_status=ASSET_SET_STATUS_AT_PAGE_CAP,
        writer=BALANCE_WRITER_TVL,
    )
    whole_fetch = ContractBalanceFetch(
        contract_id=whole.id,
        chain_id=1,
        observed_address=whole.address,
        native_status="not_determined",
        asset_set_status=ASSET_SET_STATUS_RETURNED_ASSETS,
        asset_page_length=TOKEN_BALANCE_PAGE_SIZE + 5,
        writer=BALANCE_WRITER_TVL,
    )
    db_session.add_all([capped_fetch, whole_fetch])
    db_session.flush()
    for n in range(3):
        _token_balance(db_session, capped.id, ADDR(0x970000 + n), 1.0, fetch=capped_fetch)
    for n in range(TOKEN_BALANCE_PAGE_SIZE + 5):
        _token_balance(db_session, whole.id, ADDR(0x980000 + n), 1.0, fetch=whole_fetch)
    db_session.commit()

    by_holder = {}
    for cand in select_candidates(db_session, p.id):
        for holding in cand.value_holders:
            by_holder.setdefault(holding.holder, set()).add(holding.completeness)
    assert by_holder[capped.address.lower()] == {"at_page_cap"}
    assert by_holder[whole.address.lower()] == {"not_determined"}
    # A "complete" answer would be a proven absence derived from a filtered count.
    from services.effects.selection import HOLDINGS_COMPLETENESS_STATES

    assert set(HOLDINGS_COMPLETENESS_STATES) == {"at_page_cap", "not_determined"}


@requires_postgres
def test_value_holders_are_per_asset_with_native_keyed_on_the_log_emitter(db_session):
    """Per-asset value holders.

    A single summed figure per holder let a native move out of the weETH proxy claim a sheet that is 99.99% eETH.
    Native rows are keyed on the ``traceTransfers`` emitter, unpriced holdings stay ``None``, and a holding is keyed
    on the deployment so two implementation rows don't double-count it.
    """
    p = _protocol(db_session, "per-asset-holdings")
    deployment = ADDR(0x8800)
    token = ADDR(0x88A1)
    unpriced = ADDR(0x88A2)
    impl_a = _contract(db_session, p.id, ADDR(0x8801))
    impl_b = _contract(db_session, p.id, ADDR(0x8802))
    for impl in (impl_a, impl_b):
        _fn(
            db_session,
            impl.id,
            name="withdraw",
            selector=f"0x8800000{impl.id % 10}",
            effect_targets=["S"],
            deployment_address=deployment,
        )
        _token_balance(db_session, impl.id, token, 250.0)
        _token_balance(db_session, impl.id, None, 4_000.0)
        _token_balance(db_session, impl.id, unpriced, None)
    db_session.commit()

    cand = next(c for c in select_candidates(db_session, p.id) if c.contract_id == impl_a.id)
    holdings = {(h.holder, h.asset): h.usd_value for h in cand.value_holders}
    assert holdings[(deployment.lower(), token.lower())] == 250.0
    assert holdings[(deployment.lower(), NATIVE_ASSET_LOG_EMITTER)] == 4_000.0
    assert holdings[(deployment.lower(), unpriced.lower())] is None
    # MAX per (holder, asset), not SUM.
    assert sum(1 for (holder, asset) in holdings if asset == token.lower()) == 1
    assert len(cand.value_holders) == 3


def test_principal_addresses_are_totally_ordered_so_the_probe_identity_is_the_datas(db_session):
    """``principal_addresses[0]`` is the identity every fork probe impersonates.

    Rows are inserted in descending order so heap order fails.
    """
    p = _protocol(db_session, "principal-order-proto")
    c = _contract(db_session, p.id, ADDR(0x7100))
    f = _fn(db_session, c.id, name="rebalance", selector="0x71000001", effect_targets=["S"])
    holders = [ADDR(0x71FF), ADDR(0x71C0), ADDR(0x7180), ADDR(0x7140), ADDR(0x7101)]
    for addr in holders:  # descending: insertion order is NOT the answer
        _principal(db_session, f.id, addr)
    db_session.commit()

    cand = {x.function_id: x for x in select_candidates(db_session, p.id)}[f.id]
    assert list(cand.principal_addresses) == sorted(a.lower() for a in holders)
    assert cand.principal_addresses[0] == ADDR(0x7101).lower()


def test_blank_predicate_keys_on_claims_not_effect_labels(db_session):
    p = _protocol(db_session, "blank-proto")
    c = _contract(db_session, p.id, ADDR(0x2000))
    f = _fn(db_session, c.id, name="pauseUntil", selector="0xbbbb0001", effect_targets=["SLOT"])
    f.effect_labels = ["pause"]
    f.claims = []

    # Blankness must hold across [], SQL NULL and JSON-null.
    sql_null = _fn(db_session, c.id, name="a", selector="0xbbbb0002", effect_targets=["S"])
    json_null = _fn(db_session, c.id, name="b", selector="0xbbbb0003", effect_targets=["S"], claims=None)
    db_session.commit()
    db_session.execute(text("UPDATE effective_functions SET claims = NULL WHERE id = :i"), {"i": sql_null.id})
    db_session.commit()

    got = {cand.function_id for cand in select_candidates(db_session, p.id)}
    assert {f.id, sql_null.id, json_null.id} <= got


def test_transitive_value_beats_direct_balance(db_session):
    """Direct-balance ordering would bury the small controller."""
    p = _protocol(db_session, "reach-proto")

    admin = _contract(db_session, p.id, ADDR(0x0A01))
    vault = _contract(db_session, p.id, ADDR(0x0B02))
    rich = _contract(db_session, p.id, ADDR(0x0C03))

    _balance(db_session, admin.id, 33_000.0)
    _balance(db_session, vault.id, 3_200_000_000.0)
    _balance(db_session, rich.id, 1_000_000_000.0)

    safe = ADDR(0x5AFE)
    _edge(db_session, vault.id, controlled_contract=vault.address, controller=safe)

    small = _fn(db_session, admin.id, name="setImpl", selector="0xdead0001", effect_targets=["IMPL"])
    _principal(db_session, small.id, safe)

    big_direct = _fn(db_session, rich.id, name="sweep", selector="0xdead0002", effect_targets=["BAL"])
    _principal(db_session, big_direct.id, ADDR(0xE0A1))
    db_session.commit()

    ordered = select_candidates(db_session, p.id)
    ids = [c.function_id for c in ordered]
    assert ids.index(small.id) < ids.index(big_direct.id)

    by_id = {c.function_id: c for c in ordered}
    # Exact on purpose: ``Decimal == pytest.approx(float)`` can only pass or raise.
    assert by_id[small.id].value_at_stake_usd == Decimal("3200033000.00")
    assert by_id[big_direct.id].value_at_stake_usd == Decimal("1000000000.00")


def test_authority_graph_closure_is_transitive(db_session):
    p = _protocol(db_session, "closure-proto")
    a = _contract(db_session, p.id, ADDR(0x0111))
    b = _contract(db_session, p.id, ADDR(0x0222))
    cc = _contract(db_session, p.id, ADDR(0x0333))
    _balance(db_session, a.id, 1.0)
    _balance(db_session, b.id, 10.0)
    _balance(db_session, cc.id, 100.0)
    _edge(db_session, b.id, controlled_contract=b.address, controller=a.address)
    _edge(db_session, cc.id, controlled_contract=cc.address, controller=b.address)
    db_session.commit()

    graph = build_authority_graph(db_session, p.id)
    assert graph.reachable_value({a.address}) == Decimal("111.00")
    assert graph.reachable_value({b.address}) == Decimal("110.00")
    assert graph.reachable_value({cc.address}) == Decimal("100.00")


def test_traversal_terminates_on_a_hand_built_cycle(db_session):
    """Defensive only: a mutual control pair is not legitimate (66 such pairs came from ``tracking.py:851`` unioning
    gate and callee edges), but a stale graph can hold one.
    """
    p = _protocol(db_session, "cycle-proto")
    a = _contract(db_session, p.id, ADDR(0x0AA1))
    b = _contract(db_session, p.id, ADDR(0x0BB2))
    _balance(db_session, a.id, 5.0)
    _balance(db_session, b.id, 7.0)
    _edge(db_session, b.id, controlled_contract=b.address, controller=a.address)
    _edge(db_session, a.id, controlled_contract=a.address, controller=b.address)
    db_session.commit()

    graph = build_authority_graph(db_session, p.id)
    assert graph.reachable_value({a.address}) == Decimal("12.00")


def test_callee_edges_move_no_authority(db_session):
    """B merely calls A (``external_call_target``); the pre-split writer stored that as control too."""
    p = _protocol(db_session, "callee-proto")
    a = _contract(db_session, p.id, ADDR(0x0CC1))
    b = _contract(db_session, p.id, ADDR(0x0DD2))
    _balance(db_session, a.id, 5.0)
    _balance(db_session, b.id, 7.0)
    _edge(db_session, b.id, controlled_contract=b.address, controller=a.address)
    _edge(
        db_session,
        b.id,
        controlled_contract=b.address,
        controller=a.address,
        relation=EDGE_RELATION_EXTERNAL_CALL_TARGET,
    )
    _edge(
        db_session,
        a.id,
        controlled_contract=a.address,
        controller=b.address,
        relation=EDGE_RELATION_EXTERNAL_CALL_TARGET,
    )
    db_session.commit()

    graph = build_authority_graph(db_session, p.id)
    assert graph.reachable_value({a.address}) == Decimal("12.00")
    assert graph.reachable_value({b.address}) == Decimal("7.00")


# ``reachable_value`` folds over a ``set``, whose order varies with PYTHONHASHSEED, so the float fold's low bits did
# too. These tests use real child processes or an order-sensitive fixture.

# Real local balances whose float sum depends on addition order.
_ORDER_SENSITIVE_USD = ("3488954369.29", "472190234.24", "57041255.72")
_ORDER_SENSITIVE_EXACT = Decimal("4018185859.25")


def test_order_sensitive_fixture_really_is_order_sensitive():
    """If these became order-invariant the tests below would prove nothing."""
    import itertools

    sums = {sum(p) for p in itertools.permutations([float(x) for x in _ORDER_SENSITIVE_USD])}
    assert len(sums) > 1, "fixture no longer discriminates: float addition is order-invariant here"
    assert sum(Decimal(x) for x in _ORDER_SENSITIVE_USD) == _ORDER_SENSITIVE_EXACT


def test_reachable_value_is_exact_over_an_order_sensitive_closure(db_session):
    p = _protocol(db_session, "exact-proto")
    holders = [_contract(db_session, p.id, ADDR(0xD001 + i)) for i in range(3)]
    for c, usd in zip(holders, _ORDER_SENSITIVE_USD):
        _balance(db_session, c.id, usd)
    root = _contract(db_session, p.id, ADDR(0xD0FF))
    for c in holders:
        _edge(db_session, c.id, controlled_contract=c.address, controller=root.address)
    db_session.commit()

    graph = build_authority_graph(db_session, p.id)
    got = graph.reachable_value({root.address})
    assert got == _ORDER_SENSITIVE_EXACT
    assert isinstance(got, Decimal)


def test_equal_reach_orders_by_function_id_not_by_rounding(db_session):
    """The ``function_id`` tiebreak fires on equality, which a float fold misses by an ulp."""
    p = _protocol(db_session, "tiebreak-proto")
    holders = [_contract(db_session, p.id, ADDR(0xE001 + i)) for i in range(3)]
    for c, usd in zip(holders, _ORDER_SENSITIVE_USD):
        _balance(db_session, c.id, usd)
    left = _contract(db_session, p.id, ADDR(0xE0FE))
    right = _contract(db_session, p.id, ADDR(0xE0FF))
    for c in holders:
        _edge(db_session, c.id, controlled_contract=c.address, controller=left.address)
    for c in reversed(holders):
        _edge(db_session, c.id, controlled_contract=c.address, controller=right.address)
    # ``right`` gets the lower id, so only id ordering puts it first.
    f_right = _fn(db_session, right.id, name="rightFn", selector="0xeeee0001", effect_targets=["S"])
    f_left = _fn(db_session, left.id, name="leftFn", selector="0xeeee0002", effect_targets=["S"])
    db_session.commit()

    by_id = {c.function_id: c for c in select_candidates(db_session, p.id)}
    assert by_id[f_left.id].value_at_stake_usd == by_id[f_right.id].value_at_stake_usd
    ordered = [c.function_id for c in select_candidates(db_session, p.id)]
    assert ordered.index(f_right.id) < ordered.index(f_left.id)


def test_reachable_value_is_identical_across_processes():
    """The one shape a same-process test can't express; the float fold gave up to three values."""
    import subprocess
    import sys

    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    prog = (
        "import sys; sys.path.insert(0, %r)\n"
        "from services.effects.selection import AuthorityGraph\n"
        "from decimal import Decimal\n"
        "usd = %r\n"
        "addrs = ['0x%%040x' %% (i + 1) for i in range(len(usd) * 40)]\n"
        "g = AuthorityGraph()\n"
        "g.balance = {a: Decimal(usd[i %% len(usd)]) for i, a in enumerate(addrs)}\n"
        "g.controls = {'0x%%040x' %% 0xF00D: set(addrs)}\n"
        "print(repr(g.reachable_value({'0x%%040x' %% 0xF00D})))\n"
    ) % (repo, _ORDER_SENSITIVE_USD)

    seen = set()
    for seed in ("0", "1", "2", "3"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        out = subprocess.run(
            [sys.executable, "-c", prog], capture_output=True, text=True, env=env, timeout=120, check=True
        )
        seen.add(out.stdout.strip())
    assert len(seen) == 1, f"reachable_value varies with PYTHONHASHSEED: {sorted(seen)}"


def test_token_holdings_order_is_total_under_a_value_tie(db_session):
    p = _protocol(db_session, "token-tie-proto")
    c = _contract(db_session, p.id, ADDR(0xB0B0))
    tied = [ADDR(0x7003), ADDR(0x7001), ADDR(0x7002)]
    for t in tied:
        db_session.add(
            ContractBalance(contract_id=c.id, token_address=t, raw_balance="1", decimals=18, usd_value=Decimal("41.00"))
        )
    db_session.commit()

    got = _token_holdings_by_contract(db_session, p.id, 2)[c.id]
    assert got == tuple(sorted(t.lower() for t in tied))[:2]


def test_a_crumb_holding_is_kept_out_of_the_probe_input_by_the_threshold(db_session):
    """The crumb used to be excluded only by the column's 2-decimal scale; now a stored 0.004 is excluded by the
    one-cent threshold.
    """
    p = _protocol(db_session, "crumb-proto")
    c = _contract(db_session, p.id, ADDR(0xB1B1))
    crumb, cent, rich = ADDR(0x7101), ADDR(0x7102), ADDR(0x7103)
    for token, usd in ((crumb, "0.004"), (cent, "0.01"), (rich, "41.00")):
        db_session.add(
            ContractBalance(contract_id=c.id, token_address=token, raw_balance="1", decimals=18, usd_value=Decimal(usd))
        )
    db_session.commit()
    db_session.expire_all()
    stored = {r.token_address: r.usd_value for r in db_session.query(ContractBalance).all()}
    assert stored[crumb] == Decimal("0.004000000000000000")
    assert stored[crumb] != Decimal(0)

    got = _token_holdings_by_contract(db_session, p.id, 5)[c.id]

    assert USD_CRUMB_THRESHOLD == Decimal("0.01")
    assert got == (rich.lower(), cent.lower())


def test_resource_cap_logs_exactly_what_it_dropped(db_session, caplog):
    p = _protocol(db_session, "cap-proto")
    c = _contract(db_session, p.id, ADDR(0x0D00))

    high = _contract(db_session, p.id, ADDR(0x0D01))
    _balance(db_session, high.id, 1_000_000.0)
    keep = _fn(db_session, high.id, name="big", selector="0xcafe0001", effect_targets=["S"])

    mid = _contract(db_session, p.id, ADDR(0x0D02))
    _balance(db_session, mid.id, 500.0)
    drop_mid = _fn(db_session, mid.id, name="mid", selector="0xcafe0002", effect_targets=["S"])

    drop_low = _fn(db_session, c.id, name="low", selector="0xcafe0003", effect_targets=["S"])
    db_session.commit()

    with caplog.at_level(logging.WARNING, logger="services.effects.selection"):
        kept = select_candidates(db_session, p.id, resource_cap=1)

    assert [k.function_id for k in kept] == [keep.id]

    rec = next(r for r in caplog.records if r.name == "services.effects.selection")
    assert rec.dropped == 2
    assert rec.dropped_sample_truncated is False
    assert {e["function_id"] for e in rec.dropped_sample} == {drop_mid.id, drop_low.id}
    assert {e["selector"] for e in rec.dropped_sample} == {"0xcafe0002", "0xcafe0003"}
    assert keep.id not in {e["function_id"] for e in rec.dropped_sample}


def test_probe_target_is_the_deployment_not_the_implementation(db_session):
    """The implementation holds none of the state the probes read. Hashing stays on the code-bearing address."""
    proto = _protocol(db_session, "probe-target")
    impl = _contract(db_session, proto.id, ADDR(0x7001))
    _fn(
        db_session,
        impl.id,
        name="pause",
        selector="0x8456cb59",
        effect_targets=["paused"],
        deployment_address=ADDR(0x7002),
    )
    _fn(db_session, impl.id, name="sweep", selector="0xdeadbeef", effect_targets=["bal"])
    db_session.commit()

    by_name = {c.function_name: c for c in select_candidates(db_session, proto.id)}
    proxied = by_name["pause"]
    assert proxied.contract_address == ADDR(0x7001).lower()
    assert proxied.probe_target == ADDR(0x7002).lower()
    assert by_name["sweep"].probe_target == ADDR(0x7001).lower()


# Per-job scoping must partition a protocol's candidates across its jobs without losing one.


def _job(session: Session, protocol_id: int | None, address: str, *, chain_id: int = 1, status=JobStatus.processing):
    job = Job(
        address=address,
        chain_id=chain_id,
        protocol_id=protocol_id,
        status=status,
        stage=JobStage.effects,
        request={"address": address, "chain": "ethereum"},
    )
    session.add(job)
    session.flush()
    return job


def _ran_effects(session: Session, job: Job, *, status: str = "success") -> None:
    """``stage_timing_effects`` has the same name whether the stage succeeded or failed."""
    session.add(
        Artifact(job_id=job.id, name="stage_timing_effects", data={"stage": "effects", "status": status}),
    )
    job.status = JobStatus.completed
    job.stage = JobStage.done
    session.flush()


def _verdict_for(session: Session, function_id: int, address: str) -> None:
    session.add(
        EffectVerdict(
            function_id=function_id,
            chain_id=1,
            contract_address=address.lower(),
            selector="0x0000ffff",
            effect_class="value_out",
            verdict="unknown",
            tier="tier1",
        )
    )
    session.flush()


def _scoped_fixture(session: Session, *, status=JobStatus.processing):
    """C's only job has no protocol_id, the live shape nobody would scope to."""
    proto = _protocol(session, f"scope-{ADDR(0x8000)}")
    addrs = {"a": ADDR(0x8001), "b": ADDR(0x8002), "c": ADDR(0x8003)}
    fns: dict[str, int] = {}
    jobs: dict[str, Job] = {}
    for key, addr in addrs.items():
        contract = _contract(session, proto.id, addr, chain="ethereum")
        fns[key] = _fn(session, contract.id, name=key, selector=f"0x0000{ord(key):04x}", effect_targets=["s"]).id
    jobs["a"] = _job(session, proto.id, addrs["a"], status=status)
    jobs["b"] = _job(session, proto.id, addrs["b"], status=status)
    _job(session, None, addrs["c"])  # unowned: no protocol_id
    session.commit()
    return proto, addrs, fns, jobs


def _scoped(session, proto_id, addr) -> set[int]:
    return {c.function_id for c in select_candidates(session, proto_id, scope=JobScope(addr, 1))}


def test_shape1_full_run_plans_own_contract_not_its_siblings(db_session):
    proto, addrs, fns, _ = _scoped_fixture(db_session)
    got = _scoped(db_session, proto.id, addrs["a"])
    assert fns["a"] in got
    assert fns["b"] not in got


def test_shape1_sweeps_contracts_no_job_would_ever_claim(db_session):
    """Otherwise C's verdicts vanish silently."""
    proto, addrs, fns, _ = _scoped_fixture(db_session)
    for owner in ("a", "b"):
        assert fns["c"] in _scoped(db_session, proto.id, addrs[owner]), f"unowned contract dropped by job {owner}"


def test_shape1_scoped_union_equals_protocol_wide_set(db_session):
    proto, addrs, _fns, _ = _scoped_fixture(db_session)
    protocol_wide = {c.function_id for c in select_candidates(db_session, proto.id)}
    union: set[int] = set()
    for job_addr in addrs.values():
        union |= _scoped(db_session, proto.id, job_addr)
    assert union == protocol_wide


def test_shape1_job_that_completes_early_is_not_re_swept(db_session):
    """A row-existence rule would re-sweep B into every later job."""
    proto, addrs, fns, jobs = _scoped_fixture(db_session)
    _ran_effects(db_session, jobs["b"])
    db_session.commit()

    got = _scoped(db_session, proto.id, addrs["a"])
    assert fns["b"] not in got
    assert fns["a"] in got


def test_shape1_completed_job_that_wrote_no_verdicts_is_still_owned(db_session):
    """5 of 29 live contracts wrote no verdict, so verdict-existence alone would re-sweep them forever."""
    proto, addrs, fns, jobs = _scoped_fixture(db_session)
    _ran_effects(db_session, jobs["b"])
    db_session.commit()
    assert not db_session.query(EffectVerdict).count()
    assert fns["b"] not in _scoped(db_session, proto.id, addrs["a"])


def test_shape2_new_contract_does_not_replan_the_protocol(db_session):
    proto = _protocol(db_session, "scope-incremental")
    old_addr, new_addr = ADDR(0x8301), ADDR(0x8302)
    old = _contract(db_session, proto.id, old_addr, chain="ethereum")
    old_fn = _fn(db_session, old.id, name="old", selector="0x00008301", effect_targets=["s"])
    new = _contract(db_session, proto.id, new_addr, chain="ethereum")
    new_fn = _fn(db_session, new.id, name="new", selector="0x00008302", effect_targets=["s"])
    old_job = _job(db_session, proto.id, old_addr)
    _ran_effects(db_session, old_job)
    _verdict_for(db_session, old_fn.id, old_addr)
    _job(db_session, proto.id, new_addr)  # the incremental run's only job
    db_session.commit()

    assert _scoped(db_session, proto.id, new_addr) == {new_fn.id}


def _prod_shape(session: Session, n_contracts: int = 4):
    """Every job completed earlier, none ran effects, and no verdicts exist."""
    proto = _protocol(session, f"scope-prod-{n_contracts}")
    addrs, fns = [], {}
    for i in range(n_contracts):
        addr = ADDR(0x8400 + i)
        contract = _contract(session, proto.id, addr, chain="ethereum")
        fns[addr] = _fn(session, contract.id, name=f"f{i}", selector=f"0x0000{0x8400 + i:04x}", effect_targets=["s"]).id
        _job(session, proto.id, addr, status=JobStatus.completed)
        addrs.append(addr)
    session.commit()
    return proto, addrs, fns


def test_shape3_completed_jobs_do_not_own_a_never_planned_contract(db_session):
    """A row-existence ownership rule would plan nothing on prod."""
    proto, addrs, fns = _prod_shape(db_session)
    got = _scoped(db_session, proto.id, addrs[0])
    assert got == set(fns.values()), "prod-shape contracts must all be swept on the first effects run"


def test_shape3_fresh_job_owns_itself_so_the_sweep_stays_bounded(db_session):
    proto, addrs, fns = _prod_shape(db_session)
    _job(db_session, proto.id, addrs[1])  # the new run's job for contract 1
    db_session.commit()
    assert fns[addrs[1]] not in _scoped(db_session, proto.id, addrs[0])


def test_shape3_sweep_is_self_limiting_once_verdicts_land(db_session):
    """The first sweep leaves verdicts behind, which marks the contract planned for later jobs."""
    proto, addrs, fns = _prod_shape(db_session)
    swept = _scoped(db_session, proto.id, addrs[0])
    assert swept == set(fns.values())

    for addr, fid in fns.items():
        _verdict_for(db_session, fid, addr)
    db_session.commit()

    assert _scoped(db_session, proto.id, addrs[1]) == {fns[addrs[1]]}


def test_owner_job_must_belong_to_the_same_protocol(db_session):
    mine = _protocol(db_session, "scope-proto-mine")
    theirs = _protocol(db_session, "scope-proto-theirs")
    shared, own_addr = ADDR(0x8501), ADDR(0x8502)
    shared_contract = _contract(db_session, mine.id, shared, chain="ethereum")
    shared_fn = _fn(db_session, shared_contract.id, name="s", selector="0x00008501", effect_targets=["s"])
    own = _contract(db_session, mine.id, own_addr, chain="ethereum")
    _fn(db_session, own.id, name="o", selector="0x00008502", effect_targets=["s"])
    _job(db_session, mine.id, own_addr)
    _job(db_session, theirs.id, shared)  # in flight, but for a different protocol
    db_session.commit()

    assert shared_fn.id in _scoped(db_session, mine.id, own_addr)


def test_terminally_failed_job_does_not_own_its_contract(db_session):
    proto = _protocol(db_session, "scope-failed")
    owner_addr, other_addr = ADDR(0x8101), ADDR(0x8102)
    dead = _contract(db_session, proto.id, other_addr, chain="ethereum")
    dead_fn = _fn(db_session, dead.id, name="d", selector="0x0000d001", effect_targets=["s"])
    live = _contract(db_session, proto.id, owner_addr, chain="ethereum")
    _fn(db_session, live.id, name="l", selector="0x0000d002", effect_targets=["s"])
    _job(db_session, proto.id, owner_addr)
    _job(db_session, proto.id, other_addr, status=JobStatus.failed_terminal)
    db_session.commit()

    assert dead_fn.id in _scoped(db_session, proto.id, owner_addr)


def test_scope_excludes_other_chains(db_session):
    """A chain-1 job used to probe other chains' contracts through chain-1 seams."""
    proto = _protocol(db_session, "scope-chains")
    eth_addr, base_addr = ADDR(0x8201), ADDR(0x8202)
    eth = _contract(db_session, proto.id, eth_addr, chain="ethereum")
    base = _contract(db_session, proto.id, base_addr, chain="base")
    eth_fn = _fn(db_session, eth.id, name="e", selector="0x0000c001", effect_targets=["s"])
    base_fn = _fn(db_session, base.id, name="b", selector="0x0000c002", effect_targets=["s"])
    _job(db_session, proto.id, eth_addr, chain_id=1)
    _job(db_session, proto.id, base_addr, chain_id=8453)
    db_session.commit()

    eth_got = {c.function_id for c in select_candidates(db_session, proto.id, scope=JobScope(eth_addr, 1))}
    base_got = {c.function_id for c in select_candidates(db_session, proto.id, scope=JobScope(base_addr, 8453))}
    assert eth_got == {eth_fn.id}
    assert base_got == {base_fn.id}


def test_no_scope_keeps_protocol_wide_behavior(db_session):
    proto, _addrs, fns, _ = _scoped_fixture(db_session)
    got = {c.function_id for c in select_candidates(db_session, proto.id)}
    assert got == set(fns.values())


# Rule 4: a contract swept with no plans leaves no trace, so it is re-swept forever. The marker must stop that and never
# make a contract look covered.


def _mark_planned_empty(session: Session, contract_id: int, job: Job | None, *, at: datetime) -> None:
    session.add(
        EffectsPlanMarker(
            contract_id=contract_id,
            job_id=job.id if job is not None else None,
            candidates_planned=1,
            planned_at=at,
        )
    )
    session.flush()


def _scoped_since(session, proto_id, addr, since) -> set[int]:
    return {c.function_id for c in select_candidates(session, proto_id, scope=JobScope(addr, 1, planned_since=since))}


def _swept_only(session: Session, proto: Protocol) -> tuple[str, int, Contract]:
    owner_addr, orphan_addr = ADDR(0x8601), ADDR(0x8602)
    owner = _contract(session, proto.id, owner_addr, chain="ethereum")
    _fn(session, owner.id, name="own", selector="0x00008601", effect_targets=["s"])
    orphan = _contract(session, proto.id, orphan_addr, chain="ethereum")
    orphan_fn = _fn(session, orphan.id, name="orph", selector="0x00008602", effect_targets=["s"])
    _job(session, proto.id, owner_addr)
    session.commit()
    return owner_addr, orphan_fn.id, orphan


def test_shape1_empty_planning_marker_stops_the_re_sweep(db_session):
    proto = _protocol(db_session, "scope-marker-full")
    owner_addr, orphan_fn, orphan = _swept_only(db_session, proto)
    reading_job_created = datetime.now(timezone.utc)

    assert orphan_fn in _scoped_since(db_session, proto.id, owner_addr, reading_job_created)

    _mark_planned_empty(db_session, orphan.id, None, at=reading_job_created + timedelta(seconds=1))
    db_session.commit()
    assert orphan_fn not in _scoped_since(db_session, proto.id, owner_addr, reading_job_created)


@pytest.mark.parametrize(
    ("marker_offset", "read"),
    [
        # Planning inputs change between runs, so an old marker must not suppress this run's sweep.
        pytest.param(
            -timedelta(hours=6),
            lambda session, proto_id, owner_addr, created: _scoped_since(session, proto_id, owner_addr, created),
            id="marker-older-than-the-reading-job",
        ),
        pytest.param(
            timedelta(hours=1),
            lambda session, proto_id, owner_addr, created: _scoped(session, proto_id, owner_addr),
            id="marker-ignored-without-a-planned-since",
        ),
    ],
)
def test_marker_does_not_own_the_orphan(db_session, marker_offset, read):
    proto = _protocol(db_session, "scope-marker-not-owning")
    owner_addr, orphan_fn, orphan = _swept_only(db_session, proto)
    reading_job_created = datetime.now(timezone.utc)

    _mark_planned_empty(db_session, orphan.id, None, at=reading_job_created + marker_offset)
    db_session.commit()
    assert orphan_fn in read(db_session, proto.id, owner_addr, reading_job_created)


def test_marker_does_not_shadow_a_contract_that_yields_plans(db_session):
    proto = _protocol(db_session, "scope-marker-scope")
    owner_addr, orphan_fn, orphan = _swept_only(db_session, proto)
    other_addr = ADDR(0x8603)
    other = _contract(db_session, proto.id, other_addr, chain="ethereum")
    other_fn = _fn(db_session, other.id, name="oth", selector="0x00008603", effect_targets=["s"])
    now = datetime.now(timezone.utc)
    _mark_planned_empty(db_session, orphan.id, None, at=now + timedelta(seconds=1))
    db_session.commit()

    got = _scoped_since(db_session, proto.id, owner_addr, now)
    assert orphan_fn not in got
    assert other_fn.id in got


def test_shape2_incremental_run_re_sweeps_a_marker_from_the_old_run(db_session):
    proto = _protocol(db_session, "scope-marker-incremental")
    old_addr, new_addr, empty_addr = ADDR(0x8701), ADDR(0x8702), ADDR(0x8703)
    old = _contract(db_session, proto.id, old_addr, chain="ethereum")
    old_fn = _fn(db_session, old.id, name="old", selector="0x00008701", effect_targets=["s"])
    new = _contract(db_session, proto.id, new_addr, chain="ethereum")
    new_fn = _fn(db_session, new.id, name="new", selector="0x00008702", effect_targets=["s"])
    empty = _contract(db_session, proto.id, empty_addr, chain="ethereum")
    empty_fn = _fn(db_session, empty.id, name="empty", selector="0x00008703", effect_targets=["s"])
    old_job = _job(db_session, proto.id, old_addr)
    _ran_effects(db_session, old_job)
    _verdict_for(db_session, old_fn.id, old_addr)
    last_run = datetime.now(timezone.utc) - timedelta(days=1)
    _mark_planned_empty(db_session, empty.id, old_job, at=last_run)
    db_session.commit()

    this_run = datetime.now(timezone.utc)
    got = _scoped_since(db_session, proto.id, new_addr, this_run)
    assert got == {new_fn.id, empty_fn.id}, "the incremental run must re-plan the empty contract exactly once"

    db_session.query(EffectsPlanMarker).filter(EffectsPlanMarker.contract_id == empty.id).update(
        {"planned_at": this_run + timedelta(seconds=1)}
    )
    db_session.commit()
    assert _scoped_since(db_session, proto.id, new_addr, this_run) == {new_fn.id}


def test_shape3_prod_first_run_still_sweeps_everything(db_session):
    proto, addrs, fns = _prod_shape(db_session, 3)
    now = datetime.now(timezone.utc)
    assert _scoped_since(db_session, proto.id, addrs[0], now) == set(fns.values())


def test_shape3_marker_bounds_the_prod_sweep_to_once_per_run(db_session):
    proto, addrs, fns = _prod_shape(db_session, 3)
    now = datetime.now(timezone.utc)
    contracts = {
        addr: db_session.query(Contract).filter(Contract.address == addr, Contract.protocol_id == proto.id).one()
        for addr in addrs
    }
    for addr in addrs[1:]:
        _mark_planned_empty(db_session, contracts[addr].id, None, at=now + timedelta(seconds=1))
    db_session.commit()

    got = _scoped_since(db_session, proto.id, addrs[0], now)
    assert got == {fns[addrs[0]]}


def test_marker_union_still_covers_the_protocol(db_session):
    proto, addrs, fns = _prod_shape(db_session, 3)
    now = datetime.now(timezone.utc)
    contracts = {
        addr: db_session.query(Contract).filter(Contract.address == addr, Contract.protocol_id == proto.id).one()
        for addr in addrs
    }
    union: set[int] = set()
    for addr in addrs:
        planned = _scoped_since(db_session, proto.id, addr, now)
        union |= planned
        for planned_addr in addrs:
            if fns[planned_addr] in planned and planned_addr != addr:
                db_session.merge(
                    EffectsPlanMarker(
                        contract_id=contracts[planned_addr].id,
                        candidates_planned=1,
                        planned_at=now + timedelta(seconds=1),
                    )
                )
        db_session.commit()
    assert union == set(fns.values())


# The effects stage fail-forwards, so a failed stage never reruns; reading the artifact or "in flight" alone as
# ownership would drop a contract permanently.


def _pair(session: Session, name: str, *, a: int = 0x8801, b: int = 0x8802):
    proto = _protocol(session, name)
    a_addr, b_addr = ADDR(a), ADDR(b)
    fns: dict[str, int] = {}
    for key, addr, idx in (("a", a_addr, a), ("b", b_addr, b)):
        contract = _contract(session, proto.id, addr, chain="ethereum")
        fns[key] = _fn(session, contract.id, name=key, selector=f"0x0000{idx:04x}", effect_targets=["s"]).id
    session.commit()
    return proto, a_addr, b_addr, fns


def test_failed_effects_stage_is_not_ownership(db_session):
    """A failed stage's artifact used to mark B owned, so nobody planned it again."""
    proto, a_addr, b_addr, fns = _pair(db_session, "fail-rule2")
    _job(db_session, proto.id, a_addr)
    b_job = _job(db_session, proto.id, b_addr)
    _ran_effects(db_session, b_job, status="failed")
    db_session.commit()

    assert fns["b"] in _scoped(db_session, proto.id, a_addr), "a failed effects stage must not own its contract"


def test_successful_effects_stage_is_still_ownership(db_session):
    """Otherwise per-job scoping collapses back into the storm."""
    proto, a_addr, b_addr, fns = _pair(db_session, "ok-rule2")
    _job(db_session, proto.id, a_addr)
    b_job = _job(db_session, proto.id, b_addr)
    _ran_effects(db_session, b_job, status="success")
    db_session.commit()

    assert fns["b"] not in _scoped(db_session, proto.id, a_addr)


def test_stage_timing_without_a_status_is_not_ownership(db_session):
    """Re-sweep rather than skip: costs work, never coverage."""
    proto, a_addr, b_addr, fns = _pair(db_session, "nostatus-rule2")
    _job(db_session, proto.id, a_addr)
    b_job = _job(db_session, proto.id, b_addr)
    db_session.add(Artifact(job_id=b_job.id, name="stage_timing_effects", data={"stage": "effects"}))
    b_job.status = JobStatus.completed
    b_job.stage = JobStage.done
    db_session.commit()

    assert fns["b"] in _scoped(db_session, proto.id, a_addr)


def _store_stage_timing(session: Session, job: Job, status: str) -> None:
    """The body lands in object storage and ``artifacts.data`` is JSON-null, as in production."""
    from db.queue import store_artifact

    store_artifact(
        session,
        job.id,
        "stage_timing_effects",
        data={"schema_version": "2", "stage": "effects", "status": status, "elapsed_s": 1.0},
    )
    job.status = JobStatus.completed
    job.stage = JobStage.done
    session.commit()


def test_storage_backed_failed_stage_is_not_ownership(db_session, storage_bucket):
    """70/70 preview rows have a NULL ``data->>'status'``, so the status must be resolved from storage."""
    proto, a_addr, b_addr, fns = _pair(db_session, "fail-rule2-storage", a=0x8811, b=0x8812)
    _job(db_session, proto.id, a_addr)
    b_job = _job(db_session, proto.id, b_addr)
    _store_stage_timing(db_session, b_job, "failed")

    row = db_session.query(Artifact).filter(Artifact.job_id == b_job.id).one()
    assert row.storage_key and row.data is None, "fixture must reproduce the storage-backed shape"
    assert fns["b"] in _scoped(db_session, proto.id, a_addr)


def test_storage_backed_successful_stage_is_still_ownership(db_session, storage_bucket):
    proto, a_addr, b_addr, fns = _pair(db_session, "ok-rule2-storage", a=0x8821, b=0x8822)
    _job(db_session, proto.id, a_addr)
    b_job = _job(db_session, proto.id, b_addr)
    _store_stage_timing(db_session, b_job, "success")

    assert fns["b"] not in _scoped(db_session, proto.id, a_addr)


def test_in_flight_job_past_the_effects_stage_is_not_ownership(db_session):
    """A fail-forwarded job is in flight but can never run effects again."""
    proto, a_addr, b_addr, fns = _pair(db_session, "fail-rule1", a=0x8831, b=0x8832)
    _job(db_session, proto.id, a_addr)
    b_job = _job(db_session, proto.id, b_addr)
    _ran_effects(db_session, b_job, status="failed")
    b_job.status = JobStatus.processing
    b_job.stage = JobStage.coverage
    db_session.commit()

    assert fns["b"] in _scoped(db_session, proto.id, a_addr)


def test_in_flight_job_that_skipped_effects_is_not_ownership(db_session):
    """With ``PSAT_EFFECTS_STAGE`` off, policy advances straight to coverage."""
    proto, a_addr, b_addr, fns = _pair(db_session, "skip-rule1", a=0x8841, b=0x8842)
    _job(db_session, proto.id, a_addr)
    b_job = _job(db_session, proto.id, b_addr)
    b_job.stage = JobStage.coverage
    db_session.commit()

    assert fns["b"] in _scoped(db_session, proto.id, a_addr)


@pytest.mark.parametrize("stage", [JobStage.discovery, JobStage.static, JobStage.policy, JobStage.effects])
def test_in_flight_job_before_the_effects_stage_still_owns(db_session, stage):
    proto, a_addr, b_addr, fns = _pair(db_session, f"live-rule1-{stage.value}", a=0x8851, b=0x8852)
    _job(db_session, proto.id, a_addr)
    b_job = _job(db_session, proto.id, b_addr)
    b_job.stage = stage
    db_session.commit()

    assert fns["b"] not in _scoped(db_session, proto.id, a_addr)


# Every contract must still be planned by somebody when jobs fail.


def _interleaved(session: Session, name: str):
    proto = _protocol(session, name)
    keys = ("healthy", "failed", "died", "forwarded", "reader")
    addrs = {key: ADDR(0x8900 + i) for i, key in enumerate(keys)}
    fns: dict[str, int] = {}
    for i, key in enumerate(keys):
        contract = _contract(session, proto.id, addrs[key], chain="ethereum")
        fns[key] = _fn(session, contract.id, name=key, selector=f"0x0000{0x8900 + i:04x}", effect_targets=["s"]).id

    healthy_job = _job(session, proto.id, addrs["healthy"])
    _ran_effects(session, healthy_job, status="success")
    _verdict_for(session, fns["healthy"], addrs["healthy"])

    failed_job = _job(session, proto.id, addrs["failed"])
    _ran_effects(session, failed_job, status="failed")

    _job(session, proto.id, addrs["died"], status=JobStatus.failed_terminal)

    forwarded = _job(session, proto.id, addrs["forwarded"])
    _ran_effects(session, forwarded, status="failed")
    forwarded.status = JobStatus.processing
    forwarded.stage = JobStage.coverage

    _job(session, proto.id, addrs["reader"])
    session.commit()
    return proto, addrs, fns


def test_shape4_reader_sweeps_every_contract_no_healthy_job_covered(db_session):
    proto, addrs, fns = _interleaved(db_session, "shape4-mixed")
    got = _scoped(db_session, proto.id, addrs["reader"])
    assert fns["failed"] in got
    assert fns["died"] in got
    assert fns["forwarded"] in got
    assert fns["reader"] in got
    assert fns["healthy"] not in got


def test_shape4_union_over_the_jobs_that_can_still_run_equals_the_protocol_set(db_session):
    """Union over every job address is vacuous, so union over jobs that can still run effects plus contracts with
    verdict evidence.
    """
    proto, addrs, fns = _interleaved(db_session, "shape4-union")
    protocol_wide = {c.function_id for c in select_candidates(db_session, proto.id)}

    still_running = (
        db_session.query(Job)
        .filter(
            Job.protocol_id == proto.id,
            Job.status.not_in([JobStatus.completed, JobStatus.failed_terminal]),
            Job.stage.in_([JobStage.discovery, JobStage.static, JobStage.policy, JobStage.effects]),
        )
        .all()
    )
    assert {j.address for j in still_running} == {addrs["reader"]}

    union = {v.function_id for v in db_session.query(EffectVerdict).all()}
    for job in still_running:
        union |= _scoped(db_session, proto.id, job.address)
    assert union == protocol_wide, sorted(protocol_wide - union)


def test_storage_backed_status_is_unreadable_without_storage(db_session):
    """A bucket outage may cost work, never coverage."""
    import services.effects.selection as sel

    sel._STAGE_STATUS_CACHE.clear()
    proto, a_addr, b_addr, fns = _pair(db_session, "unreadable-rule2", a=0x8861, b=0x8862)
    _job(db_session, proto.id, a_addr)
    b_job = _job(db_session, proto.id, b_addr)
    db_session.add(
        Artifact(
            job_id=b_job.id,
            name="stage_timing_effects",
            storage_key="nowhere/stage_timing_effects",
            content_type="application/json",
        )
    )
    b_job.status = JobStatus.completed
    b_job.stage = JobStage.done
    db_session.commit()

    assert fns["b"] in _scoped(db_session, proto.id, a_addr)


def test_storage_body_missing_from_the_bucket_re_sweeps(db_session, storage_bucket):
    import services.effects.selection as sel

    sel._STAGE_STATUS_CACHE.clear()
    proto, a_addr, b_addr, fns = _pair(db_session, "missingbody-rule2", a=0x8871, b=0x8872)
    _job(db_session, proto.id, a_addr)
    b_job = _job(db_session, proto.id, b_addr)
    db_session.add(
        Artifact(
            job_id=b_job.id,
            name="stage_timing_effects",
            storage_key="does/not/exist",
            content_type="application/json",
        )
    )
    b_job.status = JobStatus.completed
    b_job.stage = JobStage.done
    db_session.commit()

    assert fns["b"] in _scoped(db_session, proto.id, a_addr)


def test_resolved_status_of_a_finished_job_is_cached(db_session, storage_bucket):
    """A finished job can't rewrite its artifact, so the status is memoised; proven by deleting the object."""
    import services.effects.selection as sel

    sel._STAGE_STATUS_CACHE.clear()
    proto, a_addr, b_addr, fns = _pair(db_session, "cache-rule2", a=0x8881, b=0x8882)
    _job(db_session, proto.id, a_addr)
    b_job = _job(db_session, proto.id, b_addr)
    _store_stage_timing(db_session, b_job, "success")

    assert fns["b"] not in _scoped(db_session, proto.id, a_addr)
    key = db_session.query(Artifact).filter(Artifact.job_id == b_job.id).one().storage_key
    storage_bucket.delete(key)
    assert fns["b"] not in _scoped(db_session, proto.id, a_addr)


def test_shape4_failed_contract_is_covered_by_its_own_job_too(db_session):
    """The own-address clause never depends on any ownership rule."""
    proto, addrs, fns = _interleaved(db_session, "shape4-self")
    assert fns["failed"] in _scoped(db_session, proto.id, addrs["failed"])


def test_the_page_cap_signal_is_read_off_the_response_not_the_filtered_rows(monkeypatch):
    """The page-cap check ran on the zero-filtered list, so a full page with one zero entry read as not truncated."""
    from services.clients import etherscan

    cap = etherscan.TOKEN_BALANCE_PAGE_SIZE
    page = [
        {
            "TokenAddress": f"0x{i:040x}",
            "TokenName": "T",
            "TokenSymbol": "T",
            "TokenDivisor": "18",
            "TokenQuantity": "0" if i == 0 else str(10**18),
            "TokenPriceUSD": "1",
        }
        for i in range(cap)
    ]
    monkeypatch.setattr(etherscan, "get", lambda *a, **k: {"result": page})
    monkeypatch.setattr(etherscan.time, "sleep", lambda _s: None)
    warnings: list[str] = []
    monkeypatch.setattr(etherscan.logger, "warning", lambda msg, *a: warnings.append(msg % a))

    rows = etherscan.get_token_balances_page("0x" + "ab" * 20, chain_id=1).rows

    assert len(rows) == cap - 1, "the zero-balance entry is still filtered out of the stored rows"
    # Paging never reaches a short page here, so the list stays a declared prefix.
    assert any("PREFIX" in w for w in warnings), "a full page went unreported because the filter shrank the list"
    assert any(f"({cap} entries over 2 page(s), {cap - 1} with a balance)" in w for w in warnings)
    monkeypatch.setattr(etherscan, "get", lambda *a, **k: {"result": page[:3]})
    warnings.clear()
    etherscan.get_token_balances_page("0x" + "ac" * 20, chain_id=1)
    assert not [w for w in warnings if "FULL page" in w]
