"""Tests for services.effects.selection — the candidate cascade + value-at-stake ordering.

Synthetic fixtures drive the always-run assertions (cascade correctness,
transitive-vs-direct ordering, dropped-work logging). One optional test
reproduces the real-protocol funnel against the dev ``psat`` DB when present and
skips cleanly otherwise, so CI (which starts from a fresh empty DB) never
depends on dev data.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import create_engine, func, select, text
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


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _token_balance(
    session: Session,
    contract_id: int,
    token: str | None,
    usd: float | Decimal | str | None,
    *,
    fetch: Any = None,
) -> None:
    """One ``contract_balances`` row. ``usd=None`` is the UNPRICED shape (the producer
    writes ``price_usd = 0`` and leaves ``usd_value`` NULL on 1001 of 1376 local rows).

    ``fetch`` links the row to a recorded read. Left off, the row is the LEGACY shape
    (``fetch_id IS NULL``) that predates the fetch-provenance plane and carries no
    status and no observed address of its own."""
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
    # Stored edge is contract-controlled-BY-controller: from = contract, to = controller.
    session.add(
        ControlGraphEdge(
            contract_id=contract_id,
            from_node_id=f"address:{controlled_contract.lower()}",
            to_node_id=f"address:{controller.lower()}",
            relation=relation,
        )
    )


# ---------------------------------------------------------------------------
# Cascade
# ---------------------------------------------------------------------------


def test_cascade_filters_sink_claim_and_public(db_session):
    """Proven-inert dropped; claim-present dropped; public dropped; blank-gated kept.

    The blank predicate MUST key on ``claims``, not ``effect_labels``: a row
    with a populated ``effect_labels`` but empty ``claims`` is still blank and
    must survive.

    Filter (a) reads the mutability evidence plane, so "dropped for having nothing to
    simulate" now requires the writer to have LOOKED: a compiler-typed view with
    ``state_writes = []`` and ``sinks = []``. The two arms this test used to pin —
    ``effect_targets`` NULL and ``[]`` with no evidence written at all — are
    INVERTED below (``unmeasured``): they are not-determined and are kept.
    """
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
    # (a) the writer looked and proved there is nothing here -> dropped. Gated on
    # purpose: (c) must not be what carries this exclusion.
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
    # (a) INVERTED: the evidence plane was never written for this row (every row
    # predating the mutability columns) -> not determined -> KEPT. This row used to be
    # dropped for the absence of a display field.
    unmeasured = _fn(db_session, c.id, name="view2", selector="0xaaaa0003", effect_targets=[])
    # (b) confident claim present -> dropped
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
    # (c) public -> dropped
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
    """The input-shape → candidacy table of ``_has_effect_evidence``, row by row.

    Filter (a) used to read ``effect_targets``, a DISPLAY field concatenating
    state-write variable names with dotted external-call heads: 501 of its 1,642
    populated rows carry only call heads, so a populated value asserted a write
    nothing had proven, and an empty one dropped the function on an absence of
    measurement. Each arm below is a shape that decision got wrong, or must keep
    getting right.

    One arm per DISJUNCT, not one per narrative: the predicate is an ``or_`` of
    six, and an arm only pins the disjunct that is the SOLE admitter of its shape.
    The two ``_evidence_proven_present`` disjuncts are why ``sink_only_view`` and
    ``write_only_view`` exist below — every other arm here is admitted by
    ``state_changing IS TRUE`` or by not-determined, so with the sink/write ground
    deleted this test would still pass and the projected plane would silently lose
    116 filter-(a) rows and one gated candidate.
    """
    p = _protocol(db_session, "evidence-plane")
    c = _contract(db_session, p.id, ADDR(0x1100))
    sw = [{"var": "balanceOf", "declared_type": "mapping(address => uint256)", "origin": "body"}]

    # PROVEN WRITE with an EMPTY display field (a write reached only through a
    # modifier: ``effect_targets`` is body-origin only, ``state_writes`` is not).
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
    # The 156-function class as it MEASURES on the projected plane: gated,
    # populated ``effect_targets``, not one proven state write, and
    # ``state_changing = TRUE`` (147 of the 156; 8 are NULL, 1 is FALSE). It keeps
    # its candidate slot, and the disjunct that keeps it is the ABI-mutability one
    # — NOT the sink evidence. This arm therefore pins nothing about sinks; see
    # ``sink_only_view`` for the 1-of-156 shape that does.
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
    # Two witnesses disagree: the ABI proves mutability, the extractor found no
    # sink (an inline-assembly writer, or a body the IR never entered). Unsettled
    # is not inert.
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
    # SOLE PIN for ``_evidence_proven_present(sinks)``. A compiler-typed view with
    # a PROVEN ``external_call`` sink and a proven-empty write list: every other
    # disjunct votes no (``state_changing`` is FALSE, both lists are arrays), so
    # only the sink ground admits it. Modelled on a real row —
    # ``shouldSubmitReport(address)`` (function_id 2344 locally, gated, one
    # ``etherFiAdmin.lastHandledReportRefSlot`` call) — and that row is the ONE
    # candidate the projected plane loses if this ground is deleted, out of 116
    # filter-(a) rows of this exact shape (the other 115 are public and (c) drops
    # them). Deleting it would mean "the compiler says no write, therefore there is
    # nothing to observe", and a gated view whose answer moves protocol money is
    # exactly the claim a probe falsifies.
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
    # SOLE PIN for ``_evidence_proven_present(state_writes)``: a proven write
    # beside a ``view`` ABI flag. Zero realised rows on the local slice and no
    # producer path through ``_mutability_fields`` today, because the
    # view-contradiction rule nulls exactly this shape (state_changing FALSE +
    # non-empty writes -> writes, sinks and selectors all withheld), which is why
    # the ``withheld`` arm below is what the plane actually carries. Kept anyway,
    # and asserted ADMITTED: the reachable writers that bypass that rule are
    # ``db/effect_cache.py`` and hand backfills, and a proven
    # write is proven whatever a second witness says — the disagreement is the
    # reason to probe, never the reason to drop. Honest lower bound, not a
    # firing proof.
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
    # SOLE PIN for ``state_changing IS NULL``. The fallback/receive shape:
    # ``_mutability_fields`` withholds the ABI flag to NULL for unselectored
    # entry points (no selector is not a proof of purity — WETH9's fallback()
    # writes balanceOf) while both evidence lists are proven-empty arrays — so
    # every other disjunct votes no and only the withheld-mutability ground
    # admits it. Deleting that disjunct reads "the ABI question was never
    # answered" as "proven inert", the exact collapse this filter exists to
    # prevent.
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
    # The view-contradiction rule withholds sinks/writes (89 legitimate
    # ``external_call`` sinks on 14 local rows). Withheld is not proven-absent.
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
    # The one proven-inert shape.
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
    # ``writer_selectors`` carries a FABRICATED ``keccak("fallback()")[:4]``
    # on 15 fallback/receive rows. The filter does not read the column, so a
    # fabricated selector cannot mint candidacy — this row is inert and stays out.
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
    # The two proven-present grounds, each the only admitter of its arm.
    assert sink_only_view.id in got
    assert write_only_view.id in got
    # The withheld-mutability ground, likewise the only admitter of its arm.
    assert mutability_withheld.id in got
    assert withheld.id in got
    assert inert.id not in got
    assert fabricated_selector.id not in got


def test_filter_a_is_total_over_every_persisted_jsonb_shape(db_session):
    """A non-array in ``state_writes`` / ``sinks`` reads as not-determined, and
    cannot abort the query.

    ``jsonb_array_length`` RAISES on a scalar, and one such row would kill
    candidate selection for the whole protocol — the same trap
    ``_carries_public_admission_claim`` documents. Both shapes are reachable
    today: the jsonb scalar ``null`` from any writer that bypasses
    ``none_as_null`` (``db/effect_cache.py:462`` is a live instance of that class),
    and a malformed payload from a hand-written backfill. Neither is
    evidence of emptiness, so both must ADMIT rather than raise or drop.
    """
    p = _protocol(db_session, "jsonb-shapes")
    c = _contract(db_session, p.id, ADDR(0x1200))
    written_null = _fn(db_session, c.id, name="a", selector="0xbc000001", effect_targets=[], state_changing=False)
    malformed = _fn(db_session, c.id, name="b", selector="0xbc000002", effect_targets=[], state_changing=False)
    db_session.commit()
    # Bypass the ORM: ``none_as_null=True`` cannot produce either shape.
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

    # And the predicate itself is total: no row evaluates to SQL NULL and drops
    # out of the ``or_`` silently.
    admitted = db_session.execute(
        select(func.count())
        .select_from(EffectiveFunction)
        .where(EffectiveFunction.contract_id == c.id, _has_effect_evidence())
    ).scalar_one()
    assert admitted == 2

    # The length guard is asserted on its OWN, not through the ``and_`` in
    # ``_evidence_proven_present``: SQL does not promise to short-circuit an AND,
    # so a cascade that only passes because the planner happened to evaluate the
    # cheap ``jsonb_typeof`` test first is not a proof of totality. Unguarded,
    # this SELECT raises ``cannot get array length of a scalar``.
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
    """The narrow-open, at the seam that actually decides it.

    ``authority_public = false`` used to be an unconditional filter, on the
    reasoning that a public function has no principal to resolve. That is true of
    the PRINCIPAL and false of the EFFECT: a permissionless payout or mint is the
    shape where "anyone can call this" IS the finding. Such a function is probed
    from an arbitrary non-zero identity, which is valid precisely because no gate
    has to be satisfied.

    Public functions that merely take money IN, or that route it through another
    contract, stay out: probing them corroborates nothing and spends fork budget.
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
    # A BLANK public function is still dropped: nothing says it moves value, and
    # the exception is keyed on the claim, never on publicness alone.
    assert blank.id not in got

    # Admitted for exactly the family its claim names — never the whole class set.
    assert got[payout.id].restrict_families == frozenset({EFFECT_CLASS_VALUE_OUT})
    assert got[minted.id].restrict_families == frozenset({EFFECT_CLASS_SUPPLY})
    # And admitted AS public, which is what routes the synthesizer onto the
    # neutral caller instead of demanding a resolved principal.
    assert got[payout.id].authority_public is True
    assert got[payout.id].principal_addresses == ()


def test_the_public_admission_predicate_survives_every_claims_shape(db_session):
    """``claims`` is not always an array. ``_enrolled_families`` documents that
    SQL NULL, ``[]`` and JSON-``null`` all occur and all read as blank — and a
    set-returning ``jsonb_array_elements`` raises "cannot extract elements from a
    scalar" on the last of those. One such row would abort candidate selection for
    the WHOLE protocol, so the predicate has to be total over the column."""
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

    # The query must RUN, and must admit exactly the well-formed carrier.
    got = {cand.function_id for cand in select_candidates(db_session, p.id)}
    assert got == {admitted.id}


def test_a_public_payout_reaches_a_synthesized_probe(db_session):
    """The claim that matters is not "the filter admits the row" but "a public
    value-mover gets probed". Asserted end to end across the two seams, because a
    previous fix satisfied the synthesizer alone and was dead code: selection
    never handed it a public candidate to act on."""
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
    """Gate lift: functions already carrying flow.*/supply.* claims are re-enrolled for
    exactly those value/supply families; other claims (pause/upgrade) stay dropped;
    blank functions keep the unrestricted (None) full-synthesis default."""
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
    # Carries only a non-value/supply claim → already explained → dropped.
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
    """A zero-weight FACT must never remove a function from evidence-gathering.

    ``rate_limit.consume`` records a fact at zero severity weight and
    ``delegatecall.execute`` names where foreign code comes from — neither
    EXPLAINS the function's value/supply behaviour, so neither may flip a blank
    row from ``None`` (full synthesis) to the empty frozenset (dropped as
    "already explained").

    This pins the 13 measured local-DB rows that would silently leave the
    candidate set the moment the claims plane mints the new ids (all gated,
    ``effect_targets`` non-empty, zero other claims — i.e. exactly the
    ``rate_only`` shape below): LRTSquaredAdmin.depositToStrategy 0xaf76d4bd
    (delegatecall.execute) and the 12 EtherFiNodesManager rate-limited rows —
    queueETHWithdrawal 0x03f49be8/0xc3a9e20e, queueWithdrawals
    0x0031e778/0xeea43aba, requestConsolidation 0x6691954e,
    requestExecutionLayerTriggeredWithdrawal 0xc390d8f5 among them.
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
    # Transparency must not LAUNDER either: alongside a flow claim the family
    # scoping still applies, and alongside an explanatory claim the row is
    # still explained and dropped.
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
    # The 13-row shape: fact-only claims read as BLANK → full synthesis.
    assert by_id[rate_only.id].restrict_families is None
    assert by_id[dc_only.id].restrict_families is None
    assert by_id[both_facts.id].restrict_families is None
    assert by_id[fact_and_flow.id].restrict_families == frozenset({EFFECT_CLASS_VALUE_OUT})
    assert fact_and_pause.id not in by_id


def test_candidate_carries_witnessed_value_holders_and_acting_floor(db_session):
    """Candidates carry the protocol's witnessed value-holder set (positive
    on-chain balances) and the acting deployment's own balance floor — the inputs
    the fork value-reach probe measures against."""
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
    # PER ASSET, keyed on (holder, asset). ``_balance`` writes NATIVE rows, so
    # the asset is the emitter a synthetic native Transfer log carries.
    holders = {(h.holder, h.asset): h.usd_value for h in cand.value_holders}
    native = NATIVE_ASSET_LOG_EMITTER
    assert holders[(ADDR(0x9001).lower(), native)] == pytest.approx(221_000_000.0)
    assert holders[(ADDR(0x9002).lower(), native)] == pytest.approx(55_200_000.0)
    # A holding priced at exactly ZERO is KEPT, where the old per-holder set dropped
    # it: a measured zero is evidence, and dropping it made "this holder moved an
    # asset worth nothing" indistinguishable from "this holder moved nothing".
    assert holders[(ADDR(0x9003).lower(), native)] == pytest.approx(0.0)
    # Acting floor is this deployment's own balance.
    assert cand.acting_balance_usd == pytest.approx(221_000_000.0)


@requires_postgres
def test_the_tvl_ceiling_reads_defillama_tvl_and_never_total_usd(db_session):
    """The reach ceiling's input. ``tvl_snapshots.total_usd`` and ``contract_breakdown``
    are NULL on EVERY row of this table locally, so a ceiling written against them
    could never fire — a dead sentinel. Reading ``defillama_tvl`` is the whole
    point, and a row that has only ``total_usd`` must read as NO ceiling (skipped),
    not as a ceiling of zero or of that number."""
    from datetime import datetime, timedelta, timezone

    from db.models import TvlSnapshot

    p = _protocol(db_session, "tvl-ceiling")
    c = _contract(db_session, p.id, ADDR(0x9500))
    f = _fn(db_session, c.id, name="withdraw", selector="0x95000001", effect_targets=["S"])
    _principal(db_session, f.id, ADDR(0x9501))
    now = datetime.now(timezone.utc)
    # Only total_usd: the column the old proposal would have read.
    db_session.add(TvlSnapshot(protocol_id=p.id, timestamp=now - timedelta(hours=2), total_usd=999.0, source="x"))
    db_session.commit()
    cand = {x.function_id: x for x in select_candidates(db_session, p.id)}[f.id]
    assert cand.protocol_tvl_usd is None  # skipped, loudly — never 999.0 and never 0

    # ...and the newest defillama figure wins once one exists.
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

    An at-cap holder is marked ``at_page_cap`` so the reach probe names it as the
    reason an asset could not be valued instead of quietly skipping it.

    THE LENGTH ARM IS GONE (§9.5-addendum B.1). The fetch now pages the endpoint to
    exhaustion, so a stored list longer than ``TOKEN_BALANCE_PAGE_SIZE`` is a routine
    COMPLETE list; comparing a count to the cap announced every large sheet as
    possibly incomplete. ``not_determined`` is still the below-cap answer — there is
    no ``complete`` state — but the long holder here reaches it on the merits.

    ARMED POPULATION, honestly: ``at_page_cap`` fires on ZERO local holders today
    (U2's de-capping retired every truncated list), so this is reachable by
    construction and covered here rather than measured on the corpus."""
    from utils.etherscan import TOKEN_BALANCE_PAGE_SIZE

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
    # The capped holder stores THREE rows and is still a prefix; the whole holder
    # stores more than a page and is still not a prefix. Neither fact is a count.
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
    # And there is no third state to reach: a "complete" answer would be a proven
    # absence derived from a count whose input was already filtered.
    from services.effects.selection import HOLDINGS_COMPLETENESS_STATES

    assert set(HOLDINGS_COMPLETENESS_STATES) == {"at_page_cap", "not_determined"}


@requires_postgres
def test_value_holders_are_per_asset_with_native_keyed_on_the_log_emitter(db_session):
    """The per-asset input fix. The reach probe used to receive ONE summed figure per holder and
    match any ``Transfer`` out of it against the whole sum — so a synthetic native move
    out of the weETH proxy claimed a sheet that is 99.99% eETH ($3.489B).

    Three properties, all load-bearing:
      * the native row is keyed on the emitter ``eth_simulateV1``'s ``traceTransfers``
        actually uses (measured live), so a native move can match it at all;
      * an UNPRICED holding survives as ``usd_value=None`` rather than being dropped or
        zeroed — it is what makes a reach total not-determined;
      * a holding is keyed on the DEPLOYMENT (the only address a Transfer log can
        name), and two implementation rows behind one proxy do not double-count it.
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
        # Each code row carries a COPY of the same deployment's sheet.
        _token_balance(db_session, impl.id, token, 250.0)
        _token_balance(db_session, impl.id, None, 4_000.0)
        _token_balance(db_session, impl.id, unpriced, None)
    db_session.commit()

    cand = next(c for c in select_candidates(db_session, p.id) if c.contract_id == impl_a.id)
    holdings = {(h.holder, h.asset): h.usd_value for h in cand.value_holders}
    assert holdings[(deployment.lower(), token.lower())] == 250.0
    assert holdings[(deployment.lower(), NATIVE_ASSET_LOG_EMITTER)] == 4_000.0
    assert holdings[(deployment.lower(), unpriced.lower())] is None
    # MAX per (holder, asset), not SUM: the token appears once at 250, not twice.
    assert sum(1 for (holder, asset) in holdings if asset == token.lower()) == 1
    assert len(cand.value_holders) == 3


def test_principal_addresses_are_totally_ordered_so_the_probe_identity_is_the_datas(db_session):
    """``principal_addresses[0]`` IS the identity every fork probe
    impersonates (``calldata`` :1395/:1437/:1720/:2312 and the code-upgrade plan),
    so an unordered read left WHO we simulate as — and therefore which gate the
    probe passes and what the witness records — to the query plan.

    A third determinism class: pinning PYTHONHASHSEED and pinning allocation order
    both fix the PROCESS, and neither can see a plan-order dependency. The rows are
    inserted in DESCENDING address order on purpose, so a plan that hands back heap
    order (what dropping the ORDER BY produces here) fails this assertion.
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
    # The load-bearing element, stated as its own assertion because it is the one a
    # probe actually consumes.
    assert cand.principal_addresses[0] == ADDR(0x7101).lower()


def test_blank_predicate_keys_on_claims_not_effect_labels(db_session):
    """effect_labels populated but claims empty => still blank => selected."""
    p = _protocol(db_session, "blank-proto")
    c = _contract(db_session, p.id, ADDR(0x2000))
    f = _fn(db_session, c.id, name="pauseUntil", selector="0xbbbb0001", effect_targets=["SLOT"])
    # A legacy effect_labels projection exists, but no claim was minted.
    f.effect_labels = ["pause"]
    f.claims = []

    # Blankness must hold across all three "no claim" storage shapes: [] above,
    # true SQL NULL, and JSON-null (what the ORM writes for Python None).
    sql_null = _fn(db_session, c.id, name="a", selector="0xbbbb0002", effect_targets=["S"])
    json_null = _fn(db_session, c.id, name="b", selector="0xbbbb0003", effect_targets=["S"], claims=None)
    db_session.commit()
    db_session.execute(text("UPDATE effective_functions SET claims = NULL WHERE id = :i"), {"i": sql_null.id})
    db_session.commit()

    got = {cand.function_id for cand in select_candidates(db_session, p.id)}
    assert {f.id, sql_null.id, json_null.id} <= got


# ---------------------------------------------------------------------------
# Ordering — transitive value-at-stake
# ---------------------------------------------------------------------------


def test_transitive_value_beats_direct_balance(db_session):
    """A $33K contract whose principal controls a $3.2B vault outranks a
    directly-richer-but-terminal $1B contract.

    Direct-balance ordering would bury the small controller; transitive reach
    surfaces it.
    """
    p = _protocol(db_session, "reach-proto")

    admin = _contract(db_session, p.id, ADDR(0x0A01))
    vault = _contract(db_session, p.id, ADDR(0x0B02))
    rich = _contract(db_session, p.id, ADDR(0x0C03))

    _balance(db_session, admin.id, 33_000.0)
    _balance(db_session, vault.id, 3_200_000_000.0)
    _balance(db_session, rich.id, 1_000_000_000.0)

    safe = ADDR(0x5AFE)
    # The Safe controls the vault: stored edge is vault-controlled-BY-safe.
    _edge(db_session, vault.id, controlled_contract=vault.address, controller=safe)

    # The high-blast-radius function lives on the tiny admin contract, gated by
    # the Safe. Its reach = admin ($33K) + vault ($3.2B) via the Safe principal.
    small = _fn(db_session, admin.id, name="setImpl", selector="0xdead0001", effect_targets=["IMPL"])
    _principal(db_session, small.id, safe)

    # The directly-rich contract is terminal: a gated blank function, no control edges out.
    big_direct = _fn(db_session, rich.id, name="sweep", selector="0xdead0002", effect_targets=["BAL"])
    _principal(db_session, big_direct.id, ADDR(0xE0A1))
    db_session.commit()

    ordered = select_candidates(db_session, p.id)
    ids = [c.function_id for c in ordered]
    assert ids.index(small.id) < ids.index(big_direct.id)

    by_id = {c.function_id: c for c in ordered}
    # EXACT, not approx: value_at_stake_usd is a Decimal, and `Decimal ==
    # pytest.approx(float)` is not an assertion — it returns True when the two
    # agree and raises TypeError when they do not, so it can only ever pass.
    assert by_id[small.id].value_at_stake_usd == Decimal("3200033000.00")
    assert by_id[big_direct.id].value_at_stake_usd == Decimal("1000000000.00")


def test_authority_graph_closure_is_transitive(db_session):
    """A → B → C: reachable value from A includes C (full downstream propagation)."""
    p = _protocol(db_session, "closure-proto")
    a = _contract(db_session, p.id, ADDR(0x0111))
    b = _contract(db_session, p.id, ADDR(0x0222))
    cc = _contract(db_session, p.id, ADDR(0x0333))
    _balance(db_session, a.id, 1.0)
    _balance(db_session, b.id, 10.0)
    _balance(db_session, cc.id, 100.0)
    # a controls b (b controlled-by a); b controls cc.
    _edge(db_session, b.id, controlled_contract=b.address, controller=a.address)
    _edge(db_session, cc.id, controlled_contract=cc.address, controller=b.address)
    db_session.commit()

    graph = build_authority_graph(db_session, p.id)
    assert graph.reachable_value({a.address}) == Decimal("111.00")
    assert graph.reachable_value({b.address}) == Decimal("110.00")
    assert graph.reachable_value({cc.address}) == Decimal("100.00")


def test_traversal_terminates_on_a_hand_built_cycle(db_session):
    """DEFENSIVE ONLY: given a mutual control pair, the walk must terminate and
    count each balance once.

    This test used to be named ``test_authority_graph_handles_cycles`` and was
    the codebase's only statement about mutual control pairs — which read as
    "a mutual control pair is a legitimate cycle". It is not. At most one of
    "A controls B" / "B controls A" can be true, and 66 directed edge pairs
    asserted both, because ``tracking.py:851`` unioned "gates the caller" with
    "gets called" (see ``test_callee_edges_move_no_authority`` below, which is
    the assertion this file was missing).

    The rows here are hand-built, not writer-produced. Cycle-safety is still a
    property the traversal must have — a genuine cycle is constructible
    on-chain and a stale graph can hold one — so the guard stays, relabelled so
    it stops standing in for a correctness claim it never made.
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
    """A slot the contract only CALLS must not move value into its reach.

    The positive half of the split: A genuinely controls B, so A's reach
    includes B's balance. The negative half: B merely calls A (``eETH``,
    ``lido``, ``liquidityPool`` shape), which is recorded as
    ``external_call_target`` and must leave B's reach at its own balance. The
    pre-split writer stored that second edge as ``controller_value`` too, which
    is exactly how a mutual pair was minted.
    """
    p = _protocol(db_session, "callee-proto")
    a = _contract(db_session, p.id, ADDR(0x0CC1))
    b = _contract(db_session, p.id, ADDR(0x0DD2))
    _balance(db_session, a.id, 5.0)
    _balance(db_session, b.id, 7.0)
    # A controls B.
    _edge(db_session, b.id, controlled_contract=b.address, controller=a.address)
    # B calls A. Not control.
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


# ---------------------------------------------------------------------------
# Cross-process determinism of the ordering value
#
# The class: `reachable_value` folds balances over a `set`, and set iteration
# order over strings varies with PYTHONHASHSEED. In binary float the fold is
# therefore order-dependent in its low bits. A within-process test cannot see
# this — one process has one seed — which is why the defect survived a suite
# that ran these very functions. Every test below either runs REAL CHILD
# PROCESSES under different seeds, or pins exactness against a fixture proven
# to be order-sensitive in float.
# ---------------------------------------------------------------------------

# Three real balances from the local corpus: the weETH deployment's eETH, the
# EtherFiRestaker's stETH, and the LiquidityPool. Their float sum depends on
# addition order (see the assertion in the first test); their exact sum does not.
_ORDER_SENSITIVE_USD = ("3488954369.29", "472190234.24", "57041255.72")
_ORDER_SENSITIVE_EXACT = Decimal("4018185859.25")


def test_order_sensitive_fixture_really_is_order_sensitive():
    """Guard the guard: if float addition of these three terms ever became
    order-invariant, the tests below would still pass while proving nothing.

    This is the corpus rule applied to a unit fixture — a green result means
    something only if the fixture contains a shape a wrong implementation
    would get wrong."""
    import itertools

    sums = {sum(p) for p in itertools.permutations([float(x) for x in _ORDER_SENSITIVE_USD])}
    assert len(sums) > 1, "fixture no longer discriminates: float addition is order-invariant here"
    assert sum(Decimal(x) for x in _ORDER_SENSITIVE_USD) == _ORDER_SENSITIVE_EXACT


def test_reachable_value_is_exact_over_an_order_sensitive_closure(db_session):
    """The closure sum is the exact cent total, not one of the float roundings."""
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
    # And it is exact, not merely close: no float rounding of these terms equals it.
    assert isinstance(got, Decimal)


def test_equal_reach_orders_by_function_id_not_by_rounding(db_session):
    """The POSITIVE case for the `function_id` tiebreak, not just its presence.

    Two functions that reach the SAME money must compare exactly equal, because
    the tiebreak fires on equality alone — under a float fold, one ulp between
    two candidates holding identical balances routes them around it and orders
    the probe queue by rounding noise instead of by id."""
    p = _protocol(db_session, "tiebreak-proto")
    holders = [_contract(db_session, p.id, ADDR(0xE001 + i)) for i in range(3)]
    for c, usd in zip(holders, _ORDER_SENSITIVE_USD):
        _balance(db_session, c.id, usd)
    # Two acting contracts, each controlling the same three holders by a
    # different edge insertion order.
    left = _contract(db_session, p.id, ADDR(0xE0FE))
    right = _contract(db_session, p.id, ADDR(0xE0FF))
    for c in holders:
        _edge(db_session, c.id, controlled_contract=c.address, controller=left.address)
    for c in reversed(holders):
        _edge(db_session, c.id, controlled_contract=c.address, controller=right.address)
    # `right` gets the LOWER function id, so ordering by id puts it first while
    # ordering by insertion or by rounding would not.
    f_right = _fn(db_session, right.id, name="rightFn", selector="0xeeee0001", effect_targets=["S"])
    f_left = _fn(db_session, left.id, name="leftFn", selector="0xeeee0002", effect_targets=["S"])
    db_session.commit()

    by_id = {c.function_id: c for c in select_candidates(db_session, p.id)}
    assert by_id[f_left.id].value_at_stake_usd == by_id[f_right.id].value_at_stake_usd
    ordered = [c.function_id for c in select_candidates(db_session, p.id)]
    assert ordered.index(f_right.id) < ordered.index(f_left.id)


def test_reachable_value_is_identical_across_processes():
    """The one shape a same-process test cannot express: DIFFERENT seeds.

    Runs the real `AuthorityGraph` in child processes under four
    PYTHONHASHSEED values and compares `repr()` of the result. Under the float
    fold this returned up to three distinct values for one graph."""
    import subprocess
    import sys

    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    prog = (
        "import sys; sys.path.insert(0, %r)\n"
        "from services.effects.selection import AuthorityGraph\n"
        "from decimal import Decimal\n"
        "usd = %r\n"
        # Many nodes so the closure `set` is large enough for seed-dependent
        # iteration order to be expressed.
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
    """`usd_value DESC` alone leaves tied holdings to the query plan, and which
    ones survive the limit is then not a function of the data."""
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
    """The probe's input is positions, and a crumb is excluded by RULE.

    $0.004 is a real figure on a real quantity. It used to be excluded because
    ``usd_value`` was ``numeric(20,2)`` and stored it as 0.00, which the
    ``> 0`` filter then rejected — so the exclusion lived in the column's scale
    and nowhere else. The column now holds ``0.004000000000000000`` (asserted
    below off Postgres, so the crumb under test is a STORED one), and the row
    stays out because the threshold says a position starts at a cent.

    The boundary is on the keep side: $0.01 exactly is a position, which is the
    side the old cent-scaled column put it on.
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


# ---------------------------------------------------------------------------
# Resource safety-valve
# ---------------------------------------------------------------------------


def test_resource_cap_logs_exactly_what_it_dropped(db_session, caplog):
    """The safety-valve drops the lowest-value candidates and NAMES each one."""
    p = _protocol(db_session, "cap-proto")
    c = _contract(db_session, p.id, ADDR(0x0D00))

    # Three gated-blank candidates with distinct reach so ordering is determinate.
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
    # Names the two dropped candidates (in ``extra``, queryable), not the kept one.
    assert rec.dropped == 2
    assert rec.dropped_sample_truncated is False
    assert {e["function_id"] for e in rec.dropped_sample} == {drop_mid.id, drop_low.id}
    assert {e["selector"] for e in rec.dropped_sample} == {"0xcafe0002", "0xcafe0003"}
    assert keep.id not in {e["function_id"] for e in rec.dropped_sample}


def test_value_never_gates_without_cap(db_session):
    """With no cap, EVERY blank-gated behavior is selected regardless of value."""
    p = _protocol(db_session, "nogate-proto")
    c = _contract(db_session, p.id, ADDR(0x0E00))
    # No balances anywhere -> all value_at_stake == 0, but nothing is dropped.
    fns = [_fn(db_session, c.id, name=f"f{i}", selector=f"0xfeed000{i}", effect_targets=["S"]) for i in range(4)]
    db_session.commit()

    got = {cand.function_id for cand in select_candidates(db_session, p.id)}
    assert got == {f.id for f in fns}


# ---------------------------------------------------------------------------
# Optional: the real-protocol funnel against the dev DB (skips when absent)
# ---------------------------------------------------------------------------


def _dev_engine():
    url = os.environ.get("PSAT_DEV_DATABASE_URL", "postgresql://psat:psat@localhost:5433/psat")
    try:
        eng = create_engine(url)
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        return eng
    except Exception:
        return None


def test_appendix_a_funnel_on_dev_db():
    """Reproduce the selection funnel + gate-lift partition for etherfi (protocol_id=1).

    Counts are computed LIVE from SQL rather than hardcoded — the dev DB drifts as
    the matchers grow, so the invariant tested is the PARTITION (blank subset ==
    the old blank-claim predicate; enrolled == flow/supply claim carriers), not a
    frozen number. Data-gated: skips cleanly when the dev DB / etherfi rows are
    absent so CI's fresh empty DB never depends on it.
    """
    eng = _dev_engine()
    if eng is None:
        pytest.skip("dev psat DB not reachable")
    with Session(eng) as s:
        # The dev DB is a snapshot of a past run and is treated as read-only, so
        # it lags the migration chain. Skip rather than migrate it: this test is
        # data-gated by design and a missing relation is the same "absent" case.
        if not s.execute(text("SELECT to_regclass('public.contract_balances_latest')")).scalar_one():
            pytest.skip("dev DB predates the balance-provenance migration")
        present = s.execute(
            text(
                "SELECT count(*) FROM effective_functions ef "
                "JOIN contracts c ON c.id = ef.contract_id WHERE c.protocol_id = 1"
            )
        ).scalar_one()
        if not present:
            pytest.skip("etherfi (protocol_id=1) rows absent from dev DB")

        # The blank-claim predicate count (evidence + gated + no confident claim) —
        # the set the cascade's own filters (a) and (c) admit for full synthesis.
        # Filter (a) is taken from the module rather than hand-copied as SQL: the
        # copy was of ``array_length(effect_targets,1) > 0``, and keeping a second
        # spelling of a retired conflation in a test is how a defect outlives its
        # fix. What this asserts is the PARTITION (blank == the (a)+(c)+blank set,
        # enrolled == the flow/supply claim carriers), not a frozen number.
        expected_blank = s.execute(
            select(func.count())
            .select_from(EffectiveFunction)
            .join(Contract, Contract.id == EffectiveFunction.contract_id)
            .where(
                Contract.protocol_id == 1,
                _has_effect_evidence(),
                EffectiveFunction.authority_public.is_(False),
                # jsonb_typeof(SQL NULL) is SQL NULL, so the ELSE arm already folds
                # the no-row-value case to 0 — all three "no claims" states land here.
                text(
                    "(CASE WHEN jsonb_typeof(effective_functions.claims) = 'array' THEN "
                    "jsonb_array_length(effective_functions.claims) ELSE 0 END) = 0"
                ),
            )
        ).scalar_one()

        cands = select_candidates(s, 1)
        blank = [c for c in cands if c.restrict_families is None]
        # The blank subset is exactly the old candidate set — the gate lift is
        # purely additive over blank functions (no blank function lost).
        assert len(blank) == expected_blank
        # Gate lift: every value-mover already carries flow.out, so the lift
        # re-enrolls a non-empty set of claim-carrying functions for value/supply
        # probing — restricted to exactly those families, never the whole set.
        enrolled = [c for c in cands if c.restrict_families]
        assert enrolled
        for c in enrolled:
            assert c.restrict_families is not None
            assert c.restrict_families <= {"value_out", "supply"}


# ---------------------------------------------------------------------------
# Probe target (proxy vs implementation)
# ---------------------------------------------------------------------------


def test_probe_target_is_the_deployment_not_the_implementation(db_session):
    """A proxy-backed function must be PROBED at its deployment: the
    implementation holds none of the state the probes read, so probing it yields
    quietly-wrong witnesses (an empty totalSupply, a virgin pause latch). Hashing
    deliberately stays on the code-bearing address."""
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
    # No deployment recorded ⇒ the code-bearing address is the probe target.
    assert by_name["sweep"].probe_target == ADDR(0x7001).lower()


# ---------------------------------------------------------------------------
# Per-job scoping (JobScope) — the candidate set must PARTITION across a
# protocol's jobs without losing a single candidate.
# ---------------------------------------------------------------------------


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
    """Mark a job as having finished the effects stage the way BaseWorker does.

    ``status`` mirrors ``_record_stage_timing``: ``"success"`` on the success
    path, ``"failed"`` on the failure path — the SAME artifact name either way.
    """
    session.add(
        Artifact(job_id=job.id, name="stage_timing_effects", data={"stage": "effects", "status": status}),
    )
    job.status = JobStatus.completed
    job.stage = JobStage.done
    session.flush()


def _verdict_for(session: Session, function_id: int, address: str) -> None:
    """The residue a sweep leaves behind on a contract it planned."""
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
    """Three contracts: A and B have a protocol-bearing job; C's only job carries
    no protocol_id — the live shape where one candidate-owning contract had no
    job that would ever scope to it."""
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


# --- Shape 1: full run — every contract has a current, in-flight job ---------


def test_shape1_full_run_plans_own_contract_not_its_siblings(db_session):
    """The defect: every job re-planned every other contract's candidates."""
    proto, addrs, fns, _ = _scoped_fixture(db_session)
    got = _scoped(db_session, proto.id, addrs["a"])
    assert fns["a"] in got
    assert fns["b"] not in got


def test_shape1_sweeps_contracts_no_job_would_ever_claim(db_session):
    """Coverage guard: C has no protocol-bearing job, so no scoped job owns it.
    Every job must sweep it or its verdicts vanish silently."""
    proto, addrs, fns, _ = _scoped_fixture(db_session)
    for owner in ("a", "b"):
        assert fns["c"] in _scoped(db_session, proto.id, addrs[owner]), f"unowned contract dropped by job {owner}"


def test_shape1_scoped_union_equals_protocol_wide_set(db_session):
    """The coverage proof: the union over a protocol's per-job scopes is exactly
    the protocol-wide candidate set. No function loses its verdict."""
    proto, addrs, _fns, _ = _scoped_fixture(db_session)
    protocol_wide = {c.function_id for c in select_candidates(db_session, proto.id)}
    union: set[int] = set()
    for job_addr in addrs.values():
        union |= _scoped(db_session, proto.id, job_addr)
    assert union == protocol_wide


def test_shape1_job_that_completes_early_is_not_re_swept(db_session):
    """The transition edge: B finishes the effects stage mid-run. It is no longer
    in flight, so a row-existence rule would re-sweep it into every later job —
    the storm coming back through the side door."""
    proto, addrs, fns, jobs = _scoped_fixture(db_session)
    _ran_effects(db_session, jobs["b"])
    db_session.commit()

    got = _scoped(db_session, proto.id, addrs["a"])
    assert fns["b"] not in got
    assert fns["a"] in got


def test_shape1_completed_job_that_wrote_no_verdicts_is_still_owned(db_session):
    """5 of 29 contracts in the live run planned candidates and wrote no verdict.
    Verdict-existence alone would re-sweep them forever, so the "its own job ran
    the stage" signal has to stand on its own."""
    proto, addrs, fns, jobs = _scoped_fixture(db_session)
    _ran_effects(db_session, jobs["b"])
    db_session.commit()
    assert not db_session.query(EffectVerdict).count()
    assert fns["b"] not in _scoped(db_session, proto.id, addrs["a"])


# --- Shape 2: incremental run — one new contract joins an analyzed protocol ---


def test_shape2_new_contract_does_not_replan_the_protocol(db_session):
    """A single new contract joining an already-analyzed protocol must plan only
    itself — the settled contracts keep the verdicts they already have."""
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


# --- Shape 3: first-ever effects run on production's shape -------------------


def _prod_shape(session: Session, n_contracts: int = 4):
    """Production's steady state: every job COMPLETED in an earlier run, none of
    them ever ran the effects stage, and there is not a single verdict anywhere."""
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
    """On prod every contract has a completed job, so a row-existence ownership
    rule marked all of them owned and NOTHING would plan them —
    a silent recall regression that looks exactly like a perf win."""
    proto, addrs, fns = _prod_shape(db_session)
    got = _scoped(db_session, proto.id, addrs[0])
    assert got == set(fns.values()), "prod-shape contracts must all be swept on the first effects run"


def test_shape3_fresh_job_owns_itself_so_the_sweep_stays_bounded(db_session):
    """When the run does give a contract a fresh job, that job owns it and the
    others stop sweeping it — the sweep never covers contracts already scheduled."""
    proto, addrs, fns = _prod_shape(db_session)
    _job(db_session, proto.id, addrs[1])  # the new run's job for contract 1
    db_session.commit()
    assert fns[addrs[1]] not in _scoped(db_session, proto.id, addrs[0])


def test_shape3_sweep_is_self_limiting_once_verdicts_land(db_session):
    """Anti-storm: the first job to sweep a contract leaves verdicts behind, which
    marks it planned for every job after it. Without this the prod shape would
    have every job planning every contract, reinstating the storm."""
    proto, addrs, fns = _prod_shape(db_session)
    swept = _scoped(db_session, proto.id, addrs[0])
    assert swept == set(fns.values())

    # The sweeping job writes a verdict per planned candidate.
    for addr, fid in fns.items():
        _verdict_for(db_session, fid, addr)
    db_session.commit()

    # The next job now plans only its own contract.
    assert _scoped(db_session, proto.id, addrs[1]) == {fns[addrs[1]]}


def test_owner_job_must_belong_to_the_same_protocol(db_session):
    """One address can be a contract of two protocols; a job for the OTHER
    protocol must not silently claim ownership and strand this one's candidates."""
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
    """A job that will never reach the effects stage cannot be a contract's owner
    — otherwise the sweep skips a contract nothing else covers."""
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
    """Protocol-wide selection handed a chain-1 job another chain's contracts and
    probed them through chain-1 seams. A scoped job sees only its own chain."""
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
    """Callers with no job identity (a company/root job) still see everything."""
    proto, _addrs, fns, _ = _scoped_fixture(db_session)
    got = {c.function_id for c in select_candidates(db_session, proto.id)}
    assert got == set(fns.values())


# ---------------------------------------------------------------------------
# Ownership rule 4 — the empty-planning marker.
#
# Rules 1-3 all leave a trace only when SOMETHING happened: a job exists, a
# stage artifact was written, a verdict landed. A contract that is swept and
# whose candidates yield no plans at all leaves none of those, so it stays
# unowned and every later job re-sweeps it. These cover both directions: the
# marker must stop the re-sweep, and it must never make a contract look covered.
# ---------------------------------------------------------------------------


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
    """An owner contract with a live job, plus a contract nothing will ever own —
    the shape that gets re-swept forever when its planning yields nothing."""
    owner_addr, orphan_addr = ADDR(0x8601), ADDR(0x8602)
    owner = _contract(session, proto.id, owner_addr, chain="ethereum")
    _fn(session, owner.id, name="own", selector="0x00008601", effect_targets=["s"])
    orphan = _contract(session, proto.id, orphan_addr, chain="ethereum")
    orphan_fn = _fn(session, orphan.id, name="orph", selector="0x00008602", effect_targets=["s"])
    _job(session, proto.id, owner_addr)
    session.commit()
    return owner_addr, orphan_fn.id, orphan


def test_shape1_empty_planning_marker_stops_the_re_sweep(db_session):
    """Gap 2: a swept contract whose candidates produce NO plans writes no
    verdict, so rule 3 never fires and every later job re-sweeps it."""
    proto = _protocol(db_session, "scope-marker-full")
    owner_addr, orphan_fn, orphan = _swept_only(db_session, proto)
    reading_job_created = datetime.now(timezone.utc)

    assert orphan_fn in _scoped_since(db_session, proto.id, owner_addr, reading_job_created)

    _mark_planned_empty(db_session, orphan.id, None, at=reading_job_created + timedelta(seconds=1))
    db_session.commit()
    assert orphan_fn not in _scoped_since(db_session, proto.id, owner_addr, reading_job_created)


def test_marker_older_than_the_reading_job_does_not_own(db_session):
    """The expiry that keeps the marker safe: planning inputs are not immutable
    (an upgrade_events row lands, a re-analysis rewrites the functions), so a
    marker from a previous run must NOT suppress this run's sweep."""
    proto = _protocol(db_session, "scope-marker-stale")
    owner_addr, orphan_fn, orphan = _swept_only(db_session, proto)
    reading_job_created = datetime.now(timezone.utc)

    _mark_planned_empty(db_session, orphan.id, None, at=reading_job_created - timedelta(hours=6))
    db_session.commit()
    assert orphan_fn in _scoped_since(db_session, proto.id, owner_addr, reading_job_created)


def test_marker_is_ignored_without_a_planned_since(db_session):
    """No timestamp ⇒ rule 4 off. Costs a sweep, never coverage."""
    proto = _protocol(db_session, "scope-marker-nosince")
    owner_addr, orphan_fn, orphan = _swept_only(db_session, proto)
    _mark_planned_empty(db_session, orphan.id, None, at=datetime.now(timezone.utc) + timedelta(hours=1))
    db_session.commit()
    assert orphan_fn in _scoped(db_session, proto.id, owner_addr)


def test_marker_does_not_shadow_a_contract_that_yields_plans(db_session):
    """Coverage guard. The marker is per-contract, so it must not be readable as
    ownership for any contract other than the one recorded."""
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
    """Incremental shape: the new contract's job was created AFTER the previous
    run's marker, so the empty contract is planned once more against whatever
    facts have landed since — then marked again."""
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

    # ...and the re-plan refreshes it, so the rest of this run skips it again.
    db_session.query(EffectsPlanMarker).filter(EffectsPlanMarker.contract_id == empty.id).update(
        {"planned_at": this_run + timedelta(seconds=1)}
    )
    db_session.commit()
    assert _scoped_since(db_session, proto.id, new_addr, this_run) == {new_fn.id}


def test_shape3_prod_first_run_still_sweeps_everything(db_session):
    """First-ever effects run on production's shape — all jobs completed, zero
    verdicts, zero markers. Nothing may look owned."""
    proto, addrs, fns = _prod_shape(db_session, 3)
    now = datetime.now(timezone.utc)
    assert _scoped_since(db_session, proto.id, addrs[0], now) == set(fns.values())


def test_shape3_marker_bounds_the_prod_sweep_to_once_per_run(db_session):
    """On the prod shape every contract is unowned, so the FIRST job sweeps them
    all. Contracts that yield nothing get a marker; the next job must skip those
    and still plan its own."""
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
    """The coverage proof under rule 4: markers only ever land on contracts a job
    actually planned, so the union over the run is still the protocol-wide set."""
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
        # Everything this job planned and that yielded nothing is now marked —
        # the worst case for coverage, since it maximises what later jobs skip.
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


# ---------------------------------------------------------------------------
# Ownership under FAILURE — rules 1 and 2 are the two that can claim a contract
# NOBODY ends up planning.
#
# ``BaseWorker`` writes the SAME ``stage_timing_effects`` artifact whether the
# stage succeeded or blew up, and the effects stage fail-forwards (the terminal
# finalizer advances the job to ``coverage`` instead of failing it), so a stage
# that failed never runs again. Reading either the artifact alone or "in flight"
# alone as ownership therefore drops a contract silently and permanently.
# ---------------------------------------------------------------------------


def _pair(session: Session, name: str, *, a: int = 0x8801, b: int = 0x8802):
    """Reader contract A + subject contract B, each with one gated candidate."""
    proto = _protocol(session, name)
    a_addr, b_addr = ADDR(a), ADDR(b)
    fns: dict[str, int] = {}
    for key, addr, idx in (("a", a_addr, a), ("b", b_addr, b)):
        contract = _contract(session, proto.id, addr, chain="ethereum")
        fns[key] = _fn(session, contract.id, name=key, selector=f"0x0000{idx:04x}", effect_targets=["s"]).id
    session.commit()
    return proto, a_addr, b_addr, fns


def test_failed_effects_stage_is_not_ownership(db_session):
    """Defect 1. B's job ran the effects stage and it FAILED; the fail-forward
    finalizer advanced the job to coverage, so the stage will never run again.
    Before the fix the mere existence of ``stage_timing_effects`` marked B owned,
    and neither B's own job nor any sibling ever planned it — silent, permanent
    coverage loss that reads as a perf win."""
    proto, a_addr, b_addr, fns = _pair(db_session, "fail-rule2")
    _job(db_session, proto.id, a_addr)
    b_job = _job(db_session, proto.id, b_addr)
    _ran_effects(db_session, b_job, status="failed")
    db_session.commit()

    assert fns["b"] in _scoped(db_session, proto.id, a_addr), "a failed effects stage must not own its contract"


def test_successful_effects_stage_is_still_ownership(db_session):
    """The other side of defect 1's fix: a stage that SUCCEEDED must keep owning
    its contract, or the per-job scoping collapses back into the storm."""
    proto, a_addr, b_addr, fns = _pair(db_session, "ok-rule2")
    _job(db_session, proto.id, a_addr)
    b_job = _job(db_session, proto.id, b_addr)
    _ran_effects(db_session, b_job, status="success")
    db_session.commit()

    assert fns["b"] not in _scoped(db_session, proto.id, a_addr)


def test_stage_timing_without_a_status_is_not_ownership(db_session):
    """Fail-safe direction: an artifact whose status cannot be read (legacy row,
    undecodable body) re-sweeps rather than skips. Costs work, never coverage."""
    proto, a_addr, b_addr, fns = _pair(db_session, "nostatus-rule2")
    _job(db_session, proto.id, a_addr)
    b_job = _job(db_session, proto.id, b_addr)
    db_session.add(Artifact(job_id=b_job.id, name="stage_timing_effects", data={"stage": "effects"}))
    b_job.status = JobStatus.completed
    b_job.stage = JobStage.done
    db_session.commit()

    assert fns["b"] in _scoped(db_session, proto.id, a_addr)


def _store_stage_timing(session: Session, job: Job, status: str) -> None:
    """Write the artifact through the REAL writer so the body lands in object
    storage and ``artifacts.data`` is JSON-null — production's shape."""
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
    """The prod/preview shape. With ``ARTIFACT_STORAGE_*`` configured the body
    lives in the bucket and ``artifacts.data`` is JSON ``null`` — measured on
    psat-pr-160, 70/70 ``stage_timing_effects`` rows have a NULL
    ``data->>'status'``. A SQL-only status check would silently never fire, so
    the status has to be resolved from storage."""
    proto, a_addr, b_addr, fns = _pair(db_session, "fail-rule2-storage", a=0x8811, b=0x8812)
    _job(db_session, proto.id, a_addr)
    b_job = _job(db_session, proto.id, b_addr)
    _store_stage_timing(db_session, b_job, "failed")

    row = db_session.query(Artifact).filter(Artifact.job_id == b_job.id).one()
    assert row.storage_key and row.data is None, "fixture must reproduce the storage-backed shape"
    assert fns["b"] in _scoped(db_session, proto.id, a_addr)


def test_storage_backed_successful_stage_is_still_ownership(db_session, storage_bucket):
    """...and the efficiency win survives in that same shape."""
    proto, a_addr, b_addr, fns = _pair(db_session, "ok-rule2-storage", a=0x8821, b=0x8822)
    _job(db_session, proto.id, a_addr)
    b_job = _job(db_session, proto.id, b_addr)
    _store_stage_timing(db_session, b_job, "success")

    assert fns["b"] not in _scoped(db_session, proto.id, a_addr)


def test_in_flight_job_past_the_effects_stage_is_not_ownership(db_session):
    """Defect 2. B's effects stage failed and the fail-forward finalizer moved the
    job to ``coverage``: still in flight, but it can never run effects again.
    Before the fix rule 1 kept B hidden from every sibling until the whole job
    finished — and if no sibling ran after that, forever."""
    proto, a_addr, b_addr, fns = _pair(db_session, "fail-rule1", a=0x8831, b=0x8832)
    _job(db_session, proto.id, a_addr)
    b_job = _job(db_session, proto.id, b_addr)
    _ran_effects(db_session, b_job, status="failed")
    b_job.status = JobStatus.processing
    b_job.stage = JobStage.coverage
    db_session.commit()

    assert fns["b"] in _scoped(db_session, proto.id, a_addr)


def test_in_flight_job_that_skipped_effects_is_not_ownership(db_session):
    """The same hole with no artifact at all: with ``PSAT_EFFECTS_STAGE`` off the
    policy stage advances straight to ``coverage``, so an in-flight job can sit
    past the effects stage having never run it."""
    proto, a_addr, b_addr, fns = _pair(db_session, "skip-rule1", a=0x8841, b=0x8842)
    _job(db_session, proto.id, a_addr)
    b_job = _job(db_session, proto.id, b_addr)
    b_job.stage = JobStage.coverage
    db_session.commit()

    assert fns["b"] in _scoped(db_session, proto.id, a_addr)


@pytest.mark.parametrize("stage", [JobStage.discovery, JobStage.static, JobStage.policy, JobStage.effects])
def test_in_flight_job_before_the_effects_stage_still_owns(db_session, stage):
    """Anti-storm guard for defect 2's fix: a job that has not yet passed the
    effects stage still owns its contract, whatever stage it sits at. Dropping
    that would send every job back to sweeping every sibling."""
    proto, a_addr, b_addr, fns = _pair(db_session, f"live-rule1-{stage.value}", a=0x8851, b=0x8852)
    _job(db_session, proto.id, a_addr)
    b_job = _job(db_session, proto.id, b_addr)
    b_job.stage = stage
    db_session.commit()

    assert fns["b"] not in _scoped(db_session, proto.id, a_addr)


# --- Shape 4: failure interleavings ------------------------------------------
#
# A protocol whose jobs did not all succeed. Every contract must still be planned
# by SOMEBODY, and the union over the run must still be the protocol-wide set.


def _interleaved(session: Session, name: str):
    """Five contracts, five fates:

    healthy   — its job ran effects successfully (owned; nobody re-plans it)
    failed    — its job ran effects and the stage FAILED (must be re-swept)
    died      — its job died terminally before ever reaching effects
    forwarded — its job is still in flight but already past effects
    reader    — the job doing the selecting
    """
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
    """The interleaving proof: the one job still able to run effects picks up every
    contract whose own job failed, died, or fail-forwarded — and leaves the one
    healthy contract alone."""
    proto, addrs, fns = _interleaved(db_session, "shape4-mixed")
    got = _scoped(db_session, proto.id, addrs["reader"])
    assert fns["failed"] in got
    assert fns["died"] in got
    assert fns["forwarded"] in got
    assert fns["reader"] in got
    assert fns["healthy"] not in got


def test_shape4_union_over_the_jobs_that_can_still_run_equals_the_protocol_set(db_session):
    """The real coverage bar under failure. Union over EVERY job address is
    vacuous — the own-address clause plans a contract for a job that is dead and
    will never call selection again. So union only over the jobs that can still
    reach the effects stage, and add back the contracts an earlier stage
    demonstrably planned (verdict evidence). That must still be the whole
    protocol-wide set."""
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
    """A storage-backed artifact with no bucket configured re-sweeps. The unread
    status must never be assumed successful — a bucket outage may cost work, it
    may not cost coverage."""
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
    """Same direction when the bucket IS configured but the object is gone."""
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
    """The read is per-job-per-selection, so a wave of N jobs would otherwise pay
    N× the same GET. A finished job can never rewrite its artifact, so its status
    is memoised — proven by deleting the object and getting the same answer."""
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
    """A job whose effects stage failed and was requeued still plans its own
    contract — the own-address clause never depends on any ownership rule."""
    proto, addrs, fns = _interleaved(db_session, "shape4-self")
    assert fns["failed"] in _scoped(db_session, proto.id, addrs["failed"])


def test_the_page_cap_signal_is_read_off_the_response_not_the_filtered_rows(monkeypatch):
    """The truncation discriminator's INPUT must not be a list a filter already thinned.

    ``get_token_balances`` keeps an entry only when ``raw_balance > 0``, and the page-cap
    check used to be evaluated on that filtered list — so a FULL page containing any
    zero-balance entry read as "not truncated", one line below the filter that destroyed
    the signal. The check now asks how many entries the ENDPOINT returned.
    """
    from utils import etherscan

    cap = etherscan.TOKEN_BALANCE_PAGE_SIZE
    page = [
        {
            "TokenAddress": f"0x{i:040x}",
            "TokenName": "T",
            "TokenSymbol": "T",
            "TokenDivisor": "18",
            # ONE zero-balance entry in an otherwise full page: 100 returned, 99 stored.
            "TokenQuantity": "0" if i == 0 else str(10**18),
            "TokenPriceUSD": "1",
        }
        for i in range(cap)
    ]
    monkeypatch.setattr(etherscan, "get", lambda *a, **k: {"result": page})
    monkeypatch.setattr(etherscan.time, "sleep", lambda _s: None)
    warnings: list[str] = []
    monkeypatch.setattr(etherscan.logger, "warning", lambda msg, *a: warnings.append(msg % a))

    rows = etherscan.get_token_balances("0x" + "ab" * 20, 1)

    assert len(rows) == cap - 1, "the zero-balance entry is still filtered out of the stored rows"
    # The stub re-serves page 1 for every request, so paging cannot reach a short
    # page and the list stays a declared PREFIX — which is the same fail-closed
    # answer a full first page always produced, reported in the paged wording.
    assert any("PREFIX" in w for w in warnings), "a full page went unreported because the filter shrank the list"
    assert any(f"({cap} entries over 2 page(s), {cap - 1} with a balance)" in w for w in warnings)
    # NEGATIVE CONTROL: a genuinely short page reports nothing.
    monkeypatch.setattr(etherscan, "get", lambda *a, **k: {"result": page[:3]})
    warnings.clear()
    etherscan.get_token_balances("0x" + "ac" * 20, 1)
    assert not [w for w in warnings if "FULL page" in w]
