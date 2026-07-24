"""Tests for services.effects.selection — §6 cascade + value-at-stake ordering.

Synthetic fixtures drive the always-run assertions (cascade correctness,
transitive-vs-direct ordering, dropped-work logging). One optional test
reproduces the Appendix A funnel against the dev ``psat`` DB when present and
skips cleanly otherwise, so CI (which starts from a fresh empty DB) never
depends on dev data.
"""

from __future__ import annotations

import logging
import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from db.models import (
    Contract,
    ContractBalance,
    ControlGraphEdge,
    EffectiveFunction,
    FunctionPrincipal,
    Protocol,
)
from services.effects.selection import build_authority_graph, select_candidates
from tests.conftest import ADDR, requires_postgres

pytestmark = requires_postgres


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _protocol(session: Session, name: str) -> Protocol:
    p = Protocol(name=name)
    session.add(p)
    session.flush()
    return p


def _contract(session: Session, protocol_id: int, addr: str, **kw) -> Contract:
    c = Contract(protocol_id=protocol_id, address=addr, **kw)
    session.add(c)
    session.flush()
    return c


def _fn(
    session: Session,
    contract_id: int,
    *,
    name: str,
    selector: str | None = None,
    effect_targets: list[str] | None = None,
    claims=None,
    authority_public: bool = False,
    deployment_address: str | None = None,
) -> EffectiveFunction:
    f = EffectiveFunction(
        contract_id=contract_id,
        function_name=name,
        selector=selector,
        effect_targets=effect_targets,
        claims=claims,
        authority_public=authority_public,
        deployment_address=deployment_address,
    )
    session.add(f)
    session.flush()
    return f


def _balance(session: Session, contract_id: int, usd: float) -> None:
    session.add(
        ContractBalance(
            contract_id=contract_id,
            token_address=None,  # native
            raw_balance="0",
            decimals=18,
            usd_value=usd,
        )
    )


def _edge(session: Session, contract_id: int, controlled_contract: str, controller: str) -> None:
    # Stored edge is contract-controlled-BY-controller: from = contract, to = controller.
    session.add(
        ControlGraphEdge(
            contract_id=contract_id,
            from_node_id=f"address:{controlled_contract.lower()}",
            to_node_id=f"address:{controller.lower()}",
            relation="controller_value",
        )
    )


def _principal(session: Session, function_id: int, addr: str) -> None:
    session.add(FunctionPrincipal(function_id=function_id, address=addr))


# ---------------------------------------------------------------------------
# Cascade
# ---------------------------------------------------------------------------


def test_cascade_filters_sink_claim_and_public(db_session):
    """Sink-empty dropped; claim-present dropped; public dropped; blank-gated kept.

    The blank predicate MUST key on ``claims``, not ``effect_labels``: a row
    with a populated ``effect_labels`` but empty ``claims`` is still blank and
    must survive.
    """
    p = _protocol(db_session, "cascade-proto")
    c = _contract(db_session, p.id, ADDR(0x1000))

    kept = _fn(db_session, c.id, name="pause", selector="0xaaaa0001", effect_targets=["SLOT"])
    # (a) no sink -> dropped
    no_sink = _fn(db_session, c.id, name="view", selector="0xaaaa0002", effect_targets=None)
    empty_sink = _fn(db_session, c.id, name="view2", selector="0xaaaa0003", effect_targets=[])
    # (b) confident claim present -> dropped
    claimed = _fn(
        db_session,
        c.id,
        name="mint",
        selector="0xaaaa0004",
        effect_targets=["SLOT"],
        claims=[{"claim_id": "supply_up", "tier": "fact"}],
    )
    # (c) public -> dropped
    public = _fn(
        db_session,
        c.id,
        name="poke",
        selector="0xaaaa0005",
        effect_targets=["SLOT"],
        authority_public=True,
    )
    db_session.commit()

    got = {cand.function_id for cand in select_candidates(db_session, p.id)}
    assert kept.id in got
    assert no_sink.id not in got
    assert empty_sink.id not in got
    assert claimed.id not in got
    assert public.id not in got


def test_gate_lift_enrolls_flow_and_supply_claims_scoped(db_session):
    """§5c: functions already carrying flow.*/supply.* claims are re-enrolled for
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


def test_candidate_carries_witnessed_value_holders_and_acting_floor(db_session):
    """§5b: candidates carry the protocol's witnessed value-holder set (positive
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
    holders = dict(cand.value_holders)
    assert holders.get(ADDR(0x9001).lower()) == pytest.approx(221_000_000.0)
    assert holders.get(ADDR(0x9002).lower()) == pytest.approx(55_200_000.0)
    assert ADDR(0x9003).lower() not in holders  # zero balance dropped
    # Acting floor is this deployment's own balance.
    assert cand.acting_balance_usd == pytest.approx(221_000_000.0)


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
# Ordering — transitive value-at-stake (inv. 5)
# ---------------------------------------------------------------------------


def test_transitive_value_beats_direct_balance(db_session):
    """A $33K contract whose principal controls a $3.2B vault outranks a
    directly-richer-but-terminal $1B contract (inv. 5).

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
    assert by_id[small.id].value_at_stake_usd >= 3_200_000_000.0
    assert by_id[big_direct.id].value_at_stake_usd == pytest.approx(1_000_000_000.0)


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
    assert graph.reachable_value({a.address}) == pytest.approx(111.0)
    assert graph.reachable_value({b.address}) == pytest.approx(110.0)
    assert graph.reachable_value({cc.address}) == pytest.approx(100.0)


def test_authority_graph_handles_cycles(db_session):
    """A control cycle must not loop forever; each balance counts once."""
    p = _protocol(db_session, "cycle-proto")
    a = _contract(db_session, p.id, ADDR(0x0AA1))
    b = _contract(db_session, p.id, ADDR(0x0BB2))
    _balance(db_session, a.id, 5.0)
    _balance(db_session, b.id, 7.0)
    _edge(db_session, b.id, controlled_contract=b.address, controller=a.address)
    _edge(db_session, a.id, controlled_contract=a.address, controller=b.address)
    db_session.commit()

    graph = build_authority_graph(db_session, p.id)
    assert graph.reachable_value({a.address}) == pytest.approx(12.0)


# ---------------------------------------------------------------------------
# Resource safety-valve (inv. 4)
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

    msg = caplog.text
    # Names the two dropped candidates, not the kept one.
    assert str(drop_mid.id) in msg
    assert str(drop_low.id) in msg
    assert "0xcafe0002" in msg and "0xcafe0003" in msg
    assert "dropped 2" in msg
    # The high-value survivor is not reported as dropped.
    assert "0xcafe0001" not in msg


def test_value_never_gates_without_cap(db_session):
    """With no cap, EVERY blank-gated behavior is selected regardless of value (inv. 4)."""
    p = _protocol(db_session, "nogate-proto")
    c = _contract(db_session, p.id, ADDR(0x0E00))
    # No balances anywhere -> all value_at_stake == 0, but nothing is dropped.
    fns = [_fn(db_session, c.id, name=f"f{i}", selector=f"0xfeed000{i}", effect_targets=["S"]) for i in range(4)]
    db_session.commit()

    got = {cand.function_id for cand in select_candidates(db_session, p.id)}
    assert got == {f.id for f in fns}


# ---------------------------------------------------------------------------
# Optional: Appendix A funnel against the dev DB (skips when absent)
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
    """Reproduce the §6 funnel + §5c gate-lift partition for etherfi (protocol_id=1).

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
        present = s.execute(
            text(
                "SELECT count(*) FROM effective_functions ef "
                "JOIN contracts c ON c.id = ef.contract_id WHERE c.protocol_id = 1"
            )
        ).scalar_one()
        if not present:
            pytest.skip("etherfi (protocol_id=1) rows absent from dev DB")

        # The historical blank-claim predicate count (sink + gated + no confident
        # claim) — the exact set that used to be the whole candidate list.
        expected_blank = s.execute(
            text(
                "SELECT count(*) FROM effective_functions ef "
                "JOIN contracts c ON c.id = ef.contract_id "
                "WHERE c.protocol_id = 1 AND array_length(ef.effect_targets, 1) > 0 "
                "AND ef.authority_public IS FALSE AND (ef.claims IS NULL OR "
                "(CASE WHEN jsonb_typeof(ef.claims) = 'array' "
                "THEN jsonb_array_length(ef.claims) ELSE 0 END) = 0)"
            )
        ).scalar_one()

        cands = select_candidates(s, 1)
        blank = [c for c in cands if c.restrict_families is None]
        # The blank subset is exactly the old candidate set — the gate lift is
        # purely additive over blank functions (no blank function lost).
        assert len(blank) == expected_blank
        # §5c gate lift: every value-mover already carries flow.out, so the lift
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
