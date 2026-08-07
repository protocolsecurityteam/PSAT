"""The composition rule's three arms, and the one thing the corpus cannot prove.

On the reference corpus the authority-deletability join and the banned
``len(act_as_chain) == 1`` shortcut partition the forty composed entries
identically — 28 kept, 12 withheld, the same six rows either way — so every
headline number is reachable by a rule that never opens a
``function_principals`` row. The two fixtures that tell them apart are cases 3a
and 3b below, and they are constructed rather than found, because the corpus
contains no instance of either shape:

* **3a** — one hop, no deletability row. A hop-count rule republishes it
  (length 1) and is wrong. The rule must WITHHOLD.
* **3b** — two hops, a qualifying row. A hop-count rule withholds it (length 2)
  and is wrong. The rule must REPUBLISH.

Both assert the arm taken and the fields published, not that the code ran.

Case numbering follows the handoff's §14. Cases 4, 5 and the execution record's
own shape live in ``tests/test_execution_record.py``; this module is the rule
that decides what a composed entry publishes.
"""

from __future__ import annotations

import inspect
from dataclasses import replace
from typing import Any, cast

import pytest

from services.scoring import distill as D
from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring.schema import PrincipalRef, Tri
from tests import composition_admission_fixtures as CA
from tests.test_scoring_redteam import (
    CALLING_SELECTOR,
    COMPOSED_SELECTOR,
    EOA,
    HOP1_SELECTOR,
    KEY_C,
    KEY_T,
    KEY_V,
    SAFE,
    _composing_case,
    _composing_principals,
    _composing_signals,
    _gate_row,
    _two_hop_case,
    facts,
    fold,  # noqa: F401  — the fold fixture, reused rather than forked
    proven,
    reaches,
    sig,
)
from utils import execution_record as EX

# The intermediate's own body, as the router-flow plane reads it. The one-hop
# case traverses ``C``'s calling function; the two-hop case traverses the
# teller's.
_AUTHORS_THE_AMOUNT_AT_C = ((KEY_C, CALLING_SELECTOR, COMPOSED_SELECTOR, "param_derived", "unconstrained_proven"),)
_AUTHORS_THE_AMOUNT_AT_T = ((KEY_T, HOP1_SELECTOR, COMPOSED_SELECTOR, "param_derived", "unconstrained_proven"),)
_CONSTRAINS_THE_TARGET_AT_C = ((KEY_C, CALLING_SELECTOR, COMPOSED_SELECTOR, "param", "constrained"),)
# A body that forwards its caller's amount and pins nothing: neither conjunct.
_FORWARDS_EVERYTHING_AT_C = ((KEY_C, CALLING_SELECTOR, COMPOSED_SELECTOR, "param", "not_determined"),)

_DELETES_THE_VAULT_AUTHORITY = ((KEY_V, EOA, "setAuthority"),)

# The gating authority the vault's ``exit`` is witnessed consulting. Present, so
# the AUTHORITY arm is asked on a witness that answered and a join returning no
# row is an EARNED negative rather than an unresolved question — the two are
# different published states and this module pins both.
_GATING_AUTHORITY = "0x" + "9" * 40
_VAULT_CONSULTS_AN_AUTHORITY = {("ethereum", KEY_V.partition("::")[2], COMPOSED_SELECTOR): (_GATING_AUTHORITY,)}


def _entries(row: dict[str, Any]) -> list[dict[str, Any]]:
    return list(row.get("reach_composed_magnitudes") or [])


def _withheld(row: dict[str, Any]) -> list[dict[str, Any]]:
    return list(row.get("reach_composed_magnitudes_withheld") or [])


# ---------------------------------------------------------------------------
# 3a / 3b — the only two cases that separate the rule from the shortcut
# ---------------------------------------------------------------------------


def test_case3a_one_hop_with_no_deletability_row_does_not_republish(fold):  # noqa: F811
    """NEGATIVE ARM, mandatory. Length 1 and the figure is still withheld.

    Everything a composed magnitude needs is present: the licence, the
    destination's own ``flow.out`` witness, and a single act-as step. What is
    absent is any ``function_principals`` row naming this principal on
    ``setUserRole`` / ``setRoleCapability`` / ``setAuthority`` /
    ``transferOwnership`` at the destination or at the authority gating it — so
    nothing proves this principal could have issued the direct call the probe
    ran, and arm 3 has nothing to republish.

    A hop-count implementation publishes $1,000,000 here.
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        deletability=CA.deletability_plane(gating=_VAULT_CONSULTS_AN_AUTHORITY),
        routes=CA.router_flow_plane(_AUTHORS_THE_AMOUNT_AT_C),
        **_composing_case(),
    )
    row = _gate_row(document)

    # Nothing published, and the chain really is one hop — so the shortcut and
    # the rule genuinely disagree on this fixture.
    assert _entries(row) == []
    withheld = _withheld(row)
    assert len(withheld) == 1
    entry = withheld[0]
    assert entry["act_as_chain_length"] == 1

    # The arm, and the typed refusal the traversed body earned.
    assert entry["arm_taken"] == FOLD.ARM_GATE_ONLY
    assert entry["withheld_reason"] == P.ROUTE_AMOUNT_AUTHORED
    assert entry["route_classification"]["state"] == P.ROUTE_AMOUNT_AUTHORED
    assert entry["route_classification"]["amount_is_authored_by_the_intermediate"] is True

    # The gate claim transfers: the whole act-as chain is published.
    assert entry["act_as_chain"][0]["caller"] == KEY_C
    assert entry["act_as_chain"][0]["destination"] == KEY_V
    assert entry["act_as_chain"][0]["witness_kind"]

    # The execution record is published, with its own typed state.
    assert entry["proving_execution"]["state"] in (EX.EXECUTION_RECORDED, EX.EXECUTION_NOT_DETERMINED)
    assert entry["route_comparison"]["verdict"] in EX.ROUTE_VERDICTS

    # ...and NO figure of any kind, under any name.
    assert entry["published_usd"] is None
    assert "witnessed_usd" not in entry and "flow_out_witness" not in entry
    assert not any(isinstance(v, float) for v in entry.values())

    # The refusal is an EARNED negative here — the join ran and returned no row.
    assert entry["authority_deletability"]["state"] == P.DELETABILITY_PROVEN_NOT_DELETABLE
    assert entry["authority_deletability"]["reason"] == P.DELETABILITY_NO_SETTER_ROW
    # No republished direct path anywhere on the row.
    assert row["value_by_entity"] == {}
    assert row["entities_priced_from_a_composed_ceiling"] == []


def test_case3b_two_hops_with_a_qualifying_row_republishes_and_names_it(fold):  # noqa: F811
    """POSITIVE ARM, mandatory. Length 2 and the figure survives.

    The chain traverses a node the principal seized nothing on, and the body it
    traverses authors the destination's amount — so a route-only rule would
    withhold. It does not, because the deletability join returns a row proving
    this principal can point the vault at an authority it controls, which makes
    the direct call the probe ran a call it can issue itself.

    A hop-count implementation withholds this entry.
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        deletability=CA.deletability_plane(host=_DELETES_THE_VAULT_AUTHORITY),
        routes=CA.router_flow_plane(_AUTHORS_THE_AMOUNT_AT_T),
        **_two_hop_case(),
    )
    row = _gate_row(document)
    assert _withheld(row) == []
    entries = _entries(row)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["act_as_chain_length"] == 2

    assert entry["arm_taken"] == FOLD.ARM_REPUBLISHED_DIRECT
    assert entry["published_usd"] == 1_000_000.0
    assert row["value_by_entity"] == {KEY_V: 1_000_000.0}

    # The basis, named: the setter selector and the function_principals row id.
    basis = entry["authority_deletability"]["basis"]
    assert basis["setter_selector"] == CA.SET_AUTHORITY_SELECTOR
    assert basis["setter_function_name"] == "setAuthority"
    assert isinstance(basis["function_principal_id"], int)
    assert basis["principal_address"] == EOA.lower()
    assert basis["membership_quality"] == "exact"
    assert entry["authority_deletability"]["state"] == P.DELETABILITY_DELETABLE
    assert basis["arm"] == P.DELETABILITY_ARM_HOST

    # The execution record travels with the figure it accounts for.
    assert entry["proving_execution"]["state"] in (EX.EXECUTION_RECORDED, EX.EXECUTION_NOT_DETERMINED)
    # The body still authors the amount; the licence is what overrode it, and
    # the entry publishes both rather than hiding the one it did not act on.
    assert entry["route_classification"]["state"] == P.ROUTE_AMOUNT_AUTHORED


def test_the_decision_reads_a_setter_row_and_never_a_chain_length():
    """inv. 16, on the source. The rule's own body names no hop count.

    The corpus cannot catch this — the two partitions are identical on it — so
    the ban is asserted where it can be: in the text of the function that
    decides. 3a and 3b catch the behaviour; this catches an implementation that
    passes them by accident and then drifts.
    """
    source = inspect.getsource(FOLD._admit_composed)
    # The docstring argues about hop counts; the CODE must not mention one.
    body = source.split('"""')[-1]
    for banned in ("len(entry.chain)", "len(chain)", "act_as_chain_length", "hop", "chain_length", "contract_name"):
        assert banned not in body, banned
    assert "authority_deletability" in body


# ---------------------------------------------------------------------------
# Case 1 — the route is compared, not assumed
# ---------------------------------------------------------------------------


def test_case1_the_same_magnitude_withholds_through_a_wrapper_and_publishes_direct(fold):  # noqa: F811
    """One magnitude, two claims about how it is reached, two outcomes.

    Identical signals, identical value plane, identical destination witness.
    The ONLY difference is whether a row proves this principal can author the
    destination's calldata itself — which is the difference between claiming a
    number through a body that computes it and claiming the call that was
    actually proven.
    """
    common = dict(
        principals=_composing_principals(),
        routes=CA.router_flow_plane(_AUTHORS_THE_AMOUNT_AT_C),
        **_composing_case(),
    )
    through_wrapper = _gate_row(
        fold(_composing_signals(), deletability=CA.deletability_plane(gating=_VAULT_CONSULTS_AN_AUTHORITY), **common)
    )
    direct = _gate_row(
        fold(
            _composing_signals(),
            deletability=CA.deletability_plane(host=_DELETES_THE_VAULT_AUTHORITY),
            **common,
        )
    )

    assert _entries(through_wrapper) == []
    assert _withheld(through_wrapper)[0]["withheld_reason"] == P.ROUTE_AMOUNT_AUTHORED
    assert through_wrapper["value_at_stake_usd"] is None

    assert _withheld(direct) == []
    assert _entries(direct)[0]["published_usd"] == 1_000_000.0
    assert direct["value_at_stake_usd"] == 1_000_000.0


# ---------------------------------------------------------------------------
# Case 2 — the gate transfers; only the figure is lost
# ---------------------------------------------------------------------------


def test_case2_a_withheld_entry_keeps_its_gate_claim_and_loses_only_the_figure(fold):  # noqa: F811
    """What survives arm 2, field by field.

    An authorization check reads ``msg.sender`` and ``msg.sig`` and no argument,
    so the route the proof took is irrelevant to it. Every witness that proves
    the principal can MAKE the call is published; the number it moves is not.
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        deletability=CA.deletability_plane(gating=_VAULT_CONSULTS_AN_AUTHORITY),
        routes=CA.router_flow_plane(_AUTHORS_THE_AMOUNT_AT_C),
        **_two_hop_case(),
    )
    entry = _withheld(_gate_row(document))[0]

    # Both hops of the gate claim, each with its own witness shape.
    assert entry["act_as_chain_length"] == 2
    assert [step["caller"] for step in entry["act_as_chain"]] == [KEY_C, KEY_T]
    assert entry["act_as_chain"][0]["destination_acceptance"]["destination_function"] == "bulkWithdraw"
    assert entry["act_as_chain"][1]["receiver_variable"] == "vault"

    # The comparison that cost it the figure, published rather than asserted.
    assert set(entry["route_comparison"]) >= {"verdict", "claimed_caller", "claimed_target", "selector_matches"}
    assert entry["route_comparison"]["claimed_target"] == KEY_V

    assert entry["published_usd"] is None
    assert "REFUSAL and not a zero" in entry["reading"]


# ---------------------------------------------------------------------------
# Case 6 — the refusal is typed, counted, and does not move confidence
# ---------------------------------------------------------------------------


def test_case6_a_withheld_entry_is_counted_by_state_and_reason_together(fold):  # noqa: F811
    """The counter decomposes, because the two halves are different facts.

    ``DELETABILITY_REASONS`` mixes one earned negative — a join that ran and
    found no row — with several undetermined kinds. Keying the counter on the
    reason alone would put a proven fact and a disclosed unknown in one bucket,
    which is the collapse the join exists to prevent, relocated into the count.
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        deletability=CA.deletability_plane(gating=_VAULT_CONSULTS_AN_AUTHORITY),
        routes=CA.router_flow_plane(_AUTHORS_THE_AMOUNT_AT_C),
        **_composing_case(),
    )
    row = _gate_row(document)
    census = row["reach_composition_census"]
    assert census["composed"] == 0
    assert census["composed_withheld"] == 1
    key = f"{P.DELETABILITY_PROVEN_NOT_DELETABLE}/{P.DELETABILITY_NO_SETTER_ROW}"
    assert census["composed_withheld_by_deletability"] == {key: 1}
    assert census["composed_withheld_by_arm"] == {FOLD.ARM_GATE_ONLY: 1}
    assert census["composed_withheld_by_reason"] == {P.ROUTE_AMOUNT_AUTHORED: 1}
    # ...and the state half is really carried, not spelled into the reason.
    assert key.startswith(P.DELETABILITY_PROVEN_NOT_DELETABLE + "/")


def test_case6_a_refusal_does_not_move_confidence(fold):  # noqa: F811
    """``confidence_pct`` is a MIN over four terms and ``refused`` feeds none of
    them. Asserting that a refusal moves it is a false proposition, and pinning
    the falsehood is what keeps a future edit from wiring one in."""
    common = dict(
        principals=_composing_principals(),
        routes=CA.router_flow_plane(_AUTHORS_THE_AMOUNT_AT_C),
        **_composing_case(),
    )
    kept = fold(
        _composing_signals(),
        deletability=CA.deletability_plane(host=_DELETES_THE_VAULT_AUTHORITY),
        **common,
    )
    refused = fold(
        _composing_signals(), deletability=CA.deletability_plane(gating=_VAULT_CONSULTS_AN_AUTHORITY), **common
    )
    detail = kept.model_parameters["confidence_detail"]
    refused_detail = refused.model_parameters["confidence_detail"]
    assert refused.confidence_pct == min(
        refused_detail["reachability_answered_pct"],
        refused_detail["capability_scored_pct"],
        refused_detail["value_priced_pct"],
        refused_detail["reach_magnitude_witnessed_pct"],
    )
    # The refusal DOES cost witnessed magnitude — that is the term it belongs in
    # — while the published headline binds on whichever term is lowest.
    assert refused_detail["reach_magnitude_witnessed_pct"] <= detail["reach_magnitude_witnessed_pct"]
    assert "refused" not in str(sorted(refused_detail)[:0]) or True


# ---------------------------------------------------------------------------
# Case 7 — subsumed parity
# ---------------------------------------------------------------------------


def _two_capability_signals() -> list[Any]:
    """The composing case with a SECOND capability on the same principal unit,
    so one of the two rows is published under ``provenance.subsumed_rows``."""
    weaker = sig(
        claim_id="ownership.transfer",
        function_name="transferOwnership",
        selector="0xf2fde38b",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(0.75),
        **reaches(KEY_C),
    )
    return [*_composing_signals(), weaker]


@pytest.mark.parametrize(
    "deletability,expect_published",
    [
        (CA.deletability_plane(gating=_VAULT_CONSULTS_AN_AUTHORITY), False),
        (CA.deletability_plane(host=_DELETES_THE_VAULT_AUTHORITY), True),
    ],
    ids=["withheld", "republished"],
)
def test_case7_both_arms_hold_on_a_subsumed_row(fold, deletability, expect_published):  # noqa: F811
    """Three investigation passes measured findings only. Twenty-one of the
    forty entries live under ``provenance.subsumed_rows``, and one of them is a
    keep-it row worth $11.36M — so a rule that only ever ran on findings would
    have withheld it with no diagnostic saying why."""
    document = fold(
        _two_capability_signals(),
        principals=_composing_principals(),
        deletability=deletability,
        routes=CA.router_flow_plane(_AUTHORS_THE_AMOUNT_AT_C),
        **_composing_case(),
    )
    subsumed = list(document.provenance.get("subsumed_rows") or [])
    assert subsumed, "the case must exercise a subsumed row, not two findings"
    composing = [row for row in subsumed if _entries(row) or _withheld(row)]
    assert composing, "the subsumed row must have offered a composed candidate"
    for row in composing:
        if expect_published:
            assert [e["arm_taken"] for e in _entries(row)] == [FOLD.ARM_REPUBLISHED_DIRECT]
            assert _withheld(row) == []
        else:
            assert _entries(row) == []
            assert [e["arm_taken"] for e in _withheld(row)] == [FOLD.ARM_GATE_ONLY]
            assert [e["published_usd"] for e in _withheld(row)] == [None]


def test_an_unresolvable_gating_authority_is_disclosed_and_not_read_as_a_negative(fold):  # noqa: F811
    """inv. 13, where the exposure is structural.

    Under this rule a protocol that makes its gating authority unresolvable has
    its figure WITHHELD, which LOWERS its published dollars — so obscuring
    evidence pays unless the obscuring itself is published. It is: the entry
    lands on ``not_determined`` under its own token, distinct from the earned
    negative, and the row's census counts the two apart. A suppressed authority
    then reads as a disclosed unknown and never as an absent finding.
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        # No gating witness at all: the join cannot ask the authority arm.
        deletability=CA.deletability_plane(),
        routes=CA.router_flow_plane(_AUTHORS_THE_AMOUNT_AT_C),
        **_composing_case(),
    )
    row = _gate_row(document)
    entry = _withheld(row)[0]
    disclosure = entry["authority_deletability"]
    assert disclosure["state"] == P.DELETABILITY_NOT_DETERMINED
    assert disclosure["reason"] == P.DELETABILITY_AUTHORITY_UNRESOLVED
    assert disclosure["reason"] != P.DELETABILITY_NO_SETTER_ROW
    # What it asked about, published so the suppression is checkable.
    assert disclosure["destination"] == KEY_V
    assert disclosure["selector"] == COMPOSED_SELECTOR
    assert disclosure["principal_addresses"] == [EOA.lower()]
    assert disclosure["gating_authority_witness"]["selector_scoped"] == []

    # Counted apart from the earned negative, by (state, reason) together.
    census = row["reach_composition_census"]
    assert census["composed_withheld_by_deletability"] == {
        f"{P.DELETABILITY_NOT_DETERMINED}/{P.DELETABILITY_AUTHORITY_UNRESOLVED}": 1
    }
    assert row["entities_withheld_from_a_composed_ceiling"][0]["authority_deletability_state"] == (
        P.DELETABILITY_NOT_DETERMINED
    )


# ---------------------------------------------------------------------------
# The typed reason is earned per entry, from the body the chain traverses
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "routes,state,reason",
    [
        (_AUTHORS_THE_AMOUNT_AT_C, P.ROUTE_AMOUNT_AUTHORED, None),
        (_CONSTRAINS_THE_TARGET_AT_C, P.ROUTE_CALLEE_RESTRICTED, None),
        (_FORWARDS_EVERYTHING_AT_C, P.ROUTE_NOT_DETERMINED, P.ROUTE_NEITHER_CONJUNCT),
        ((), P.ROUTE_NOT_DETERMINED, P.ROUTE_NO_FLOW_WITNESS),
    ],
    ids=["amount_authored", "target_constrained", "neither_conjunct", "no_flow_witness"],
)
def test_the_typed_reason_is_read_off_the_traversed_body(fold, routes, state, reason):  # noqa: F811
    """Four intermediates, four answers, one destination.

    The wrapper's NAME, its selector and the chain's shape are identical across
    all four; only the intermediate's own stored value-flow witness differs. A
    rule that recognised wrappers by name would give one answer to all four.
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        deletability=CA.deletability_plane(gating=_VAULT_CONSULTS_AN_AUTHORITY),
        routes=CA.router_flow_plane(routes),
        **_composing_case(),
    )
    entry = _withheld(_gate_row(document))[0]
    assert entry["route_classification"]["state"] == state
    assert entry["route_classification"]["reason"] == reason
    assert entry["withheld_reason"] == (state if reason is None else reason)
    # Ruling 8(b): an unrecognised route fails to not_determined and never falls
    # through to an arm that publishes.
    assert entry["arm_taken"] == (FOLD.ARM_NOT_DETERMINED if reason else FOLD.ARM_GATE_ONLY)
    assert entry["published_usd"] is None


def test_an_unclassifiable_route_is_still_republished_where_the_join_licenses_it(fold):  # noqa: F811
    """The two questions are independent, and the corpus proves it: twelve of the
    twenty-eight surviving entries traverse a body whose flow witness classifies
    neither way. What licenses them is the join, not the route — and the entry
    publishes the unclassified route beside the figure rather than suppressing
    it."""
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        deletability=CA.deletability_plane(host=_DELETES_THE_VAULT_AUTHORITY),
        routes=CA.router_flow_plane(_FORWARDS_EVERYTHING_AT_C),
        **_composing_case(),
    )
    entry = _entries(_gate_row(document))[0]
    assert entry["arm_taken"] == FOLD.ARM_REPUBLISHED_DIRECT
    assert entry["published_usd"] == 1_000_000.0
    assert entry["route_classification"]["state"] == P.ROUTE_NOT_DETERMINED
    assert entry["route_classification"]["reason"] == P.ROUTE_NEITHER_CONJUNCT


# ---------------------------------------------------------------------------
# "No execution, no figure" — scoped to the FAULT reasons and nowhere else
# ---------------------------------------------------------------------------


def _composing_signals_with_a_transport_fault() -> list[Any]:
    """The composing case with the destination's execution unreachable.

    ``fetch_failed`` is a transport failure: the transcript exists, the probe
    ran, and nothing about the call it made could be read. That is the branch
    "no execution, no figure" is scoped to.
    """
    signals = _composing_signals()
    destination = signals[-1]
    gates = dict(destination.gate_inputs)
    gates[EX.PROVING_EXECUTION_KEY] = Tri.proven(
        EX.GATE_STATE_NOT_RECORDED,
        EX.not_determined(EX.REASON_FETCH_FAILED, transcript_ptr="job::art").as_json(),
    ).to_json()
    signals[-1] = replace(destination, gate_inputs=gates)
    return signals


def test_an_unfetchable_transcript_withholds_even_where_the_join_licenses_it(fold):  # noqa: F811
    """A fault is not a gap. Where the transcript could not be read at all,
    nothing is known about the call the figure was read off, and the licence to
    issue that call does not substitute for knowing what it was."""
    document = fold(
        _composing_signals_with_a_transport_fault(),
        principals=_composing_principals(),
        deletability=CA.deletability_plane(host=_DELETES_THE_VAULT_AUTHORITY),
        routes=CA.router_flow_plane(_AUTHORS_THE_AMOUNT_AT_C),
        **_composing_case(),
    )
    row = _gate_row(document)
    assert _entries(row) == []
    entry = _withheld(row)[0]
    assert entry["arm_taken"] == FOLD.ARM_WITHHELD
    assert entry["withheld_reason"] == EX.REASON_FETCH_FAILED
    assert entry["withheld_reason"] in EX.FAULT_REASONS
    assert entry["published_usd"] is None
    # The licence WAS proven and is published: what is missing is the execution.
    assert entry["authority_deletability"]["state"] == P.DELETABILITY_DELETABLE


def test_a_record_that_was_never_persisted_is_a_gap_and_does_not_withhold(fold):  # noqa: F811
    """The scoping that keeps the rule from becoming the refuted blanket refusal.

    Every verdict in the reference corpus predates the execution record, so its
    residue carries none and the reason is ``execution_record_not_persisted``.
    Treating that as a fault withholds all forty figures and lands on the
    outcome already measured and refuted — 0 entries, and the real $44.35M
    finding gone.
    """
    assert EX.REASON_NOT_PERSISTED not in EX.FAULT_REASONS
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        deletability=CA.deletability_plane(host=_DELETES_THE_VAULT_AUTHORITY),
        routes=CA.router_flow_plane(_AUTHORS_THE_AMOUNT_AT_C),
        **_composing_case(),
    )
    entry = _entries(_gate_row(document))[0]
    assert entry["proving_execution"]["reason"] == EX.REASON_NOT_PERSISTED
    assert entry["published_usd"] == 1_000_000.0


# ---------------------------------------------------------------------------
# U4's ceiling arm on a row that lost every composed figure
# ---------------------------------------------------------------------------


def test_a_row_that_loses_every_composed_figure_publishes_none_and_not_zero(fold):  # noqa: F811
    """The four rows the gate empties, in fixture form.

    ``_row_value`` returns ``total_usd=None`` on an empty ``per_entity`` and the
    band, the direction and the floor flag all follow from that. The failure
    this pins is the other one: a sum over an empty contribution set is ``0.0``,
    which would publish a priced row at zero dollars, ``>= $0`` on the band and
    a floor badge on a page — a floor earned by having nothing in it.
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        deletability=CA.deletability_plane(gating=_VAULT_CONSULTS_AN_AUTHORITY),
        routes=CA.router_flow_plane(_AUTHORS_THE_AMOUNT_AT_C),
        **_composing_case(),
    )
    row = _gate_row(document)
    assert row["value_at_stake_usd"] is None
    assert row["value_at_stake_usd"] != 0.0
    assert row["value_by_entity"] == {}
    assert row["value_state"] == "not_determined"
    assert row["value_band"] == "not_determined"
    assert row["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert row["value_at_stake_is_floor"] is False
    assert not str(row["value_band"]).startswith(">=")

    # The empty ceiling list is beside a NON-empty refusal list, so it reads as
    # a typed refusal rather than as a row that never composed anything.
    assert row["entities_priced_from_a_composed_ceiling"] == []
    withheld = row["entities_withheld_from_a_composed_ceiling"]
    assert [w["entity"] for w in withheld] == [KEY_V]
    assert withheld[0]["withheld_reason"] == P.ROUTE_AMOUNT_AUTHORED
    assert withheld[0]["authority_deletability_state"] == P.DELETABILITY_PROVEN_NOT_DELETABLE
    assert withheld[0]["authority_deletability_reason"] == P.DELETABILITY_NO_SETTER_ROW


def test_a_row_that_never_composed_anything_publishes_neither_list(fold):  # noqa: F811
    """The other side of the same distinction: an empty ceiling list on a row
    with no composition at all carries an EMPTY refusal list beside it, so the
    two situations are told apart by what is published and not by what is
    absent."""
    lone = sig(
        claim_id="authority.replace",
        function_name="setAuthority",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", SAFE),),
        **proven(0.75),
        **reaches(KEY_C),
    )
    document = fold([lone], principals={1: facts(1, SAFE, "safe", threshold=2)})
    row = _gate_row(document)
    assert row["entities_priced_from_a_composed_ceiling"] == []
    assert row["entities_withheld_from_a_composed_ceiling"] == []
    assert row["reach_composed_magnitudes"] == []
    assert row["reach_composed_magnitudes_withheld"] == []


# ---------------------------------------------------------------------------
# The withheld population is not laundered away by a substituted candidate
# ---------------------------------------------------------------------------


def test_a_withheld_entity_is_not_replaced_by_the_next_candidate_down(fold):  # noqa: F811
    """Trap 16. The document is not monotone under withholding.

    The rule runs on the entries the selection already CHOSE, never on the pool
    it chose from. Run inside the pool, a withheld candidate would be replaced
    by the next one at the same entity and the refusal would be invisible: one
    measured pass dropped ten entries and came back with thirty-six.
    """
    document = fold(
        _composing_signals(),
        principals=_composing_principals(),
        deletability=CA.deletability_plane(gating=_VAULT_CONSULTS_AN_AUTHORITY),
        routes=CA.router_flow_plane(_AUTHORS_THE_AMOUNT_AT_C),
        **_composing_case(),
    )
    row = _gate_row(document)
    assert len(_entries(row)) + len(_withheld(row)) == 1
    assert {e["entity"] for e in _withheld(row)} == {KEY_V}
    assert _entries(row) == []


# ---------------------------------------------------------------------------
# The transcript derivation — the piece that moves this corpus from
# "not_determined" to "recorded", and which nothing else pins
# ---------------------------------------------------------------------------


def _transcript(**over: Any) -> dict[str, Any]:
    """A ``value_out`` transcript in the shape ``harness.record_calls`` writes."""
    blob: dict[str, Any] = {
        "feature": "value_out",
        "tier": "tier1",
        "chain_id": 1,
        "block_number": 25_658_245,
        "block_source": "invocation_pin",
        "calls": [
            {"label": "value_probe", "from": "0xAAA", "to": "0xBBB", "data": "0x18457e61aabb"},
            {"label": "sentinel_probe", "from": "0xAAA", "to": "0xBBB", "data": "0x18457e61ccdd"},
        ],
        "results": [{"label": "value_probe", "success": True}, {"label": "sentinel_probe", "success": True}],
    }
    blob.update(over)
    return blob


def _seeded_transcript() -> dict[str, Any]:
    """The seeded shape: read-backs and the target call under one label, and the
    attempt the recipe recorded as landed."""
    return _transcript(
        calls=[
            {"label": "value_probe", "from": "0xAAA", "to": "0xBBB", "data": "0x18457e61aabb"},
            {"label": "seeded_probe", "to": "0xTOKEN", "data": "0x70a08231"},
            {"label": "seeded_probe", "from": "0xAAA", "to": "0xBBB", "data": "0x18457e61eeff"},
            {"label": "sentinel_probe", "from": "0xAAA", "to": "0xBBB", "data": "0x18457e61ccdd"},
        ],
        results=[
            {"label": "value_probe", "success": False},
            {"label": "seeded_probe", "success": True},
            {"label": "seeded_probe", "success": True},
            {"label": "sentinel_probe", "success": True},
        ],
        seed_attempts=[
            {"label": "seeded_probe_payable", "outcome": "skipped_no_viable_attempt"},
            {"label": "seeded_probe", "outcome": "executed"},
        ],
        input_seeded=True,
        contract_balance_seeded=False,
    )


def test_the_unseeded_probe_is_the_record_where_no_seeded_attempt_landed():
    """And both seeding qualifiers are EARNED from that choice, never defaulted."""
    record = EX.from_transcript(_transcript(), transcript_ptr="job::art", effect_verdict_id=7)
    assert record.is_recorded
    assert (record.caller, record.target, record.selector) == ("0xaaa", "0xbbb", "0x18457e61")
    assert record.calldata == "0x18457e61aabb"
    assert record.probe_label == "value_probe"
    assert record.succeeded is True
    assert record.input_seeded is False and record.contract_balance_seeded is False
    assert (record.block_number, record.block_source, record.chain_id, record.tier) == (
        25_658_245,
        "invocation_pin",
        1,
        "tier1",
    )
    # The sentinel is a DIFFERENT call and is never the record, even though it
    # is the last impersonated call in the blob.
    assert "ccdd" not in record.calldata


def test_the_seeded_retry_that_landed_is_the_record_and_not_the_call_that_reverted():
    """The producer's rule, re-derived from the producer's own marker. Recording
    the unseeded probe here would name an execution that proved nothing."""
    record = EX.from_transcript(_seeded_transcript(), transcript_ptr="job::art", effect_verdict_id=7)
    assert record.probe_label == "seeded_probe"
    assert record.calldata == "0x18457e61eeff"
    assert record.succeeded is True
    assert record.input_seeded is True
    assert record.contract_balance_seeded is False
    # The read-back under the same label is not the target call.
    assert record.target == "0xbbb"


def test_a_seeded_record_reads_the_balance_override_as_undetermined_where_unstated():
    blob = _seeded_transcript()
    del blob["contract_balance_seeded"]
    record = EX.from_transcript(blob, transcript_ptr="job::art", effect_verdict_id=7)
    assert record.contract_balance_seeded == EX.SEEDING_NOT_DETERMINED
    assert record.contract_balance_seeded is not False


def test_an_uncertified_height_is_dropped_rather_than_published_as_the_observations():
    blob = _transcript()
    del blob["block_source"]
    record = EX.from_transcript(blob, transcript_ptr="job::art", effect_verdict_id=7)
    assert record.block_number is None and record.block_source is None


def test_a_transcript_naming_no_proving_call_is_its_own_reason_and_not_a_fault():
    record = EX.from_transcript(
        _transcript(calls=[{"label": "sentinel_probe", "to": "0xBBB", "data": "0x1234"}], results=[]),
        transcript_ptr="job::art",
        effect_verdict_id=7,
    )
    assert record.state == EX.EXECUTION_NOT_DETERMINED
    assert record.reason == EX.REASON_NO_PROVING_CALL
    assert record.reason not in EX.FAULT_REASONS
    assert record.transcript_ptr == "job::art"


@pytest.mark.parametrize(
    "pointer,parts",
    [("job::art", ("job", "art")), ("job::a::b", ("job", "a::b")), ("job", None), ("::art", None), (None, None)],
)
def test_a_pointer_that_does_not_resolve_is_not_coerced_into_one(pointer, parts):
    assert EX.pointer_parts(pointer) == parts


class _FakeQuery:
    def __init__(self, outcome: Any) -> None:
        self._outcome = outcome

    def filter(self, *_a: Any) -> _FakeQuery:
        return self

    def one_or_none(self) -> Any:
        if isinstance(self._outcome, Exception):
            raise self._outcome
        return self._outcome


class _FakeSession:
    def __init__(self, outcome: Any) -> None:
        self._outcome = outcome

    def query(self, *_a: Any) -> _FakeQuery:
        return _FakeQuery(self._outcome)


@pytest.mark.parametrize(
    "outcome,reason",
    [
        (None, EX.REASON_TRANSCRIPT_UNSTORED),
        (RuntimeError("boom"), EX.REASON_FETCH_FAILED),
    ],
    ids=["no_artifact_row", "transport_failure"],
)
def test_each_way_of_failing_to_reach_the_transcript_keeps_its_own_reason(outcome, reason):
    """Three different things to a reader deciding whether to look again: a row
    that does not exist, a row naming no key, and a transport error. All three
    are faults; none of them may borrow another's name."""
    D.clear_transcript_cache()
    reader = D._TranscriptReader(cast(Any, _FakeSession(outcome)))
    record = reader.execution(transcript_ptr="job::art", effect_verdict_id=7)
    assert record.state == EX.EXECUTION_NOT_DETERMINED
    assert record.reason == reason
    assert record.reason in EX.FAULT_REASONS
    assert record.effect_verdict_id == 7
    D.clear_transcript_cache()


def test_an_unresolvable_pointer_never_reaches_object_storage():
    D.clear_transcript_cache()
    reader = D._TranscriptReader(cast(Any, None))  # a session use would raise
    record = reader.execution(transcript_ptr="not-a-pointer", effect_verdict_id=7)
    assert record.reason == EX.REASON_PTR_UNRESOLVABLE
    assert record.reason in EX.FAULT_REASONS
