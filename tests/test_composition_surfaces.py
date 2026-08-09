"""The two composed-entry surfaces §8 ruled on, and the disclosures beside them.

Each case is a *derivation* pinned by two carriers whose data differs, never by
one carrier against a literal: the mutation that de-interpolates a derived
string into a constant has to fail here, and a test that asserts only that the
field exists does not count.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys
from dataclasses import replace
from typing import Any

import pytest

from services.scoring import constants as K
from services.scoring import fold as FOLD
from services.scoring import planes as P
from tests import composition_admission_fixtures as CA
from tests.test_scoring_redteam import (
    CALLING_SELECTOR,
    COMPOSED_SELECTOR,
    KEY_C,
    KEY_V,
    _composing_principals,
    _gate_row,
    _tied_case,
    _tied_signals,
    fold,  # noqa: F401  — the fold fixture
)
from utils import execution_record as EX

_AUTHORS_THE_AMOUNT_AT_C = ((KEY_C, CALLING_SELECTOR, COMPOSED_SELECTOR, "param_derived", "unconstrained_proven"),)
_CONSTRAINS_THE_TARGET_AT_C = ((KEY_C, CALLING_SELECTOR, COMPOSED_SELECTOR, "param", "constrained"),)
_GATING_AUTHORITY = "0x" + "9" * 40
_VAULT_CONSULTS_AN_AUTHORITY = {("ethereum", KEY_V.partition("::")[2], COMPOSED_SELECTOR): (_GATING_AUTHORITY,)}

# The token §7.2 named and CAP-A §R2 retired. Kept as a literal here on purpose:
# it is the one string this module asserts the ABSENCE of, and a symbol would
# make the assertion vacuous the day the symbol is deleted.
RETIRED_CALLEE_TOKEN = "destination_callee_is_restricted_by_the_intermediate"

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _withheld(row: dict[str, Any]) -> list[dict[str, Any]]:
    return list(row.get("reach_composed_magnitudes_withheld") or [])


def _gate_only_document(fold, routes):  # noqa: F811
    """One withheld entry on the gate-only arm: the join returns no setter row so
    arm 3 cannot republish and the route alone decides the arm."""
    return CA.composed_document(
        fold, deletability=CA.deletability_plane(gating=_VAULT_CONSULTS_AN_AUTHORITY), routes=routes
    )


# CAP-A §R2 — the token names the field it is earned from


def test_the_second_typed_reason_names_the_constrained_target_and_not_a_callee(fold):  # noqa: F811
    """CAP-A §R2. The token is read off ``target_constraint``, which pins the
    destination call's counterparty ARGUMENT; no stored witness restricts the
    callee, so "the callee is restricted" asserted a property the evidence does
    not earn. The state and the boolean now share one name."""
    entry = _withheld(_gate_row(_gate_only_document(fold, _CONSTRAINS_THE_TARGET_AT_C)))[0]
    classification = entry["route_classification"]

    assert classification["state"] == P.ROUTE_TARGET_CONSTRAINED
    assert entry["withheld_reason"] == P.ROUTE_TARGET_CONSTRAINED
    # The token IS the name of the field it is read from, in the same block.
    assert classification[classification["state"]] is True
    assert "callee" not in P.ROUTE_TARGET_CONSTRAINED


@pytest.mark.parametrize(
    "routes",
    [_AUTHORS_THE_AMOUNT_AT_C, _CONSTRAINS_THE_TARGET_AT_C, ()],
    ids=["amount_authored", "target_constrained", "no_flow_witness"],
)
def test_no_published_route_state_claims_a_restricted_callee(fold, routes):  # noqa: F811
    """The retired token has no producer: the classifier cannot emit it under any
    of its outcomes, and it is not in the registry a state is checked against."""
    assert RETIRED_CALLEE_TOKEN not in P.ROUTE_CLASSIFICATIONS
    row = _gate_row(_gate_only_document(fold, routes))
    for entry in _withheld(row):
        assert entry["route_classification"]["state"] != RETIRED_CALLEE_TOKEN
        assert entry["withheld_reason"] != RETIRED_CALLEE_TOKEN
    assert RETIRED_CALLEE_TOKEN not in row["reach_composition_census"]["reading"]


# B1-R R2-a — the gate-only arm fires on two tokens and its cause names which


def test_the_census_cause_names_the_route_token_and_not_only_the_arm(fold):  # noqa: F811
    """B1-R R2-a. ``ARM_GATE_ONLY`` is taken on either of two route tokens and
    the census gave both the AUTHORING cause. The two documents differ only in
    the intermediate's stored flow witness, so a cause keyed on the arm alone
    publishes one sentence for both and fails here."""
    authored = _gate_row(_gate_only_document(fold, _AUTHORS_THE_AMOUNT_AT_C))
    constrained = _gate_row(_gate_only_document(fold, _CONSTRAINS_THE_TARGET_AT_C))

    # Same arm, same count — only the token differs.
    for row, token in ((authored, P.ROUTE_AMOUNT_AUTHORED), (constrained, P.ROUTE_TARGET_CONSTRAINED)):
        assert _withheld(row)[0]["arm_taken"] == FOLD.ARM_GATE_ONLY
        assert _withheld(row)[0]["withheld_reason"] == token
        assert row["reach_composition_census"]["composed_withheld_by_arm"] == {FOLD.ARM_GATE_ONLY: 1}

    authored_reading = authored["reach_composition_census"]["reading"]
    constrained_reading = constrained["reach_composition_census"]["reading"]
    assert authored_reading != constrained_reading
    assert "AUTHORING" in authored_reading and "AUTHORING" not in constrained_reading
    assert "PINNING" in constrained_reading and "PINNING" not in authored_reading
    # ...and the census points at the field that separates the two tokens rather
    # than at composed_withheld_by_arm, which does not.
    assert "composed_withheld_by_reason" in constrained_reading
    assert constrained["reach_composition_census"]["composed_withheld_by_reason"] == {P.ROUTE_TARGET_CONSTRAINED: 1}


def test_a_cause_is_registered_per_arm_and_route_token_with_no_fall_through():
    """No default sentence: an unregistered pair raises rather than reaching the
    document through a cause nobody wrote for it. And the count the closing
    sentence prints is the registry's own size, so a frozen "three" cannot
    survive the day a fourth cause is registered."""
    assert (FOLD.ARM_GATE_ONLY, P.ROUTE_AMOUNT_AUTHORED) in FOLD._WITHHELD_CAUSE_ORDER
    assert (FOLD.ARM_GATE_ONLY, P.ROUTE_TARGET_CONSTRAINED) in FOLD._WITHHELD_CAUSE_ORDER
    assert (FOLD.ARM_GATE_ONLY, None) not in FOLD._WITHHELD_CAUSE_ORDER
    with pytest.raises(KeyError):
        FOLD._withheld_cause((FOLD.ARM_GATE_ONLY, P.ROUTE_NOT_DETERMINED))
    with pytest.raises(KeyError):
        FOLD._withheld_cause((FOLD.ARM_REPUBLISHED_DIRECT, None))
    assert f"The {len(FOLD._WITHHELD_CAUSE_ORDER)} registered causes" in FOLD._withheld_cause_clause(
        (_a_withheld_record(),)
    )
    # The empty case counts nothing and claims nothing about the registry.
    assert "registered causes" not in FOLD._withheld_cause_clause(())


def _a_withheld_record() -> FOLD._WithheldComposition:
    return FOLD._WithheldComposition(
        entity=KEY_V,
        selector=COMPOSED_SELECTOR,
        function="exit",
        chain=(),
        execution=EX.ProvingExecution(state=EX.EXECUTION_NOT_DETERMINED, reason=EX.REASON_NOT_PERSISTED),
        arm=FOLD.ARM_NOT_DETERMINED,
        reason=P.ROUTE_NO_FLOW_WITNESS,
        route=P.RouteClassification(P.ROUTE_NOT_DETERMINED, P.ROUTE_NO_FLOW_WITNESS, (), None, None),
        deletability=P.authority_deletability(P.DeletabilityPlane({}, {}, {}), [], KEY_V, COMPOSED_SELECTOR),
    )


# Ruling 6.2 M4 / §11.2 (k) — chosen_by names what decided THIS tie


def _tied_pair(**over: Any) -> FOLD._ComposedMagnitude:
    """A winner carrying one tied candidate that differs only where ``over`` says."""
    base = FOLD._ComposedMagnitude(
        entity=KEY_V,
        selector="0x11111111",
        function="exit",
        witness_state="proven_floor",
        witnessed_usd=1_000_000.0,
        usd=1_000_000.0,
        sheet_usd=None,
        chain=(),
        predicates=P.DestinationPredicates(P.PREDICATES_FUNCTION_NOT_LOCATED, None, None, None, None, 0),
        execution=EX.ProvingExecution(state=EX.EXECUTION_NOT_DETERMINED, reason=EX.REASON_NOT_PERSISTED),
    )
    return replace(base, tied_with=(replace(base, **over),))


def _tie(entry: FOLD._ComposedMagnitude) -> dict[str, Any]:
    """The published tie block. ``None`` there is the proven "one candidate",
    which none of these fixtures builds, so it is an error rather than a skip."""
    block = entry._tie_json()
    assert block is not None
    return block


def test_chosen_by_names_the_component_that_actually_decided_the_tie():
    """Ruling 6.2 M4. Reciting the whole ladder reads as though every component
    applied; three ties decided at three different components publish three
    different strings, which a recital cannot do."""
    by_state = _tied_pair(witness_state="proven_upper_bound")
    by_selector = _tied_pair(selector="0x22222222")
    by_function = _tied_pair(function="manage")

    assert len({_tie(entry)["chosen_by"] for entry in (by_state, by_selector, by_function)}) == 3
    assert "the weakest witness state (component 2 of 6)" in _tie(by_state)["chosen_by"]
    assert "the lowest selector (component 3 of 6)" in _tie(by_selector)["chosen_by"]
    assert "the lowest destination function (component 4 of 6)" in _tie(by_function)["chosen_by"]
    # ...and each names only its own component as a decider, not the ladder.
    assert "the lowest selector (component 3 of 6) against" not in _tie(by_state)["chosen_by"]
    assert "the weakest witness state (component 2 of 6) against" not in _tie(by_selector)["chosen_by"]


@pytest.mark.parametrize(
    "rival,first,later",
    [
        ({"selector": "0x22222222", "function": "manage"}, 3, 4),
        ({"witness_state": "proven_upper_bound", "selector": "0x22222222"}, 2, 3),
        ({"witness_state": "proven_upper_bound", "selector": "0x22222222", "function": "manage"}, 2, 4),
    ],
    ids=["selector_then_function", "state_then_selector", "three_components"],
)
def test_chosen_by_names_the_FIRST_differing_component_and_not_a_later_one(rival, first, later):
    """B2-R SF-1. Every other fixture here builds a rival differing at exactly
    ONE component, where first and last are the same index — so a rule returning
    the LAST differing component is still derived, moves all twelve published
    strings, and passed the module. These rivals differ at two components (one at
    three)."""
    chosen_by = _tie(_tied_pair(**rival))["chosen_by"]

    def as_decider(index):
        return f"{FOLD._ORDER_COMPONENT_NAMES[index - 1]} (component {index} of 6) against"

    assert f"What decided it: {as_decider(first)} 1 candidate(s)" in chosen_by
    # The later component IS named — the ladder recital lists every one — but
    # never as a decider, because the components behind the first are not reached.
    assert as_decider(later) not in chosen_by
    assert FOLD._ORDER_COMPONENT_NAMES[later - 1] in chosen_by, "the recital still lists every component"
    # Exactly one component decided this tie, so exactly one is named as one.
    assert chosen_by.count(" against ") == 1


def test_chosen_by_counts_the_candidates_each_component_separated():
    """The counts are this tie's own, not a frozen "1 candidate(s)"."""
    winner = _tied_pair(selector="0x22222222")
    two_rivals = replace(
        winner,
        tied_with=(
            replace(winner, tied_with=(), selector="0x22222222"),
            replace(winner, tied_with=(), selector="0x33333333"),
        ),
    )
    one = _tie(winner)["chosen_by"]
    two = _tie(two_rivals)["chosen_by"]
    assert "against 1 candidate(s)" in one and "over the 2 candidates" in one
    assert "against 2 candidate(s)" in two and "over the 3 candidates" in two
    assert one != two


def test_a_tie_the_order_does_not_separate_publishes_that_and_names_no_decider():
    """The third state: two candidates equal under the whole key still differ in
    fields the key does not read, and naming a component there credits the rule
    with a choice the arrival order made."""
    unseparated = replace(
        _tied_pair(),
        tied_with=(
            replace(
                _tied_pair(),
                tied_with=(),
                execution=EX.ProvingExecution(state=EX.EXECUTION_NOT_DETERMINED, reason=EX.REASON_FETCH_FAILED),
            ),
        ),
    )
    chosen_by = _tie(unseparated)["chosen_by"]
    assert "decides NOTHING here" in chosen_by
    assert "the order the candidates were built in and not on this rule" in chosen_by
    assert "component 1 of 6" not in chosen_by
    assert chosen_by != _tie(_tied_pair(selector="0x22222222"))["chosen_by"]


def test_the_component_names_line_up_with_the_order_they_describe():
    """A name per component, positionally. A ladder that grew a component without
    a name would publish the wrong rule for every tie decided past it."""
    assert len(FOLD._ORDER_COMPONENT_NAMES) == len(FOLD._composed_order(_tied_pair()))


def test_chosen_by_glosses_the_chain_component_over_the_fields_a_step_publishes(fold):  # noqa: F811
    """§11.2 (k). The order's tail is every field ``ActAsStep.as_json``
    publishes, so the gloss is read off the steps in hand."""
    document = fold(_tied_signals(), principals=_composing_principals(), **_tied_case())
    tied = [
        entry
        for entry in (_gate_row(document).get("reach_composed_magnitudes") or [])
        if entry.get("composed_selector_tie")
    ]
    assert tied, "this fixture must compose a tie for the chain gloss to be read off a real step"
    chosen_by = tied[0]["composed_selector_tie"]["chosen_by"]
    step_fields = set(tied[0]["act_as_chain"][0])
    assert len(step_fields) > 5, "the gloss is only under-inclusive where the step publishes more than five"
    for field_name in step_fields:
        assert field_name in chosen_by


def test_the_chain_gloss_is_read_off_the_steps_and_not_written_into_the_sentence():
    """A chain-less candidate cannot claim a field list it does not publish."""
    chosen_by = _tie(_tied_pair(selector="0x22222222"))["chosen_by"]
    assert "no candidate here publishes a step at all" in chosen_by
    assert "receiver_variable" not in chosen_by


# CAP-A §B4 — the uncalibrated-arm register


def test_every_arm_this_run_added_is_flagged_uncalibrated_and_disclosed():
    """CAP-A §B4 / ``SCORER_DISCIPLINE_CONTRACT.md`` §8. Phase A added seven
    narrower three-states and flagged none, so a reader could not tell an arm the
    model was fitted to from one nothing has exercised. The token and the
    disclosure are two lists, and the register only discloses if every disclosed
    arm is also flagged."""
    parameters = K.model_parameters()
    flagged = parameters["uncalibrated_arms"]
    block = parameters["uncalibrated_arm_disclosures"]
    registered = block["registered"]

    # Seven arms this run added, plus the code-control ceiling's one surviving
    # zero-carrier arm — the shared-implementation refusal, which no row can
    # publish because the fold refuses such a key before any magnitude branch
    # reads a sheet. THREE came off when the chain-log sweep earned this corpus
    # its first proven-empty sheets: ``code_control_ceiling:proven_empty`` and
    # the per-entity ``sheet_ceiling_bound_direction:ceiling`` gained carriers on
    # 115 such sheets, and the pre-existing row-header
    # ``value_at_stake_bound_direction:ceiling`` gained its first carrying row (a
    # subsumed one, every contributing entity a proven $0 with no coverage gap).
    # The COUNT is authored, not derived — nothing in this suite counts a corpus
    # — so it is checked by a reader against the scored document and moves only
    # with such a reading.
    # The disposition run added ``code_control_ceiling:airdrop_determined`` and
    # then took it straight back off: its live one-shot determined 13 sheets and
    # one of them publishes a ceiling under that reason, so the register's own
    # rule — an entry whose positive branch has fired is removed — fired inside
    # the same run. Checked against the scored document's
    # ``sheet_ceilings.entities_by_ceiling_reason``, which reads
    # ``airdrop_determined: 1``.
    #
    # The run's ONE surviving zero-carrier arm is
    # ``sheet_bound_refused:sheet_determined_by_disposition_does_not_bound`` —
    # the trim sites' answer where a sheet exists, is determined, and still may
    # not bound a witness. The 13 determined sheets carry no witnessed magnitude
    # for it to refuse a bound for, so it has no carrier on this corpus and is
    # disclosed like its siblings rather than left as a bare flag. Ninth entry.
    assert len(registered) == 9
    for entry in registered:
        assert entry["arm"] in flagged, entry["arm"]
        assert entry["state"] and entry["note"]
        assert entry["exercised_by"], entry["arm"]
        # Spelled, never omitted: a missing key reads as a field nobody filled in.
        assert "published_at" in entry and "population_census" in entry

    # One sentence per arm, and they cannot collapse: a registry whose entries
    # all read the same is a constant wearing a dict, and the register would then
    # say nothing about any particular arm.
    assert len({entry["note"] for entry in registered}) == len(registered)
    assert len({entry["arm"] for entry in registered}) == len(registered)

    # The remainder is DERIVED, not authored: the tokens that predate the
    # per-arm shape and carry no record are listed rather than left to be
    # inferred from the difference between two lists.
    disclosed = {entry["arm"] for entry in registered}
    assert block["arms_registered_without_a_disclosure"] == [a for a in flagged if a not in disclosed]
    assert set(block["arms_registered_without_a_disclosure"]).isdisjoint(disclosed)


def test_the_register_counts_no_population_and_points_at_the_document_instead():
    """The register is authored where no data is read, so a population figure in
    it would be a claim about a corpus it has never seen. It carries a POINTER
    instead, and ``null`` there is not a zero."""
    block = K.model_parameters()["uncalibrated_arm_disclosures"]
    for entry in block["registered"]:
        for value in entry.values():
            assert not isinstance(value, (int, float)) or isinstance(value, bool), entry["arm"]
    censuses = {entry["population_census"] for entry in block["registered"]}
    assert None in censuses and len(censuses) > 1, "a register where every pointer is null discloses nothing"
    assert "counts NOTHING" in block["reading"]


def test_every_test_the_register_names_exists():
    """A named test that does not exist makes the disclosure a promise rather
    than a record."""

    named = [
        node
        for entry in K.model_parameters()["uncalibrated_arm_disclosures"]["registered"]
        for node in entry["exercised_by"]
    ]
    assert named
    collected = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "--collect-only",
            "-m",
            "not live",
            *sorted({n.split("::")[0] for n in named}),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    ).stdout
    for node in named:
        module, _, rest = node.partition("::")
        assert f"{module}::{rest}" in collected, node


# Ruling 6.1 — destination_predicates is KEPT, and stays a field-description


def test_the_predicate_block_survives_and_claims_nothing_about_this_row(fold):  # noqa: F811
    """Ruling 6.1's KEEP, asserted as a property rather than left as an absence
    of change: the block is the only place a reader can check the composed
    ceiling against the destination's own body. M1 and M2 landed in B1 and A3 and
    are re-verified here on the post-Phase-B document."""
    document = fold(_tied_signals(), principals=_composing_principals(), **_tied_case())
    entries = _gate_row(document).get("reach_composed_magnitudes") or []
    assert entries
    for entry in entries:
        block = entry["destination_predicates"]
        assert block["evaluated"] is False
        assert block["source"] == "effective_functions.conditions"
        reading = block["reading"]
        # M1: modal, so the sentence claims nothing about THIS row's list.
        assert "it may include the authorization guard" in reading
        assert "it includes the authorization guard" not in reading
        # M2: clause (4) and the block it cross-referenced are both gone, and the
        # promise counts the clauses that remain.
        assert "Three things about them" in reading
        assert "(1)" in reading and "(2)" in reading and "(3)" in reading and "(4)" not in reading
        assert "caller_holding_precondition" not in reading
        # The three-state read is intact: descriptions is null where nothing was
        # read and a list where something was, never an empty list standing in
        # for an extraction that never ran.
        assert (block["descriptions"] is None) == (block["state"] != P.PREDICATES_EXTRACTED)


# CAP-B ruling 1 — the migration block is DATED HISTORY, not a live claim


def _migration(from_version):
    """The one record describing the bump that STARTED at `from_version`.

    `next()` with no default on purpose: a renamed or dropped record must fail
    the lookup loudly rather than let a test pass over a block that is no longer
    there."""
    records = K.model_parameters()["model_version_migrations"]
    return next(record for record in records if record["from"] == from_version)


def test_the_migration_block_dates_its_composition_figures_to_the_bump_that_measured_them():
    """CAP-B ruling 1. Two clauses of the only published record of the 1.0.1 ->
    1.1.0 bump were present tense and Phase A made both false. Both are now
    anchored — past tense, version-stamped, pointing at the census for the live
    count."""
    block = _migration("1.0.1-provisional")
    recovered = block["what_composition_did_not_recover"]
    confidence = block["read_the_confidence_fall_correctly"]

    # Past tense, stamped with the version whose measurement it reports — and
    # that version is now the LITERAL 1.1.0, not `MODEL_VERSION`. See the
    # frozen-literal test below for why the interpolation was retired here.
    assert "At this bump's own measurement (1.1.0-provisional, before the execution-witness pass)" in recovered
    assert "those composed 13 entities and $46,164,146.29" in recovered
    # The present-tense forms are gone.
    assert "composing 13 entities" not in recovered
    assert "40 signals composition answered" not in confidence
    # ...and the live count is delegated to the census rather than restated.
    assert "counted in reach_composition_census rather than asserted here" in recovered
    assert "40 signals composition was asked of" in confidence
    assert "28 of them publish a composed figure and 12 are withheld" in confidence


def test_the_1_1_0_migration_stamp_is_frozen_and_cannot_silently_re_interpolate(monkeypatch):
    """The other half of the stamp discipline, and the half a passing suite
    would otherwise never notice.

    The 1.0.1 -> 1.1.0 record reports what was measured while 1.1.0 was the
    CURRENT version. Once 1.2.0 shipped, an interpolated `MODEL_VERSION` there
    would restamp that dated measurement with whatever is shipping now — a 1.1.0
    figure wearing a 1.2.0 label, which is precisely the drift the interpolation
    was originally added to prevent, running the other way. So the stamp is
    frozen, and this test is what keeps it frozen: it fails the moment the
    f-string comes back."""
    from services.scoring import constants as C

    shipped = _migration("1.0.1-provisional")["what_composition_did_not_recover"]
    monkeypatch.setattr(C, "MODEL_VERSION", "9.9.9-fictional")
    unmoved = _migration("1.0.1-provisional")["what_composition_did_not_recover"]

    assert unmoved == shipped
    assert "(1.1.0-provisional, before the execution-witness pass)" in unmoved
    assert "9.9.9-fictional" not in unmoved
    # The record's own endpoint is frozen with it: this bump ENDED at 1.1.0 and
    # no later version can claim to be where it landed.
    assert _migration("1.0.1-provisional")["to"] == "1.1.0-provisional"


def test_the_1_2_0_migration_stamp_is_frozen_and_cannot_silently_re_interpolate(monkeypatch):
    """The same freeze, one bump later, on the record that has just stopped
    describing the current version.

    The 1.1.0 -> 1.2.0 record reports what was measured while 1.2.0 was CURRENT.
    Once 1.3.0 shipped, an interpolated `MODEL_VERSION` there would restamp
    those dated figures — the λ fall to 71.7053, the B+ -> B drop — with
    whatever is shipping now. Frozen, and this is what keeps it frozen."""
    from services.scoring import constants as C

    shipped = _migration("1.1.0-provisional")
    monkeypatch.setattr(C, "MODEL_VERSION", "9.9.9-fictional")
    unmoved = _migration("1.1.0-provisional")

    assert unmoved == shipped
    assert "this bump's own tip (1.2.0-provisional)" in unmoved["measured_at"]
    assert "9.9.9-fictional" not in unmoved["measured_at"]
    # The record's own endpoint is frozen with it: this bump ENDED at 1.2.0 and
    # no later version can claim to be where it landed.
    assert unmoved["to"] == "1.2.0-provisional"


def test_the_1_3_0_migration_stamp_is_frozen_and_cannot_silently_re_interpolate(monkeypatch):
    """The same freeze, one bump later again.

    The 1.2.0 -> 1.3.0 record reports what was measured while 1.3.0 was CURRENT.
    Once 1.4.0 shipped, an interpolated `MODEL_VERSION` there would restamp those
    dated figures — the revoked $0.05 ceiling, the 11 -> 10 entity fall — with
    whatever is shipping now. Frozen, and this is what keeps it frozen."""
    from services.scoring import constants as C

    shipped = _migration("1.2.0-provisional")
    monkeypatch.setattr(C, "MODEL_VERSION", "9.9.9-fictional")
    unmoved = _migration("1.2.0-provisional")

    assert unmoved == shipped
    assert "this bump's own tip (1.3.0-provisional)" in unmoved["measured_at"]
    assert "9.9.9-fictional" not in unmoved["measured_at"]
    # The record's own endpoint is frozen with it: this bump ENDED at 1.3.0 and
    # no later version can claim to be where it landed.
    assert unmoved["to"] == "1.3.0-provisional"


def test_the_migration_version_stamp_moves_with_the_version(monkeypatch):
    """B1's S1 lesson applied to CAP-B's stamp: a literal reads identically
    today and drifts silently at the next bump.

    Moved onto the 1.3.0 -> 1.4.0 record, which is the one describing the
    version that is CURRENT — the only record for which "moves with the version"
    is the honest behaviour. Its three predecessors are frozen by the tests
    above."""
    from services.scoring import constants as C

    shipped = _migration("1.3.0-provisional")["measured_at"]
    monkeypatch.setattr(C, "MODEL_VERSION", "9.9.9-fictional")
    moved = _migration("1.3.0-provisional")["measured_at"]

    assert moved != shipped
    assert "at this bump's own tip (9.9.9-fictional)" in moved
    assert "1.4.0-provisional" not in moved
    # The endpoint interpolates too, so the record cannot name one version in
    # its prose and a different one in its field.
    assert _migration("1.3.0-provisional")["to"] == "9.9.9-fictional"


def test_the_1_3_0_migration_record_states_its_invariant_6_exception():
    """A bump that LOWERS a term has to say so where the model is published.

    1.3.0's guard un-publishes a sheet ceiling, which moves a confidence term
    DOWN — the one direction invariant 6 forbids. The exception is ruled and it
    is ruled here, on the record a reader joins to by `model_version`, rather
    than in a spec file no consumer of the document can see."""
    record = _migration("1.2.0-provisional")
    exception = record["the_invariant_6_exception_this_bump_takes"]

    assert "invariant 6" in exception
    # The ruling's own shape: what is withdrawn was never earned, so the fall is
    # the correction rather than the price of one.
    assert "reach_magnitude_witnessed_of_reaching_pct" in exception
    assert "35.6 -> 35.5" in exception
    assert "never earned" in exception
    # And the grade surface it does NOT move, which is the other half of the
    # ruling: only the ceiling dollars move, by the revoked $0.05.
    unmoved = record["what_did_not_move_and_why_that_was_a_ruling"]
    assert "grade_lambda stays 71.7053" in unmoved
    assert "$4,218,707,276.09 -> $4,218,707,276.04" in unmoved


def test_the_current_migration_record_states_its_invariant_6_exception():
    """1.4.0 takes its own, and of the opposite shape.

    The disposition rule's protocol-reference conjunct is ANTI-MONOTONE:
    discovery growing moves a token INTO the universe and WITHDRAWS a
    determination. The ruling is that withdrawal is the safe direction — and the
    consequence a reader has to carry is that the document is not stable across
    discovery growth. Every single point of failure the measurement found is
    named on the record itself, not left in a spec no consumer can see."""
    record = _migration("1.3.0-provisional")
    exception = record["the_invariant_6_exception_this_bump_takes"]

    assert "invariant 6" in exception
    assert "ANTI-MONOTONE" in exception
    assert "NOT STABLE ACROSS DISCOVERY GROWTH" in exception
    # The named tokens, and the reason the condemnation of a REAL one is not a
    # lie: the published state is a delivery-shape claim. The class the rule
    # touches is FIVE real tokens, not the two the pre-run analysis named.
    assert "FIVE demonstrably real tokens" in exception
    assert "HEX" in exception and "SINGLE effect_verdicts row" in exception
    # The second single point of failure, measured after the pre-run census: one
    # source, one real token, and the source with no chain column at all.
    assert "base USDC is spared by dapp_interactions ALONE" in exception
    assert "uniETH" in exception and "delivery-shape claim" in exception
    # What the bump does not close travels with it, on its own key.
    open_items = record["what_this_bump_does_not_close"]
    assert "INERT ON BASE" in open_items
    assert "1,175 of 1,175" in open_items
    assert "NOT proven whole" in open_items
    # And what the live one-shot behind this bump did and did not move. The four
    # dollar surfaces held byte-for-byte; confidence is the one figure that
    # moved, and the record states both halves rather than either alone.
    unmoved = record["what_did_not_move_and_why_that_was_a_ruling"]
    assert "grade_lambda stays 71.7053" in unmoved
    assert "ceiling_usd_over_distinct_entities stays $4,218,743,833.16" in unmoved
    assert "confidence_pct 42.5 -> 43.2" in unmoved
    assert record["confidence_pct"] == [42.5, 43.2]
    # The measurement is real data, not a rule shipped ahead of any: the record
    # counts the readings the one-shot disposed.
    assert "1,973 readings over 1,264 tokens" in record["what_moved"]


def test_the_frontend_golden_was_regenerated_for_the_current_model_version():
    """The residual staleness hole in the version-bump checklist, closed on the
    side that actually runs in CI.

    `site/src/test/fixtures/score_etherfi.json` is the document the vitest
    suites assert against, and a bump that edits `MODEL_VERSION` without
    regenerating it leaves the page's tests pinned to the PREVIOUS model's
    lambda, letter and ranking — all still internally consistent, so vitest
    stays green and nothing anywhere reports that the golden is a version
    behind. Asserting the stamp here makes the omission fail loudly in the
    Python suite, which is where the bump is made."""
    import json

    golden = json.loads((ROOT / "site" / "src" / "test" / "fixtures" / "score_etherfi.json").read_text())
    assert golden["model_version"] == K.MODEL_VERSION, (
        f"the frontend golden is stamped {golden['model_version']!r} but MODEL_VERSION is "
        f"{K.MODEL_VERSION!r} — regenerate site/src/test/fixtures/score_etherfi.json "
        f"(see its README for the shape and the minified one-line write)"
    )


def test_the_pre_existing_ceiling_arm_came_off_when_a_row_finally_earned_it():
    """CAP-B ruling 2, discharged by evidence rather than by a deferral.

    The arm was registered while ``value_at_stake_bound_direction: ceiling`` had
    0 carrying rows before Phase A and 0 after — ``site/src/score/derive.js``
    allow-lists the direction, so a ``<=`` badge would have rendered for a state
    nothing could earn. The chain-log sweep changed the corpus, not the rule: a
    row every one of whose contributing entities is a PROVEN $0 with no coverage
    gap satisfies the conjunction, and one such row now publishes the direction.

    The register's own rule (``constants.py``: entries are rules whose positive
    branch has never fired) then requires REMOVAL, and removal rather than a
    narrowing of scope: an entry kept because some slice of the population still
    reads zero would say the model was never fitted to a state the document
    publishes, which is the one thing this register must not say. The removal is
    authored and reader-checked against the scored corpus; what is asserted here
    is only that no half-removed reference survives in either list.
    """
    parameters = K.model_parameters()
    assert "value_at_stake_bound_direction:ceiling" not in parameters["uncalibrated_arms"]
    assert "value_at_stake_bound_direction:ceiling" not in {
        entry["arm"] for entry in parameters["uncalibrated_arm_disclosures"]["registered"]
    }
    # The direction itself is untouched and still earnable — the arm came off
    # because it fired, not because the state was withdrawn.
    assert FOLD.BOUND_DIRECTION_CEILING == "ceiling"


def test_the_ceiling_direction_stays_allow_listed_on_the_page():
    """The register is the fix, not the removal: dropping `ceiling` from
    `BOUND_DIRECTIONS` trades an undisclosed badge for an undisclosed blank."""
    derive = (ROOT / "site" / "src" / "score" / "derive.js").read_text()
    assert f'"{FOLD.BOUND_DIRECTION_CEILING}"' in derive
    assert "BOUND_DIRECTIONS" in derive
