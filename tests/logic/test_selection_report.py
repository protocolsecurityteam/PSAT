"""Selection must preserve important/uncertain effects without doing address expansion."""

import copy
import json
from dataclasses import replace

import pytest

from services.logic.formula import compile_function
from services.logic.model import Effect, Formula, ReadError, encode
from services.logic.terms import CALLER, ORIGIN, TRUE, const, mk, mk_and, mk_cmp, mk_not, mk_or
from services.resolution.logic_selection import ReportLimits, selection_report
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """
pragma solidity 0.8.27;
contract C {
    address owner;
    bool paused = true;
    uint limit;
    uint counter;
    mapping(address => bool) members;
    constructor() { owner = msg.sender; }
    function setOwner(address value) external { require(msg.sender == owner); owner = value; }
    function publicOwner(address value) external { owner = value; }
    function pausedOwner(address value) external { require(msg.sender == owner && !paused); owner = value; }
    function bounded(uint value) external { require(msg.sender == owner && value <= 10); limit = value; }
    function gated() external { require(msg.sender == owner); counter += 1; }
    function early() external { if(msg.sender != owner) return; counter = 1; }
    function grant(address who) external { require(msg.sender == owner); members[who] = true; }
    function guardedMember() external { require(members[msg.sender]); counter = 1; }
    function limitUse(uint value) external { require(value <= limit); counter = value; }
    function impossible() external { revert(); }
}
"""


@pytest.fixture(scope="module")
def source_bundle(anvil):
    d = O.deployment(*anvil, SOURCE)
    d.deploy("C")
    rows = [
        compile_function(d.slither["C"], f, d.at["C"], d.chain(), d.contracts("C"))
        for f in d.slither["C"].functions_entry_points
        if not f.is_constructor
    ]
    return d, {
        "schema": 2,
        "kind": "formulas",
        "chain_id": 1,
        "block": d.chain().block,
        "address": O.hex20(d.at["C"]),
        "functions": {f.signature: encode(f) for f in rows},
    }


def run(bundle, limits=ReportLimits()):
    d, artifact = bundle
    reads = d.chain()

    def forbidden(*args):
        raise AssertionError("selection tried to enumerate")

    reads.storage_dump = reads.key_words = reads.preimages = forbidden
    return selection_report(artifact, reads=reads, contracts=d.contracts("C"), limits=limits)


def row(report, name):
    return next(r for r in report["rows"] if r["function"].split("(")[0] == name)


def test_owner_change_is_selected_on_dependency_evidence(source_bundle, monkeypatch):
    def forbidden(*a, **kw):
        raise AssertionError("selection ran expansion")

    monkeypatch.setattr("services.logic.expansion.expand_formula", forbidden)
    before = copy.deepcopy(source_bundle[1])
    result = run(source_bundle)
    change = row(result, "setOwner")
    assert change["access"]["status"] == "restricted"
    assert change["priority"] == "high" and "decision" not in change
    assert "impact" not in change  # power evidence isn't a loss estimate
    assert any(f["kind"] == "may_change_authority_condition" for f in change["facts"])
    assert result["automatic_execution"] is False
    assert source_bundle[1] == before
    json.dumps(result)
    d = source_bundle[0]
    fn = O.function(d, "C", "setOwner")
    assert O.passes(d, "C", fn, [O.hex20(O.ACCOUNTS[1])], O.OWNER)
    assert not O.passes(d, "C", fn, [O.hex20(O.ACCOUNTS[1])], O.ACCOUNTS[2])


def test_unrestricted_power_is_reported_not_hidden(source_bundle):
    public = row(run(source_bundle), "publicOwner")
    assert public["access"]["status"] == "unrestricted"
    assert public["priority"] == "high" and "decision" not in public


def test_early_return_does_not_make_the_write_unrestricted(source_bundle):
    result = row(run(source_bundle), "early")
    assert result["access"]["status"] == "restricted"
    d = source_bundle[0]
    assert O.passes(d, "C", O.function(d, "C", "early"), sender=O.ACCOUNTS[1])


def test_paused_power_keeps_attention_without_inventing_holders(source_bundle):
    result = row(run(source_bundle), "pausedOwner")
    assert result["access"]["activity"] == "inactive_at_block"
    assert result["priority"] == "high" and "impact" not in result
    assert "decision" not in result


def test_value_bound_is_not_called_an_economic_loss_bound(source_bundle):
    result = row(run(source_bundle), "bounded")
    bound = result["value_bound"]
    assert bound is not None and bound["upper"] == 10
    assert "not an asset-loss" in bound["meaning"]
    assert "impact" not in result


def test_membership_needs_state_without_scanning_it(source_bundle):
    result = row(run(source_bundle), "guardedMember")
    assert result["access"]["status"] == "unresolved"
    assert any(i["kind"] == "state_required" for i in result["access"]["issues"])
    assert "decision" not in result and "impact" not in result


def test_membership_writer_can_be_selected_without_listing_members(source_bundle):
    result = row(run(source_bundle), "grant")
    assert result["priority"] == "high" and "decision" not in result
    assert result["access"]["status"] == "unresolved"
    assert any(f["kind"] == "may_change_authority_condition" for f in result["facts"])


def test_pure_revert_needs_no_enumeration(source_bundle):
    result = row(run(source_bundle), "impossible")
    assert result["access"]["activity"] == "inactive_at_block"
    assert "impact" not in result


def test_offline_report_and_zero_budgets_keep_unknowns_visible(source_bundle):
    saved = source_bundle[1]
    report = selection_report(saved)
    assert report["mode"] == "offline" and report["direct_reads"] == 0
    assert row(report, "setOwner")["access"]["status"] == "unresolved"
    cut = run(source_bundle, ReportLimits(solver_queries=0, dependency_pairs=0))
    assert cut["solver_queries"] == 0
    assert all("decision" not in r for r in cut["rows"])
    assert len(cut["rows"]) == len(report["rows"])
    assert {r["function"] for r in cut["rows"]} == set(saved["functions"])


def test_transport_failure_aborts_instead_of_lowering_priority(source_bundle):
    d, saved = source_bundle
    reads = d.chain()

    def failed(*args):
        raise ReadError("node unavailable")

    reads.storage = failed
    with pytest.raises(ReadError):
        selection_report(saved, reads=reads, contracts=d.contracts("C"))


def test_direct_read_budget_is_enforced_without_losing_rows(source_bundle):
    result = run(source_bundle, ReportLimits(direct_reads=0))
    assert result["direct_reads"] == 0
    assert row(result, "setOwner")["access"]["status"] == "unresolved"
    assert "decision" not in row(result, "setOwner")


def test_report_requires_the_original_block(source_bundle):
    d, saved = source_bundle
    reads = d.chain()
    reads.block += 1
    with pytest.raises(ValueError, match="pinned block"):
        selection_report(saved, reads=reads, contracts=d.contracts("C"))


def bundle(*formulas):
    return {
        "schema": 2,
        "kind": "formulas",
        "chain_id": 1,
        "address": "0x1",
        "block": 1,
        "functions": {f.signature: encode(f) for f in formulas},
    }


def function(name, guard, target="value", value=None):
    value = value or const(1)
    return Formula(1, 1, name, 0, (), guard, (Effect("write", (const(1, "address"), target, ()), value, guard),), ())


def test_origin_and_signature_authority_cannot_be_existentially_freed():
    origin = function("viaOrigin()", mk_cmp("eq", ORIGIN, const(7)))
    signer = mk("signer", const(1), *(mk("arg", n, "uint256") for n in ("v", "r", "s")))
    signed = function("signed()", mk_cmp("eq", signer, const(7)))
    result = selection_report(bundle(origin, signed))
    assert row(result, "viaOrigin")["access"]["status"] == "restricted"
    assert row(result, "viaOrigin")["access"]["identity_dimensions"] == ("origin",)
    assert row(result, "signed")["access"]["status"] == "unresolved"


def test_public_branch_prevents_a_false_required_identity_dependency():
    stored = mk("load", const(1, "address"), "owner", ())
    gate = mk_cmp("eq", CALLER, stored)
    public = mk_cmp("eq", mk("arg", "mode", "uint256"), const(0))
    consumer = function("consumer()", mk_or([gate, public]))
    setter = function("setter()", mk_cmp("eq", CALLER, const(7)), target="owner")
    result = selection_report(bundle(consumer, setter))
    assert not any(f["kind"] == "may_change_authority_condition" for f in row(result, "setter")["facts"])


def test_identifier_renaming_does_not_change_priority():
    def report(name):
        loaded = mk("load", const(1, "address"), name, ())
        return selection_report(
            bundle(
                function("consume()", mk_cmp("eq", CALLER, loaded)),
                function("set()", mk_cmp("eq", CALLER, const(7)), target=name),
            )
        )

    a, b = report("owner"), report("unremarkable_word")
    assert [(r["priority"], r["access"]["status"]) for r in a["rows"]] == [
        (r["priority"], r["access"]["status"]) for r in b["rows"]
    ]


def test_all_arguments_remain_connected_in_access_queries():
    arg = mk("arg", "id", "uint8")
    gate = mk_and(
        [
            mk_or(
                [
                    mk_and([mk_cmp("eq", CALLER, const(7)), mk_cmp("eq", arg, const(0))]),
                    mk_and([mk_not(mk_cmp("eq", CALLER, const(7))), mk_cmp("eq", arg, const(1))]),
                ]
            ),
            mk_cmp("eq", arg, const(0)),
        ]
    )
    result = row(selection_report(bundle(function("gated()", gate))), "gated")
    assert result["access"]["status"] == "restricted"
    assert result["access"]["activity"] == "reachable_in_call_frame"


def test_arguments_can_vary_by_identity_without_requiring_one_global_witness():
    arg = mk("arg", "choice", "uint8")
    guard = mk_or(
        [
            mk_and([mk_cmp("eq", CALLER, const(7)), mk_cmp("eq", arg, const(0))]),
            mk_and([mk_not(mk_cmp("eq", CALLER, const(7))), mk_cmp("eq", arg, const(1))]),
        ]
    )
    assert row(selection_report(bundle(function("f()", guard))), "f")["access"]["status"] == "unrestricted"


def test_an_unmodelled_effect_remains_high_attention():
    from services.logic.terms import unknown

    f = function("f()", unknown("unsupported:external_transition"))
    f = replace(f, effects=(Effect("call", ("act", unknown("target"), ()), TRUE, f.success),))
    result = row(selection_report(bundle(f)), "f")
    assert result["priority"] == "high" and "decision" not in result
    assert result["access"]["status"] == "unresolved"


def test_different_struct_fields_are_not_aliased():
    a = const(1, "address")
    read = mk("load", a, "records", (("k", const(0)), ("f", "admin")))
    consumer = function("use()", mk_cmp("eq", CALLER, read))
    setter = function("set()", TRUE)
    setter = replace(
        setter, effects=(Effect("write", (a, "records", (("k", const(0)), ("f", "note"))), const(1), TRUE),)
    )
    result = row(selection_report(bundle(consumer, setter)), "set")
    assert not result["facts"]


def test_not_verified_deployment_is_not_a_clean_empty_result():
    saved = {
        "schema": 2,
        "kind": "formulas",
        "chain_id": 1,
        "block": 1,
        "address": "0x1",
        "status": "not_verified",
        "functions": {},
    }
    result = selection_report(saved)
    assert result["input_status"] == "not_verified"
    assert result["rows"] == [] and result["automatic_execution"] is False
