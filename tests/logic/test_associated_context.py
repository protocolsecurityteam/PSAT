"""Related code is source context, not extra address enumeration or authority evidence."""

from services.clients.jev import JevClient
from services.logic import deployment
from services.logic.model import decode_formula
from services.logic.source_context import validate_context
from services.resolution.logic_assessment import assess_formulas
from services.resolution.logic_impact import JudgmentCache
from services.resolution.logic_selection import selections_from_report
from tests.logic._anvil import anvil  # noqa: F401
from tests.logic.test_formula_engine import FixtureReads, deployed  # noqa: F401
from tests.logic.test_impact import Session
from tests.logic.test_separate_expansion import install_inputs


def test_source_discovered_by_one_entrypoint_is_available_to_the_other(monkeypatch, deployed):
    install_inputs(monkeypatch, deployed, FixtureReads(deployed))
    result = deployment.deployment_formulas(
        None, f"0x{deployed.at['C']:040x}", 1, "unused", signatures={"delegated()", "selected(uint256)"}
    )
    context = result["contexts"]["selected(uint256)"]
    validate_context(context, decode_formula(result["functions"]["selected(uint256)"]))
    assert any("contract Guard" in unit["source"] for unit in context["units"])
    assert {d["address"] for d in context["deployments"]} == {f"0x{deployed.at[n]:040x}" for n in ("C", "Guard")}
    assert result["source_scope"]["complete_dependency_graph"] is False


def test_explicit_related_source_is_included_without_compiling_its_functions(monkeypatch, deployed):
    install_inputs(monkeypatch, deployed, FixtureReads(deployed))
    result = deployment.deployment_formulas(
        None,
        f"0x{deployed.at['C']:040x}",
        1,
        "unused",
        signatures={"selected(uint256)"},
        related_addresses=(f"0x{deployed.at['Guard']:040x}", "0x99"),
    )
    assert set(result["functions"]) == {"selected(uint256)"}
    context = result["contexts"]["selected(uint256)"]
    assert any("contract Guard" in unit["source"] for unit in context["units"])
    assert "unverified:0x99" in context["source_gaps"]
    assert context["source_complete"] is False
    assert result["source_scope"]["unverified_addresses"] == [f"0x{0x99:040x}"]


def test_context_limit_is_visible_and_does_not_change_formulas(monkeypatch, deployed):
    install_inputs(monkeypatch, deployed, FixtureReads(deployed))
    args = (None, f"0x{deployed.at['C']:040x}", 1, "unused")
    full = deployment.deployment_formulas(*args, signatures={"selected(uint256)"})
    small = deployment.deployment_formulas(*args, signatures={"selected(uint256)"}, context_chars=50)
    assert small["functions"] == full["functions"]
    assert small["contexts"]["selected(uint256)"]["source_complete"] is False
    assert any("truncated" in g for g in small["contexts"]["selected(uint256)"]["source_gaps"])


def test_generated_assessed_plan_expands_the_saved_relation_on_local_chain(monkeypatch, deployed, tmp_path):
    from tests.logic.test_formula_engine import OWNER

    def forbidden(*args):
        raise AssertionError("generate/assess attempted holder enumeration")

    class NoEnumeration(FixtureReads):
        storage_dump = key_words = preimages = forbidden

    reads = NoEnumeration(deployed)
    contracts = install_inputs(monkeypatch, deployed, reads)
    saved = deployment.deployment_formulas(
        None, f"0x{deployed.at['C']:040x}", 1, "unused", signatures={"selected(uint256)"}
    )
    assessment = assess_formulas(
        saved,
        cache=JudgmentCache(tmp_path),
        reads=reads,
        contracts=contracts,
        client=JevClient("test-key", session=Session()),
    )
    assert assessment["assessment"]["judgments_complete"] is True
    plan = selections_from_report(saved, assessment)
    assert plan["selected(uint256)"].callers is False
    install_inputs(monkeypatch, deployed, FixtureReads(deployed))
    result = deployment.deployment_expansions(None, saved, "unused", plan)
    value = result["functions"]["selected(uint256)"]["expansion"]["value"]
    assert value["callers"] is None
    effect = value["effects"]["tuple"][0]
    assert effect["members"] == {"tuple": [OWNER]}
    assert effect["representation"] == "finite"
