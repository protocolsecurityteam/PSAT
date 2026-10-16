"""Every enumeration in static analysis that can grow with the contract stops at a budget, and what it stopped on is
published as not determined with the budget's reason: never as an unguarded effect or a smaller reach condition.
"""

from __future__ import annotations

import time

import pytest

from services.resolution.adapters import AdapterRegistry, EvaluationContext
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.predicate_evaluator import evaluate_tree_with_registry
from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts
from services.static.contract_analysis_pipeline.effect_scope_codec import expand_effect_scopes
from services.static.contract_analysis_pipeline.predicates import reach
from tests.support.foundry_project import write_foundry_project


def _leaf_reasons(tree) -> set[str]:
    if not isinstance(tree, dict):
        return set()
    leaf = tree.get("leaf") or {}
    found = {leaf["unsupported_reason"]} if leaf.get("unsupported_reason") else set()
    for child in tree.get("children") or []:
        found |= _leaf_reasons(child)
    return found


def _resolved_openness(tree) -> tuple[str, str | None]:
    from services.policy.capability_surface import capability_surface_openness, project_capability_surface

    cap = capability_to_dict(evaluate_tree_with_registry(tree, AdapterRegistry(), EvaluationContext(chain_id=1)))
    return capability_surface_openness(cap, project_capability_surface(cap)), cap.get("unsupported_reason")


def _scopes(tmp_path, name: str, source: str) -> dict:
    _, trees, _ = collect_contract_analysis_with_artifacts(write_foundry_project(tmp_path, name, source))
    assert isinstance(trees, dict)
    return expand_effect_scopes(trees)


@pytest.mark.compile
def test_a_function_with_more_effect_sites_than_the_budget_is_not_determined(tmp_path):
    writes = "\n".join(f"  s{i} = v;" for i in range(300))
    slots = " ".join(f"uint256 s{i};" for i in range(300))
    source = f"""pragma solidity ^0.8.19;
contract ManySites {{
 address owner; {slots}
 function f(uint256 v) external {{
  require(msg.sender == owner);
{writes}
 }}
}}"""
    sites = _scopes(tmp_path, "ManySites", source)["f(uint256)"]
    unresolved = [site for site in sites if site["kind"] == "unresolved_effect"]
    assert len(unresolved) == 1
    assert _leaf_reasons(unresolved[0]["predicate"]) == {"effect_site_budget"}
    assert all("effect_site_budget" in _leaf_reasons(site["predicate"]) for site in sites)
    assert _resolved_openness(unresolved[0]["predicate"]) == ("not_determined", "effect_site_budget")


@pytest.mark.compile
def test_a_guard_behind_more_paths_than_the_budget_is_not_determined(tmp_path):
    branches = "\n".join(f"  if (a & {1 << i} > 0) {{ t{i} = 1; }}" for i in range(8))
    slots = " ".join(f"uint256 t{i};" for i in range(8))
    source = f"""pragma solidity ^0.8.19;
contract ManyPaths {{
 address owner; bool strict; uint256 y; {slots}
 function f(uint256 a) external {{
{branches}
  if (strict) {{ require(msg.sender == owner); }}
  y = a;
 }}
}}"""
    sites = _scopes(tmp_path, "ManyPaths", source)["f(uint256)"]
    site = next(site for site in sites if site["target"] == "y")
    assert "effect_path_budget" in _leaf_reasons(site["predicate"])
    openness, _ = _resolved_openness(site["predicate"])
    assert openness == "not_determined"


def _shared(levels: int):
    formula = ("branch", 0, True)
    for level in range(1, levels + 1):
        formula = (
            "or",
            (("and", (formula, ("branch", 2 * level, True))), ("and", (formula, ("branch", 2 * level + 1, True)))),
        )
    return formula


def test_a_reach_condition_over_its_leaf_budget_is_not_determined_and_counted_without_expanding_it():
    within = ("or", tuple(("branch", i, True) for i in range(reach._REACH_LEAF_BUDGET)))
    assert reach._within_budget(within) == within
    over = ("or", tuple(("branch", i, True) for i in range(reach._REACH_LEAF_BUDGET + 1)))
    assert reach._within_budget(over) == ("unsupported", "gate_reach_condition_budget")
    # 2^60 leaves once its shared sub-formulas are read as a tree.
    started = time.process_time()
    assert reach._within_budget(_shared(60)) == ("unsupported", "gate_reach_condition_budget")
    assert time.process_time() - started < 1
    assert reach._within_budget(_shared(3)) == _shared(3)
