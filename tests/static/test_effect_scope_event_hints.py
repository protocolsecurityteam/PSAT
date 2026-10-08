"""An effect site's authority leaf must carry the same writer-event evidence as its entry point's tree.

Without the hints, the site's caller-role check had no adapter. On a cold index that hid behind the entry point's own
deferral; once the index caught up, the resolver published the site's ``unsupported(no_adapter)`` over the entry point's
resolved principals (a TimelockController whose PROPOSER is a Safe read as not determined).
"""

from __future__ import annotations

import pytest

from services.resolution.adapters import AdapterRegistry, EvaluationContext
from services.resolution.adapters.event_indexed import EventIndexedAdapter
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.effect_scopes import resolve_effect_scopes, site_predicates
from services.resolution.predicate_evaluator import evaluate_tree_with_registry
from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts
from services.static.contract_analysis_pipeline.effect_scope_codec import expand_effect_scopes
from tests.resolution.test_adapter_event_indexed import FakeEventLogRepo
from tests.support.foundry_project import write_foundry_project

pytestmark = pytest.mark.compile

OPERATOR = "0x" + "ab" * 20
SOURCE = """pragma solidity ^0.8.19;
contract Gated {
    mapping(address => bool) public operators;
    address public owner;
    uint256 public value;
    event OperatorAdded(address indexed who);
    event OperatorRemoved(address indexed who);
    constructor() { owner = msg.sender; }
    function addOperator(address who) external {
        require(msg.sender == owner);
        operators[who] = true;
        emit OperatorAdded(who);
    }
    function removeOperator(address who) external {
        require(msg.sender == owner);
        operators[who] = false;
        emit OperatorRemoved(who);
    }
    function set(uint256 next) external { require(operators[msg.sender], "not operator"); value = next; }
}
"""


def _membership_hints(tree, *, full=False):
    """Each caller-role membership leaf's writer-event hints: their topics, or the hints themselves with ``full``."""
    found = []

    def walk(node):
        if not isinstance(node, dict):
            return
        if node.get("op") == "LEAF":
            leaf = node.get("leaf") or {}
            descriptor = leaf.get("set_descriptor") or {}
            if leaf.get("kind") == "membership" and descriptor.get("kind") == "mapping_membership":
                hints = descriptor.get("enumeration_hint") or []
                found.append(hints if full else sorted(hint["topic0"] for hint in hints))
            return
        for child in node.get("children") or []:
            walk(child)

    walk(tree)
    return found


@pytest.fixture(scope="module")
def artifacts(tmp_path_factory):
    project = write_foundry_project(tmp_path_factory.mktemp("gated"), "Gated", SOURCE)
    _, trees, _ = collect_contract_analysis_with_artifacts(project)
    assert trees is not None
    return trees


def test_an_effect_site_carries_its_entry_points_event_hints(artifacts):
    entry_hints = _membership_hints(artifacts["trees"]["set(uint256)"])
    assert entry_hints and entry_hints[0], "guard: the entry point's operator check must carry writer-event hints"

    [site] = expand_effect_scopes(artifacts)["set(uint256)"]
    assert _membership_hints(site["predicate"]) == entry_hints


def test_an_indexed_role_resolves_the_same_at_the_site_as_at_the_entry_point(artifacts):
    [hints] = _membership_hints(artifacts["trees"]["set(uint256)"], full=True)
    [topic_added] = [hint["topic0"] for hint in hints if hint["direction"] == "add"]
    repo = FakeEventLogRepo({topic_added: [("add", OPERATOR)]})
    registry = AdapterRegistry()
    registry.register(EventIndexedAdapter)
    ctx = EvaluationContext(chain_id=1, contract_address="0x" + "cd" * 20, block=18_000_000, event_log_repo=repo)

    base = evaluate_tree_with_registry(artifacts["trees"]["set(uint256)"], registry, ctx)
    expanded = expand_effect_scopes(artifacts)
    aggregate, records = resolve_effect_scopes(
        expanded["set(uint256)"], registry, ctx, base_cap=base, effect_predicates=site_predicates(expanded)
    )

    assert base.kind == "finite_set" and [m.lower() for m in base.members or []] == [OPERATOR]
    assert aggregate is not None and capability_to_dict(aggregate) == capability_to_dict(base)
    assert [record["capability"]["kind"] for record in records] == ["finite_set"]
