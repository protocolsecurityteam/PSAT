from pathlib import Path

import pytest

from services.policy.capability_surface import capability_surface_openness, project_capability_surface
from services.resolution.adapters import AdapterRegistry, EvaluationContext
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.effect_scopes import resolve_effect_scopes, site_predicates
from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts
from services.static.contract_analysis_pipeline.effect_scope_codec import expand_effect_scopes
from tests.support.foundry_project import write_foundry_project

pytestmark = pytest.mark.compile
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/contracts/authorization/structural_controls.sol"
OWNER = "0x" + "11" * 20


def _resolve(trees, signature, ctx):
    scopes = expand_effect_scopes(trees)
    return resolve_effect_scopes(scopes[signature], AdapterRegistry(), ctx, effect_predicates=site_predicates(scopes))


@pytest.fixture(scope="module")
def artifact(tmp_path_factory):
    project = write_foundry_project(tmp_path_factory.mktemp("structural"), "StructuralControls", FIXTURE.read_text())
    return collect_contract_analysis_with_artifacts(project)


def test_storage_summaries_distinguish_aliases_grants_and_revocation(artifact):
    _, trees, _ = artifact
    summaries = trees["structural_evidence"]["functions"]
    assert summaries["StructuralControls.grant(address)"]["writes"][0]["nonzero_transition"] == "may_grant"
    assert summaries["StructuralControls.revoke(address)"]["writes"][0]["nonzero_transition"] == "revokes"
    assert summaries["StructuralControls.run(address,bytes)"]["writes"][0]["nonzero_transition"] == "revokes"
    assert (
        summaries["StructuralControls.setLimit(uint256)"]["calls"][0]["declaration"] == "StructuralControls.authorize()"
    )


def test_public_withdrawal_and_privileged_call_keep_separate_authority(artifact):
    _, trees, _ = artifact
    ctx = EvaluationContext(chain_id=1, state_var_values={"owner": OWNER})
    aggregate, scopes = _resolve(trees, "mixed(bool,address,bytes,uint256)", ctx)
    assert aggregate is not None
    assert aggregate is not None
    result = capability_to_dict(aggregate)
    assert capability_surface_openness(result, project_capability_surface(result)) == "open"
    call_scopes = [s for s in scopes if s["kind"] == "external_call"]
    outcomes = {
        s["target"]: capability_surface_openness(s["capability"], project_capability_surface(s["capability"]))
        for s in call_scopes
    }
    assert outcomes["target.call"] == "restricted", scopes
    assert outcomes["msg.sender.call"] == "open", scopes


def test_zero_write_is_not_unconditionally_a_revocation():
    from services.static.contract_analysis_pipeline.structural_evidence import acceptance_transition

    assert acceptance_transition("NOT_EQUAL", 0, 0) == "revokes"
    assert acceptance_transition("EQUAL", 0, 0) == "may_grant"
    assert acceptance_transition("GREATER_EQUAL", 3, 2) == "revokes"
    assert acceptance_transition("GREATER_EQUAL", 3, 4) == "may_grant"
    assert acceptance_transition("NOT_EQUAL", 0, None) == "unknown"


def test_scheduled_action_keeps_scheduler_authority_after_consumption(artifact):
    _, trees, _ = artifact
    ctx = EvaluationContext(chain_id=1, state_var_values={"owner": OWNER})
    aggregate, scopes = _resolve(trees, "run(address,bytes)", ctx)
    assert aggregate is not None
    result = capability_to_dict(aggregate)
    surface = project_capability_surface(result)
    assert capability_surface_openness(result, surface) == "restricted", scopes
    assert {r["address"] for r in surface.principal_rows} == {OWNER}


def test_claim_uses_its_effect_scope_instead_of_the_public_sibling(artifact):
    from services.policy.effect_authority import scope_claim_authority

    _, trees, effects = artifact
    signature = "mixed(bool,address,bytes,uint256)"
    ctx = EvaluationContext(chain_id=1, state_var_values={"owner": OWNER})
    aggregate, scopes = _resolve(trees, signature, ctx)
    assert aggregate is not None
    capability = {**capability_to_dict(aggregate), "effect_capabilities": scopes}
    claims = scope_claim_authority(effects["functions"][signature]["claims"], capability)
    execute = next(c for c in claims if c["claim_id"] == "exec.arbitrary")
    authority = execute["witness"]["effect_authority"]
    assert authority["openness"] == "restricted", authority
    assert authority["principal_addresses"] == [OWNER]


@pytest.mark.parametrize(
    "mutation,proven",
    [
        (None, True),
        (("require(participants[msg.sender] != address(0));", ""), False),
        (("person == msg.sender || approvals[action][person] != 0", "person == msg.sender || true"), False),
        (("count++;", "count += 2;"), False),
    ],
)
def test_counted_authority_requires_real_distinct_approvals(tmp_path, mutation, proven):
    source = FIXTURE.with_name("counted_permissions.sol").read_text()
    if mutation:
        source = source.replace(*mutation)
    project = write_foundry_project(tmp_path, "CountedPermissions", source)
    _, trees, _ = collect_contract_analysis_with_artifacts(project)
    assert trees is not None
    tree = trees["trees"]["execute(address,bytes)"]

    def descriptors(node):
        descriptor = (node.get("leaf") or {}).get("set_descriptor") or {}
        yield descriptor
        for child in node.get("children", []):
            yield from descriptors(child)

    found = [d for d in descriptors(tree) if d.get("kind") == "authorization_threshold"]
    assert bool(found) is proven
    if not proven and mutation[0] != "person == msg.sender || approvals[action][person] != 0":
        from services.resolution.predicate_evaluator import evaluate_tree_with_registry

        cap = capability_to_dict(evaluate_tree_with_registry(tree, AdapterRegistry(), EvaluationContext(chain_id=1)))
        assert capability_surface_openness(cap, project_capability_surface(cap)) == "not_determined"
    if proven:
        assert found[0]["bound_parameters"] == [0, 1]
        assert found[0]["count_proof"]["distinctness"] == "unique_registry_traversal"


def test_cyclic_state_requirements_do_not_become_public(tmp_path):
    source = """pragma solidity ^0.8.19;
contract Circular {
 mapping(bytes32 => uint256) a; mapping(bytes32 => uint256) b;
 function grantA(bytes32 key) external { require(b[key] != 0); a[key] = 1; }
 function grantB(bytes32 key) external { require(a[key] != 0); b[key] = 1; }
 function execute(address target, bytes calldata payload) external {
  require(a[keccak256(payload)] != 0); (bool ok,) = target.call(payload); require(ok);
 }
}"""
    project = write_foundry_project(tmp_path, "Circular", source)
    _, trees, _ = collect_contract_analysis_with_artifacts(project)
    assert trees is not None
    aggregate, _ = _resolve(trees, "execute(address,bytes)", EvaluationContext(chain_id=1))
    assert aggregate is not None
    cap = capability_to_dict(aggregate)
    assert capability_surface_openness(cap, project_capability_surface(cap)) == "not_determined"


def test_bound_enum_argument_prunes_the_unreachable_effect(tmp_path):
    source = """pragma solidity ^0.8.19;
contract Router {
 enum Operation { Call, Delegate }
 function execute(address target, bytes memory payload) public { route(Operation.Delegate, target, payload); }
 function route(Operation op, address target, bytes memory payload) internal {
  if (op == Operation.Call) { (bool ok,) = target.call(payload); require(ok); }
  else { (bool ok,) = target.delegatecall(payload); require(ok); }
 }
}"""
    project = write_foundry_project(tmp_path, "Router", source)
    _, trees, effects = collect_contract_analysis_with_artifacts(project)
    assert trees is not None and effects is not None
    sites = trees["effect_scopes"]["execute(address,bytes)"]
    assert any(s["kind"] == "delegatecall" for s in sites)
    assert not any(s["kind"] == "external_call" for s in sites)
    assert not any(c["claim_id"] == "exec.arbitrary" for c in effects["functions"]["execute(address,bytes)"]["claims"])


@pytest.mark.parametrize(
    "body",
    [
        "if (choice) { require(msg.sender == first); } else { require(msg.sender == second); }",
        "if (choice) { require(msg.sender == first); } if (!choice) { require(msg.sender == second); }",
    ],
)
def test_guards_before_a_join_preserve_correlated_alternatives(tmp_path, body):
    source = """pragma solidity ^0.8.19; contract Joined {
 address first; address second;
 function execute(bool choice, address target, bytes memory data) external {
 BODY
 (bool ok,) = target.call(data); require(ok);
 }
}""".replace("BODY", body)
    project = write_foundry_project(tmp_path, "Joined", source)
    _, trees, _ = collect_contract_analysis_with_artifacts(project)
    assert trees is not None
    ctx = EvaluationContext(chain_id=1, state_var_values={"first": "0x" + "11" * 20, "second": "0x" + "22" * 20})
    aggregate, _ = _resolve(trees, "execute(bool,address,bytes)", ctx)
    assert aggregate is not None
    cap = capability_to_dict(aggregate)
    surface = project_capability_surface(cap)
    assert capability_surface_openness(cap, surface) == "restricted", cap
    assert {p["address"] for p in surface.principal_rows} == {"0x" + "11" * 20, "0x" + "22" * 20}


def test_role_membership_is_not_public_when_member_inventory_is_unknown(artifact):
    _, trees, _ = artifact
    aggregate, _ = _resolve(trees, "mint(uint256)", EvaluationContext(chain_id=1))
    assert aggregate is not None
    cap = capability_to_dict(aggregate)
    assert capability_surface_openness(cap, project_capability_surface(cap)) == "not_determined"


def test_proven_public_bypass_survives_conditional_private_guard(tmp_path):
    source = """pragma solidity ^0.8.19; contract Bypass {
 address owner;
 function execute(bool privatePath, address target, bytes memory data) external {
  if (privatePath) { require(msg.sender == owner); }
  (bool ok,) = target.call(data); require(ok);
 }
}"""
    project = write_foundry_project(tmp_path, "Bypass", source)
    _, trees, _ = collect_contract_analysis_with_artifacts(project)
    assert trees is not None
    ctx = EvaluationContext(chain_id=1, state_var_values={"owner": OWNER})
    aggregate, _ = _resolve(trees, "execute(bool,address,bytes)", ctx)
    assert aggregate is not None
    cap = capability_to_dict(aggregate)
    assert capability_surface_openness(cap, project_capability_surface(cap)) == "open"


def test_call_depth_limit_is_an_obligation_not_an_empty_public_result(tmp_path):
    helpers = "\n".join(
        f"function step{i}(address target, bytes memory data) internal {{ step{i + 1}(target, data); }}"
        for i in range(10)
    )
    source = """pragma solidity ^0.8.19; contract Deep {
 address owner;
 function execute(address target, bytes memory data) external { step0(target, data); }
 HELPERS
 function step10(address target, bytes memory data) internal {
  require(msg.sender == owner); (bool ok,) = target.call(data); require(ok);
 }
}""".replace("HELPERS", helpers)
    project = write_foundry_project(tmp_path, "Deep", source)
    _, trees, _ = collect_contract_analysis_with_artifacts(project)
    assert trees is not None
    sites = trees["effect_scopes"]["execute(address,bytes)"]
    assert any(s["kind"] == "unresolved_effect" for s in sites)
    aggregate, _ = _resolve(trees, "execute(address,bytes)", EvaluationContext(chain_id=1))
    assert aggregate is not None
    cap = capability_to_dict(aggregate)
    assert capability_surface_openness(cap, project_capability_surface(cap)) == "not_determined"


def test_counting_with_a_callback_does_not_assume_an_unchanged_registry(tmp_path):
    source = (
        FIXTURE.with_name("counted_permissions.sol")
        .read_text()
        .replace("count++;", 'count++;\n                msg.sender.call("");')
    )
    project = write_foundry_project(tmp_path, "CountedPermissions", source)
    _, trees, _ = collect_contract_analysis_with_artifacts(project)
    assert trees is not None
    from services.resolution.predicate_evaluator import evaluate_tree_with_registry

    cap = capability_to_dict(
        evaluate_tree_with_registry(
            trees["trees"]["execute(address,bytes)"], AdapterRegistry(), EvaluationContext(chain_id=1)
        )
    )
    assert capability_surface_openness(cap, project_capability_surface(cap)) == "not_determined"


def test_missing_effect_predicate_is_not_a_public_path():
    sites = [{"id": "missing", "kind": "external_call", "target": "x", "sink_ids": [], "origin": "body"}]
    cap, _ = resolve_effect_scopes(sites, AdapterRegistry(), EvaluationContext(chain_id=1))
    assert cap is not None
    data = capability_to_dict(cap)
    assert capability_surface_openness(data, project_capability_surface(data)) == "not_determined"
