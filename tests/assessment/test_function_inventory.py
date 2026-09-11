"""Identity and useful partial analysis survive the consolidated pipeline."""

from collections.abc import Mapping
from typing import Any

import pytest
from eth_utils.crypto import keccak

from db.queue.typed import ArtifactSchemaError, validate_assessment
from services.assessment import add_policy, build_static_assessment, project_permission_index
from tests.conftest import requires_postgres
from tests.support.policy_builders import _minimal_static_facts
from tests.support.policy_builders import assessed_permissions as build_permission_index


def build(effects: Mapping[str, Any], trees: Mapping[str, Any]):
    return build_static_assessment(
        chain_id=1,
        address="0x" + "11" * 20,
        contract_name="C",
        code_hash=None,
        source_hash=None,
        static_facts=_minimal_static_facts(),
        effects=effects,
        predicate_trees=trees,
    )


def test_effect_failure_keeps_predicate_function_and_unsupported_policy():
    trees = {"trees": {"f()": {"op": "AND", "children": []}}, "canonical_signatures": {"f()": "f()"}}
    assessment = build({"error": "effect analyzer crashed"}, trees)
    assert assessment["functions"]["f()"]["state_changing"] is None
    permissions = build_permission_index(_minimal_static_facts(), predicate_trees=trees, effects={"error": "crashed"})
    result = add_policy(assessment, permissions["functions"], chain_id=1)
    assert project_permission_index(result)["functions"][0]["function"] == "f()"
    assert not any("function_not_found" in item["reason"] for item in result["analyses"][-1]["omissions"])


@pytest.mark.parametrize(
    "source,canonical",
    [
        ("setMode(C.Mode)", "setMode(uint8)"),
        ("execute(C.Order)", "execute((uint256,address))"),
        ("setFoo(IFoo)", "setFoo(address)"),
    ],
)
def test_canonical_signature_overrides_source_spelling(source, canonical):
    assessment = build(
        {"functions": {source: {"abi_signature": source, "selector": "0xdeadbeef"}}},
        {"trees": {}, "canonical_signatures": {source: canonical}},
    )
    selector = "0x" + keccak(text=canonical).hex()[:8]
    result = add_policy(
        assessment,
        {"functions": [{"function": source, "abi_signature": canonical, "selector": selector}]}["functions"],
        chain_id=1,
    )
    row = project_permission_index(result)["functions"][0]
    assert (row["abi_signature"], row["selector"]) == (canonical, selector)


def test_storage_rejects_mismatched_identity():
    assessment = build({"functions": {"f()": {}}}, {"trees": {}})
    assessment["functions"]["f()"]["selector"] = "0xdeadbeef"
    with pytest.raises(ArtifactSchemaError, match="does not match ABI signature"):
        validate_assessment(assessment)


def test_unknown_source_type_does_not_publish_a_fabricated_dispatch():
    assessment = build({"functions": {"f(C.Unknown)": {"selector": "0xdeadbeef"}}}, {"error": "predicate crash"})
    assert assessment["functions"]["f(C.Unknown)"] == {"abi_signature": None, "selector": None, "state_changing": None}


@pytest.mark.parametrize("signature", ["f(uintThing)", "f(bytes33)", "f(uint7)", "f(uint256[)", "f(,uint256)"])
def test_malformed_or_unknown_abi_tokens_have_no_identity(signature):
    from services.abi import function_identity

    assert function_identity(signature) == (None, None)


@requires_postgres
def test_unknown_abi_stays_unknown_in_permission_index(db_session):
    from db.models import Contract, EffectiveFunction
    from services.policy.permission_index_writer import write_permission_rows

    assessment = build({"functions": {"f(C.Unknown)": {}}}, {"error": "predicate crash"})
    assessment = add_policy(
        assessment, {"functions": [{"function": "f(C.Unknown)", "status": "unsupported"}]}["functions"], chain_id=1
    )
    contract = Contract(address="0x" + "11" * 20, chain="ethereum", contract_name="C")
    db_session.add(contract)
    db_session.flush()
    write_permission_rows(
        db_session, contract_id=contract.id, function_records=project_permission_index(assessment)["functions"]
    )
    row = db_session.query(EffectiveFunction).filter_by(contract_id=contract.id).one()
    assert row.abi_signature is None
    assert row.selector is None


@pytest.mark.compile
@pytest.mark.parametrize("predicate_failure", [False, True])
def test_compiled_user_types_through_policy_projection(tmp_path, predicate_failure):
    from slither import Slither

    from services.static.static_analysis.effects import build_effects
    from services.static.static_analysis.predicate_artifacts import build_predicate_artifacts

    source = tmp_path / "C.sol"
    source.write_text("""pragma solidity ^0.8.20;
interface IFoo {}
contract C {
 enum Mode { A, B }
 struct Order { uint256 value; address target; }
 uint256 public value;
 function setMode(Mode mode) external { value = uint256(mode); }
 function execute(Order calldata order) external { value = order.value; }
 function setFoo(IFoo target) external { value = uint160(address(target)); }
}""")
    contract = next(c for c in Slither(str(source)).contracts if c.name == "C")
    effects = build_effects(contract)
    trees = {"error": "predicate analyzer crashed"} if predicate_failure else build_predicate_artifacts(contract)
    assessment = build(effects, trees)
    permissions = build_permission_index(
        _minimal_static_facts(),
        predicate_trees=trees,
        effects=effects,
    )
    result = add_policy(assessment, permissions["functions"], chain_id=1)
    rows = project_permission_index(result)["functions"]
    for canonical in ("setMode(uint8)", "execute((uint256,address))", "setFoo(address)"):
        row = next(row for row in rows if row["abi_signature"] == canonical)
        assert row["selector"] == "0x" + keccak(text=canonical).hex()[:8]
