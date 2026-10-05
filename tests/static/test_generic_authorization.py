from __future__ import annotations

from pathlib import Path

import pytest

from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts
from tests.support.foundry_project import write_foundry_project

pytestmark = pytest.mark.compile

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "contracts" / "authorization" / "generic_quorum_wallet.sol"


def _tree(tmp_path, replacements=()):
    source = FIXTURE.read_text()
    for old, new in replacements:
        source = source.replace(old, new)
    project = write_foundry_project(tmp_path, "GenericQuorumWallet", source)
    _, trees, _ = collect_contract_analysis_with_artifacts(project)
    assert trees is not None
    tree = trees["trees"]["execute(address,bytes,uint256,bytes)"]

    return tree


def _descriptor(tmp_path, replacements=()):
    tree = _tree(tmp_path, replacements)

    def find(node):
        descriptor = (node.get("leaf") or {}).get("set_descriptor") or {}
        if descriptor.get("kind") == "signature_threshold":
            return descriptor
        return next((found for child in node.get("children") or [] if (found := find(child)) is not None), None)

    return find(tree)


def test_custom_error_quorum_and_assembly_hash_are_derived_from_structure(tmp_path):
    descriptor = _descriptor(tmp_path)
    assert descriptor is not None
    assert descriptor["threshold"]["variable"] == "minimumApprovals"
    assert descriptor["registry"]["variable"] == "signerLinks"
    assert descriptor["bound_parameters"] == [0, 1, 2]
    assert descriptor["requires_positive"] is True


@pytest.mark.parametrize(
    "old,new",
    [
        ("signerLinks[candidate] == address(0) || ", ""),
        ("candidate <= previous || ", ""),
    ],
)
def test_quorum_structure_withholds_when_membership_or_distinctness_is_removed(tmp_path, old, new):
    assert _descriptor(tmp_path, [(old, new)]) is None


def test_hash_binding_withholds_parameters_removed_from_the_digest(tmp_path):
    descriptor = _descriptor(tmp_path, [("mstore(add(ptr, 64), actionNonce)", "mstore(add(ptr, 64), 0)")])
    assert descriptor is not None
    assert descriptor["bound_parameters"] == [0, 1]


@pytest.mark.parametrize(
    "replacement,expected",
    [
        ("mstore(ptr, 0)\n digest := keccak256(ptr, 96)", [1, 2]),
        ("mstore8(add(ptr, 31), 0)\n digest := keccak256(ptr, 96)", [1, 2]),
        ("mstore(add(ptr, 16), 0)\n digest := keccak256(ptr, 96)", [2]),
        ("digest := keccak256(ptr, 65)", [0, 1]),
        ("digest := keccak256(ptr, 96)\n mstore(ptr, 0)", [0, 1, 2]),
        ("calldatacopy(ptr, 0, 32)\n digest := keccak256(ptr, 96)", [1, 2]),
        ("calldatacopy(ptr, 0, 0)\n digest := keccak256(ptr, 96)", [0, 1, 2]),
        ("mstore(add(ptr, actionNonce), 0)\n digest := keccak256(ptr, 96)", []),
        ("if actionNonce { mstore(ptr, 0) }\n digest := keccak256(ptr, 96)", []),
    ],
    ids=[
        "overwrite",
        "byte-overwrite",
        "overlap",
        "partial-word",
        "after-hash",
        "copy",
        "empty-copy",
        "alias",
        "branch",
    ],
)
def test_assembly_binding_requires_complete_surviving_words(tmp_path, replacement, expected):
    descriptor = _descriptor(tmp_path, [("digest := keccak256(ptr, 96)", replacement)])
    assert descriptor is not None
    assert descriptor["bound_parameters"] == expected


def _assert_unresolved(tree, monkeypatch):
    from services.policy.capability_surface import capability_surface_openness, project_capability_surface
    from services.resolution.adapters import AdapterRegistry, EvaluationContext
    from services.resolution.adapters.authorization import AuthorizationAdapter
    from services.resolution.capabilities import CapabilityExpr
    from services.resolution.capability_resolver import capability_to_dict
    from services.resolution.predicate_evaluator import evaluate_tree_with_registry

    # Even a successful inventory cannot lend authority to a recovered signer without a quorum proof.
    monkeypatch.setattr(AuthorizationAdapter, "matches", classmethod(lambda cls, descriptor, ctx: 100))
    monkeypatch.setattr(AuthorizationAdapter, "enumerate", lambda *args: CapabilityExpr.finite_set(["0x" + "11" * 20]))
    registry = AdapterRegistry()
    registry.register(AuthorizationAdapter)
    cap = capability_to_dict(evaluate_tree_with_registry(tree, registry, EvaluationContext(chain_id=1)))
    surface = project_capability_surface(cap)
    assert capability_surface_openness(cap, surface) == "not_determined", cap
    assert not surface.principal_rows
    assert not surface.public_paths


def test_unrecognized_signer_loop_never_publishes_individual_owners(tmp_path, monkeypatch):
    tree = _tree(tmp_path, [("candidate <= previous || ", "")])
    _assert_unresolved(tree, monkeypatch)


def test_passthrough_override_keeps_parent_authentication(tmp_path):
    source = FIXTURE.read_text().replace("contract GenericQuorumWallet", "contract ParentWallet")
    source = source.replace("        external\n", "        public virtual\n", 1)
    source += """
contract GenericQuorumWallet is ParentWallet {
    constructor(address[] memory signers, uint256 minimum) ParentWallet(signers, minimum) {}
    function execute(address target, bytes calldata payload, uint256 actionNonce, bytes calldata signatures)
        public override
    {
        super.execute(target, payload, actionNonce, signatures);
    }
}
"""
    descriptor = _descriptor(tmp_path, [(FIXTURE.read_text(), source)])
    assert descriptor is not None
    assert descriptor["bound_parameters"] == [0, 1, 2]


def _external_signer_variant():
    return [
        (
            "contract GenericQuorumWallet",
            "interface Validator { function verify(bytes calldata message, bytes calldata proof) "
            "external view returns (bytes4); }\ncontract GenericQuorumWallet",
        ),
        (
            "bytes32 digest = actionDigest(target, payload, actionNonce);",
            "bytes memory encoded = abi.encode(target, payload, actionNonce);\nbytes32 digest = keccak256(encoded);",
        ),
        (
            "validateBundle(msg.sender, digest, signatures, minimumApprovals);",
            "validateBundle(msg.sender, digest, signatures, minimumApprovals, encoded);",
        ),
        (
            "bytes calldata signatures, uint256 needed) public view",
            "bytes calldata signatures, uint256 needed, bytes memory encoded) public view",
        ),
        (
            "address candidate = ecrecover(digest, v, r, s);",
            """address candidate;
            if (v == 0) {
                candidate = address(uint160(uint256(r)));
                require(Validator(candidate).verify(encoded, signatures) == bytes4(0x12345678));
            } else {
                candidate = ecrecover(digest, v, r, s);
            }""",
        ),
    ]


def test_external_signer_payload_binding_follows_actual_arguments(tmp_path):
    descriptor = _descriptor(tmp_path, _external_signer_variant())
    assert descriptor is not None
    assert descriptor["modes"] == ["ecdsa", "external"]
    assert descriptor["bound_parameters"] == [0, 1, 2]


def test_same_parameter_taint_does_not_prove_identical_signed_message(tmp_path, monkeypatch):
    replacements = _external_signer_variant() + [
        ("minimumApprovals, encoded);", "minimumApprovals, abi.encode(target, payload, actionNonce + 1));")
    ]
    assert _descriptor(tmp_path / "descriptor", replacements) is None
    _assert_unresolved(_tree(tmp_path / "resolution", replacements), monkeypatch)


def test_payload_binding_survives_another_helper_frame(tmp_path):
    replacements = _external_signer_variant() + [
        (
            "        if (needed == 0 || signatures.length < needed * 65)",
            """        verifyInner(digest, signatures, needed, encoded);
    }
    function verifyInner(bytes32 digest, bytes calldata signatures, uint256 needed, bytes memory encoded)
        internal view {
        if (needed == 0 || signatures.length < needed * 65)""",
        ),
    ]
    descriptor = _descriptor(tmp_path, replacements)
    assert descriptor is not None
    assert descriptor["bound_parameters"] == [0, 1, 2]


@pytest.mark.parametrize(
    "mutation",
    ["encoded[0] = bytes1(uint8(1));", "delete encoded[0];", "encoded = abi.encode(target, payload, actionNonce + 1);"],
)
def test_mutated_preimage_cannot_borrow_the_original_digest_binding(tmp_path, mutation):
    replacements = _external_signer_variant() + [
        (
            "validateBundle(msg.sender, digest, signatures, minimumApprovals, encoded);",
            mutation + "\nvalidateBundle(msg.sender, digest, signatures, minimumApprovals, encoded);",
        ),
    ]
    assert _descriptor(tmp_path, replacements) is None


@pytest.mark.parametrize("checked", [True, False], ids=["checked-return", "ignored-return"])
def test_boolean_verifier_only_contributes_facts_when_its_result_is_required(tmp_path, checked):
    replacements = [
        ("uint256 needed) public view {", "uint256 needed) public view returns (bool) {"),
        ("revert InvalidAuthorization();", "return false;"),
        ("previous = candidate;\n        }", "previous = candidate;\n        }\n        return true;"),
    ]
    if checked:
        replacements.append(
            (
                "validateBundle(msg.sender, digest, signatures, minimumApprovals);",
                "require(validateBundle(msg.sender, digest, signatures, minimumApprovals));",
            )
        )
    descriptor = _descriptor(tmp_path, replacements)
    assert (descriptor is not None) is checked


def test_recovery_helper_and_separate_guards_compose(tmp_path):
    replacements = [
        ("address candidate = ecrecover(digest, v, r, s);", "address candidate = recoverIdentity(digest, v, r, s);"),
        ("candidate <= previous || ", ""),
        (
            "if (signerLinks[candidate]",
            "if (candidate <= previous) revert InvalidAuthorization();\n            if (signerLinks[candidate]",
        ),
        (
            "    function split(",
            "    function recoverIdentity(bytes32 h, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) "
            "{ return ecrecover(h, v, r, s); }\n    function split(",
        ),
    ]
    descriptor = _descriptor(tmp_path, replacements)
    assert descriptor is not None
    assert descriptor["bound_parameters"] == [0, 1, 2]


def test_resetting_order_accumulator_does_not_prove_distinct_signers(tmp_path):
    assert (
        _descriptor(
            tmp_path,
            [("address candidate = ecrecover", "previous = address(0);\n            address candidate = ecrecover")],
        )
        is None
    )


def test_boolean_contract_approval_ignores_paths_the_caller_rejects(tmp_path):
    replacements = _external_signer_variant() + [
        ("returns (bytes4);", "returns (bool);"),
        ("bytes memory encoded) public view {", "bytes memory encoded) public view returns (bool) {"),
        (
            "require(Validator(candidate).verify(encoded, signatures) == bytes4(0x12345678));",
            "if (!Validator(candidate).verify(encoded, signatures)) return false;",
        ),
        ("revert InvalidAuthorization();", "return false;"),
        ("previous = candidate;\n        }", "previous = candidate;\n        }\n        return true;"),
        (
            "validateBundle(msg.sender, digest, signatures, minimumApprovals, encoded);",
            "require(validateBundle(msg.sender, digest, signatures, minimumApprovals, encoded));",
        ),
    ]
    descriptor = _descriptor(tmp_path, replacements)
    assert descriptor is not None
    assert descriptor["modes"] == ["ecdsa", "external"]


@pytest.mark.parametrize(
    "change",
    [
        "minimumApprovals = 1;",
        "rewriteMinimum();",
    ],
)
def test_storage_changed_before_validation_does_not_use_the_pinned_threshold(tmp_path, change):
    replacements = [
        (
            "validateBundle(msg.sender, digest, signatures, minimumApprovals);",
            change + "\nvalidateBundle(msg.sender, digest, signatures, minimumApprovals);",
        ),
        (
            "    function split(",
            "    function rewriteMinimum() internal { minimumApprovals = 1; }\n    function split(",
        ),
    ]
    tree = _tree(tmp_path, replacements)

    def find(node):
        d = (node.get("leaf") or {}).get("set_descriptor") or {}
        return (
            d
            if d.get("kind") == "authorization_unresolved"
            else next((x for c in node.get("children", []) if (x := find(c))), None)
        )

    descriptor = find(tree)
    assert descriptor is not None
    assert descriptor["missing"] == ["authorization_state_modified_before_check"]
