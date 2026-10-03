from __future__ import annotations

from pathlib import Path

import pytest

from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts
from tests.support.foundry_project import write_foundry_project

pytestmark = pytest.mark.compile

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "contracts" / "authorization" / "generic_quorum_wallet.sol"


def _descriptor(tmp_path, replacements=()):
    source = FIXTURE.read_text()
    for old, new in replacements:
        source = source.replace(old, new)
    project = write_foundry_project(tmp_path, "GenericQuorumWallet", source)
    _, trees, _ = collect_contract_analysis_with_artifacts(project)
    assert trees is not None
    tree = trees["trees"]["execute(address,bytes,uint256,bytes)"]

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
