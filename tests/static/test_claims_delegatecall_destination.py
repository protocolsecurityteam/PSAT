"""``delegatecall.execute`` destination resolution, per destination kind.

The self arm is the one this module was added for: a literal ``address(this)``
destination is a compile-time value that no writer and no caller can redirect,
so it must publish the proven ``self`` kind with a proven-constrained
``destination_constraint``. It reaches the opcode two ways — directly, and (the
OZ v5 ``Multicall`` shape) through a library formal — and both must earn the
same answer.

The arms that must NOT be affected are asserted beside it in the same compile:
a caller-named destination stays ``param``, a storage-held one stays
``storage_setter`` with its writer, and ``msg.sender`` — a solidity variable
like ``this``, but not this contract — stays ``indeterminate``.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

pytest.importorskip("slither")

from tests.support.foundry_project import write_foundry_project  # noqa: E402

_SRC = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

library Address {
    // OpenZeppelin ``Address.functionDelegateCall``: the destination reaches the
    // opcode as this library's own formal.
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        (bool ok, bytes memory ret) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        return ret;
    }
}

contract DelegatecallDestinations {
    address public owner;
    address public module;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // The OZ v5 ``Multicall`` shape: batched delegatecall to address(this).
    function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            results[i] = Address.functionDelegateCall(address(this), data[i]);
        }
    }

    // The same destination, reached without the library.
    function selfCall(bytes calldata data) external {
        (bool ok, ) = address(this).delegatecall(data);
        require(ok, "self call failed");
    }

    // Caller-named destination.
    function execTarget(address target, bytes calldata data) external onlyOwner {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "target call failed");
    }

    // Storage-held destination with a setter.
    function execModule(bytes calldata data) external onlyOwner {
        (bool ok, ) = module.delegatecall(data);
        require(ok, "module call failed");
    }

    function setModule(address newModule) external onlyOwner {
        module = newModule;
    }

    // A solidity variable that is NOT this contract.
    function execSender(bytes calldata data) external onlyOwner {
        (bool ok, ) = msg.sender.delegatecall(data);
        require(ok, "sender call failed");
    }
}
"""

_CONTRACT = "DelegatecallDestinations"


@pytest.fixture(scope="module")
def witnesses(tmp_path_factory) -> dict[str, dict]:
    """``{signature: delegatecall.execute witness}`` from the real static
    pipeline — Slither, effects, and the production claims phase."""
    from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts

    project_dir = write_foundry_project(
        tmp_path_factory.mktemp("delegatecall_destinations"),
        _CONTRACT,
        textwrap.dedent(_SRC).strip() + "\n",
    )
    assert Path(project_dir, "src", f"{_CONTRACT}.sol").exists()
    _analysis, _trees, effects = collect_contract_analysis_with_artifacts(project_dir)
    assert effects is not None and "functions" in effects

    out: dict[str, dict] = {}
    for signature, record in effects["functions"].items():
        for claim in record.get("claims") or []:
            if claim["claim_id"] == "delegatecall.execute":
                out[signature] = claim["witness"]
    assert out, "the fixture minted no delegatecall.execute claim at all"
    return out


@pytest.mark.parametrize("signature", ["multicall(bytes[])", "selfCall(bytes)"])
def test_address_this_destinations_resolve_to_self(witnesses, signature):
    """Both routes to ``address(this)``. Before the self recognizer these fell
    through to the catch-all and published ``unresolved_operand`` for a
    compile-time constant."""
    assert witnesses[signature]["destination"]["target_kind"] == "self"


@pytest.mark.parametrize("signature", ["multicall(bytes[])", "selfCall(bytes)"])
def test_a_self_destination_carries_a_proven_constrained_verdict(witnesses, signature):
    """``self`` is a PROVEN fixed destination, so its constraint is earned on the
    destination operand — not the ``not_determined`` the unsettled kinds get."""
    assert witnesses[signature]["destination_constraint"] == {
        "state": "constrained",
        "guard": "literal_self",
        "pins": True,
        "binding": "destination_operand",
    }


def test_the_claim_still_fires_on_a_self_destination(witnesses):
    """Only the destination moved: a delegatecall IS happening either way, and
    the sink evidence has to stay attached to say so."""
    for signature in ("multicall(bytes[])", "selfCall(bytes)"):
        witness = witnesses[signature]
        assert witness["kind"] == "delegatecall_sink"
        assert witness["sink_ids"]


def test_a_caller_named_destination_still_resolves_to_its_param(witnesses):
    """The negative guard: the caller supplies this destination, and the self
    branch must not swallow it."""
    witness = witnesses["execTarget(address,bytes)"]
    assert witness["destination"]["target_kind"] == "param"
    assert witness["destination"]["variable"] == "target"
    assert witness["destination_constraint"]["state"] != "constrained"


def test_a_storage_held_destination_still_resolves_to_its_setter(witnesses):
    """The other negative guard: whoever passes ``setModule``'s gate owns this
    contract's storage, and that stays visible."""
    witness = witnesses["execModule(bytes)"]
    assert witness["destination"]["target_kind"] == "storage_setter"
    assert witness["destination"]["variable"] == "module"
    assert witness["destination"]["writer_signatures"] == ["setModule(address)"]
    assert witness["destination_constraint"] == {"state": "not_determined"}


def test_msg_sender_is_not_read_as_self(witnesses):
    """``msg.sender`` is a solidity variable too. Recognising the CLASS rather
    than the name would hand a caller-controlled destination the strongest
    verdict on the field."""
    witness = witnesses["execSender(bytes)"]
    assert witness["destination"]["target_kind"] == "indeterminate"
    assert witness["destination_constraint"] == {"state": "not_determined"}
