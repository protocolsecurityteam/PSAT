"""Version fixtures are independent execution oracles, never production recognition rules."""

from __future__ import annotations

import pytest

from services.policy.capability_surface import capability_surface_openness, project_capability_surface
from services.resolution.adapters import AdapterRegistry, EvaluationContext
from services.resolution.adapters.authorization import AuthorizationAdapter
from services.resolution.capability_resolver import capability_to_dict
from services.resolution.predicate_evaluator import evaluate_tree_with_registry
from tests.support.anvil import _start_anvil, _terminate
from tests.support.canonical_safe import EXEC, call, calldata, deploy_safe, rpc, send

pytestmark = [pytest.mark.compile, pytest.mark.anvil]


@pytest.mark.parametrize("version,l2", [("1.3.0", False), ("1.3.0", True), ("1.4.1", False), ("1.4.1", True)])
@pytest.mark.parametrize("broken", [False, True], ids=["authenticated", "authentication-removed"])
def test_original_compiler_versions_publish_the_authority_they_execute(tmp_path, version, l2, broken):
    proc, port = _start_anvil()
    try:
        safe = deploy_safe(
            tmp_path, f"http://127.0.0.1:{port}", broken=broken, version=version, l2=l2, compiler="0.7.6"
        )
        if not broken:
            with pytest.raises(RuntimeError, match="GS020"):
                call(
                    safe.url,
                    safe.address,
                    EXEC,
                    safe.args() + [safe.signatures(safe.args(), (0, 1))],
                    sender=safe.relayer,
                )
        signatures = b"" if broken else safe.signatures(safe.args())
        receipt = send(safe.url, safe.relayer, calldata(EXEC, safe.args() + [signatures]), safe.address)
        assert int(receipt["status"], 16) == 1
        assert safe.value() == 42
        registry = AdapterRegistry()
        registry.register(AuthorizationAdapter)
        ctx = EvaluationContext(
            chain_id=1,
            contract_address=safe.address,
            rpc_url=safe.url,
            block=int(rpc(safe.url, "eth_blockNumber", []), 16),
        )
        tree = next(t for sig, t in safe.trees["trees"].items() if sig.startswith("execTransaction("))
        cap = capability_to_dict(evaluate_tree_with_registry(tree, registry, ctx))
        surface = project_capability_surface(cap)
        assert capability_surface_openness(cap, surface) == ("open" if broken else "restricted")
        if not broken:
            assert cap["kind"] == "threshold_group"
            assert cap["threshold"]["m"] == 3
            assert set(cap["threshold"]["signers"]) == set(safe.owners)
            assert len(surface.principal_rows) == 1
            assert surface.principal_rows[0]["address"] == safe.address
            record = next(r for sig, r in safe.effects["functions"].items() if sig.startswith("execTransaction("))
            claims = record["claims"]
            arbitrary = next(c for c in claims if c["claim_id"] == "exec.arbitrary")
            assert arbitrary["witness"]["destination_constraint"]["guard"] == "signature_witness"
    finally:
        _terminate(proc)


def test_overwritten_target_binding_agrees_with_actual_execution(tmp_path):
    import json
    from pathlib import Path

    from eth_abi.abi import encode
    from eth_account import Account

    from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts
    from tests.support.canonical_safe import MNEMONIC
    from tests.support.foundry_project import write_foundry_project

    fixture = Path(__file__).resolve().parents[1] / "fixtures/contracts/authorization/generic_quorum_wallet.sol"
    source = fixture.read_text().replace(
        "digest := keccak256(ptr, 96)", "mstore(ptr, 0)\n            digest := keccak256(ptr, 96)"
    )
    project = write_foundry_project(tmp_path, "GenericQuorumWallet", source)
    _, _, effects = collect_contract_analysis_with_artifacts(project)
    assert effects is not None
    claims = effects["functions"]["execute(address,bytes,uint256,bytes)"]["claims"]
    arbitrary = next(c for c in claims if c["claim_id"] == "exec.arbitrary")
    assert arbitrary["witness"]["destination_constraint"].get("guard") != "signature_witness"
    proc, port = _start_anvil()
    try:
        url = f"http://127.0.0.1:{port}"
        accounts = rpc(url, "eth_accounts", [])
        artifact = json.loads((project / "out/GenericQuorumWallet.sol/GenericQuorumWallet.json").read_text())
        code = artifact["bytecode"]["object"].removeprefix("0x")
        receipt = send(url, accounts[0], "0x" + code + encode(["address[]", "uint256"], [[accounts[0]], 1]).hex())
        assert int(receipt["status"], 16) == 1
        address = receipt["contractAddress"]
        hashes = [
            call(url, address, "actionDigest(address,bytes,uint256)", [target, b"", 1], ["bytes32"])[0]
            for target in accounts[1:3]
        ]
        assert hashes[0] == hashes[1]
        Account.enable_unaudited_hdwallet_features()
        signer = Account.from_mnemonic(MNEMONIC, account_path="m/44'/60'/0'/0/0")
        signature = bytes(Account.unsafe_sign_hash(hashes[0], private_key=signer.key).signature)
        # An outsider can redirect the signed request to the other target. The analyzer must not credit target binding.
        receipt = send(
            url,
            accounts[9],
            calldata("execute(address,bytes,uint256,bytes)", [accounts[2], b"", 1, signature]),
            address,
        )
        assert int(receipt["status"], 16) == 1
    finally:
        _terminate(proc)
