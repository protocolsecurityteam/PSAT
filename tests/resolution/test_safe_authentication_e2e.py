"""Canonical Safe execution is the independent oracle for the extracted, persisted and scored authority.

The twin keeps every selector/getter but removes the signature check. Both halves must be distinguished;
recognizing the ABI or trusting a manually constructed threshold capability cannot satisfy this regression.
"""

from __future__ import annotations

import shutil
from typing import Any, cast

import pytest

from db.models import Contract, EffectiveFunction, Job, JobStatus, Protocol
from services.policy.capability_surface import capability_surface_openness, project_capability_surface
from services.policy.effective_permissions import build_effective_permissions
from services.policy.effective_permissions_writer import write_effective_function_rows
from services.resolution.adapters import AdapterRegistry, EvaluationContext
from services.resolution.adapters.authorization import AuthorizationAdapter
from services.resolution.capability_resolver import capability_to_dict, resolve_contract_capabilities
from services.resolution.predicate_evaluator import evaluate_tree_with_registry
from services.scoring.cli import distill_protocol_in_memory
from services.scoring.fold import compute_protocol_score
from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts
from tests.conftest import requires_postgres
from tests.support.anvil import _start_anvil, _terminate
from tests.support.canonical_safe import EXEC, call, calldata, deploy_safe, rpc, send

pytestmark = [pytest.mark.compile, pytest.mark.anvil]


@pytest.fixture(scope="module")
def safe_pair(tmp_path_factory):
    proc, port = _start_anvil()
    try:
        root = tmp_path_factory.mktemp("canonical_safe")
        url = f"http://127.0.0.1:{port}"
        yield deploy_safe(root, url, broken=False), deploy_safe(root, url, broken=True)
    finally:
        _terminate(proc)


@pytest.fixture(autouse=True)
def restore_chain(safe_pair):
    url = safe_pair[0].url
    snapshot = rpc(url, "evm_snapshot", [])
    yield
    assert rpc(url, "evm_revert", [snapshot])


def test_canonical_claim_inventory_and_commitments_replace_the_simplified_fixture(safe_pair):
    safe, broken = safe_pair
    records = {sig.split("(", 1)[0]: row for sig, row in safe.effects["functions"].items()}
    expected = {
        "safe.signer_mgmt": ["addOwnerWithThreshold", "removeOwner", "swapOwner", "changeThreshold"],
        "safe.module_mgmt": ["enableModule", "disableModule"],
        "safe.set_guard": ["setGuard"],
        "exec.arbitrary": ["execTransaction", "execTransactionFromModule", "execTransactionFromModuleReturnData"],
    }
    owned_claim_ids = set(expected)
    for claim_id, names in expected.items():
        for name in names:
            claims = [c for c in records[name]["claims"] if c["claim_id"] in owned_claim_ids]
            assert [(c["claim_id"], c["tier"]) for c in claims] == [(claim_id, "standard_exact")]
    assert sum(c["claim_id"] in owned_claim_ids for row in records.values() for c in row["claims"]) == 10
    for name in ("getOwners", "getThreshold"):
        assert not any(c["claim_id"] in owned_claim_ids for c in records[name]["claims"])
    signed = {"state": "constrained", "guard": "signature_witness", "pins": True, "binding": "operand"}
    for claim in records["execTransaction"]["claims"]:
        if claim["claim_id"] == "exec.arbitrary":
            assert {k: claim["witness"]["destination_constraint"][k] for k in signed} == signed
        elif claim["claim_id"] == "flow.out":
            # Real Safe has an indirectly computed gas-refund receiver, unlike the old direct-to.call toy. Preserve
            # the signed commitment wherever a target parameter was actually recovered; don't invent that binding.
            for flow in claim["witness"]["flows"]:
                if (flow.get("target_kind") or {}).get("kind") == "param":
                    assert flow["target_constraint"] == signed
    for name in ("execTransactionFromModule", "execTransactionFromModuleReturnData"):
        for claim in records[name]["claims"]:
            if claim["claim_id"] == "exec.arbitrary":
                assert claim["witness"]["destination_constraint"] == {"state": "unconstrained_proven"}
            elif claim["claim_id"] == "flow.out":
                for flow in claim["witness"]["flows"]:
                    assert (flow.get("target_constraint") or {}).get("guard") != "signature_witness"
    broken_exec = next(row for sig, row in broken.effects["functions"].items() if sig.startswith("execTransaction("))
    for claim in broken_exec["claims"]:
        if claim["claim_id"] == "exec.arbitrary":
            assert claim["witness"]["destination_constraint"].get("guard") != "signature_witness"


OWNER_GUARD = (
    "require(currentOwner > lastOwner && owners[currentOwner] != address(0) && "
    'currentOwner != SENTINEL_OWNERS, "GS026");'
)


@pytest.mark.parametrize(
    "indices,error",
    [((), "GS020"), ((0, 1), "GS020"), ((0, 1, 8), "GS026"), ((0, 0, 1), "GS026"), (None, "GS026")],
    ids=["unsigned", "below-threshold", "non-owner", "duplicate-owner", "invalid-signatures"],
)
def test_canonical_safe_rejects_unauthorized_execution(safe_pair, indices, error):
    safe, _ = safe_pair
    args = safe.args()
    signatures = (b"\x00" * 64 + b"\x1b") * 3 if indices is None else safe.signatures(args, indices) if indices else b""
    before = safe.value()
    with pytest.raises(RuntimeError, match=error):
        call(safe.url, safe.address, EXEC, args + [signatures], sender=safe.relayer)
    receipt = send(safe.url, safe.relayer, calldata(EXEC, args + [signatures]), safe.address)
    assert int(receipt["status"], 16) == 0
    assert safe.value() == before


@pytest.mark.parametrize("changed", ["payload", "target", "signature-order"])
def test_owners_authorize_the_exact_call_and_an_outsider_can_relay_it(safe_pair, changed):
    safe, _ = safe_pair
    args = safe.args()
    signatures = safe.signatures(args)
    assert safe.relayer not in safe.owners
    invalid_args = safe.args(43) if changed == "payload" else list(args)
    invalid_signatures = signatures
    if changed == "target":
        invalid_args[0] = safe.relayer
    elif changed == "signature-order":
        invalid_signatures = signatures[130:] + signatures[65:130] + signatures[:65]
    with pytest.raises(RuntimeError, match="GS026"):
        call(safe.url, safe.address, EXEC, invalid_args + [invalid_signatures], sender=safe.relayer)
    assert int(send(safe.url, safe.relayer, calldata(EXEC, args + [signatures]), safe.address)["status"], 16) == 1
    assert safe.value() == 42


def test_module_execution_requires_an_enabled_module(safe_pair):
    safe, _ = safe_pair
    module_exec = "execTransactionFromModule(address,uint256,bytes,uint8)"
    args = safe.args()[:4]
    with pytest.raises(RuntimeError, match="GS104"):
        call(safe.url, safe.address, module_exec, args, sender=safe.relayer)
    safe.configure("enableModule(address)", [safe.relayer])
    assert int(send(safe.url, safe.relayer, calldata(module_exec, args), safe.address)["status"], 16) == 1
    assert safe.value() == 42


@pytest.mark.parametrize("fault", ["unpinned", "unavailable-block", "malformed-owners", "rpc-error"])
def test_missing_authorization_state_never_projects_as_public(safe_pair, monkeypatch, fault):
    safe, _ = safe_pair
    tree = next(tree for sig, tree in safe.trees["trees"].items() if sig.startswith("execTransaction("))
    registry = AdapterRegistry()
    registry.register(AuthorizationAdapter)
    block = int(rpc(safe.url, "eth_blockNumber", []), 16)
    ctx = EvaluationContext(chain_id=1, contract_address=safe.address, rpc_url=safe.url, block=block)
    if fault == "unpinned":
        ctx.block = None
    elif fault == "unavailable-block":
        ctx.block = block + 1_000_000
    elif fault == "malformed-owners":
        monkeypatch.setattr("services.resolution.adapters.authorization.rpc_request", lambda *a, **k: "0x00")
    else:

        def fail(*args, **kwargs):
            raise RuntimeError("RPC unavailable")

        monkeypatch.setattr("services.resolution.adapters.authorization.rpc_request", fail)
    cap = capability_to_dict(evaluate_tree_with_registry(tree, registry, ctx))
    assert capability_surface_openness(cap, project_capability_surface(cap)) == "not_determined"


def test_source_variant_uses_the_same_generic_authorization_proof(safe_pair, tmp_path):
    safe, _ = safe_pair
    project = tmp_path / "source_variant"
    shutil.copytree(safe.project / "src", project / "src")
    for file in ("foundry.toml", "contract_meta.json"):
        shutil.copy(safe.project / file, project / file)
    source = project / "src" / "Safe.sol"
    source.write_text(source.read_text() + "\n// Unrecognized source identity; authentication remains intact.\n")
    _, trees, _ = collect_contract_analysis_with_artifacts(project)
    assert trees is not None
    tree = next(tree for sig, tree in trees["trees"].items() if sig.startswith("execTransaction("))
    registry = AdapterRegistry()
    registry.register(AuthorizationAdapter)
    ctx = EvaluationContext(
        chain_id=1,
        contract_address=safe.address,
        rpc_url=safe.url,
        block=int(rpc(safe.url, "eth_blockNumber", []), 16),
    )
    cap = capability_to_dict(evaluate_tree_with_registry(tree, registry, ctx))
    assert capability_surface_openness(cap, project_capability_surface(cap)) == "restricted"
    assert cap["threshold"]["m"] == 3


def _variant_trees(safe, tmp_path, replacements):
    project = tmp_path / "authorization_variant"
    shutil.copytree(safe.project / "src", project / "src")
    for file in ("foundry.toml", "contract_meta.json"):
        shutil.copy(safe.project / file, project / file)
    for source in project.joinpath("src").rglob("*.sol"):
        text = source.read_text()
        for old, new in replacements:
            text = text.replace(old, new)
        source.write_text(text)
    _, trees, _ = collect_contract_analysis_with_artifacts(project)
    assert trees is not None
    return next(tree for sig, tree in trees["trees"].items() if sig.startswith("execTransaction("))


def _threshold_descriptor(tree):
    leaf = tree.get("leaf") or {}
    descriptor = leaf.get("set_descriptor") or {}
    if descriptor.get("kind") == "signature_threshold":
        return descriptor
    for child in tree.get("children") or []:
        if found := _threshold_descriptor(child):
            return found
    return None


def _assert_authorization_unresolved(safe, tree):
    registry = AdapterRegistry()
    registry.register(AuthorizationAdapter)
    ctx = EvaluationContext(
        chain_id=1,
        contract_address=safe.address,
        rpc_url=safe.url,
        block=int(rpc(safe.url, "eth_blockNumber", []), 16),
    )
    cap = capability_to_dict(evaluate_tree_with_registry(tree, registry, ctx))
    surface = project_capability_surface(cap)
    assert capability_surface_openness(cap, surface) == "not_determined", cap
    assert not surface.principal_rows
    assert not surface.public_paths


def test_generic_recognizer_ignores_contract_function_and_variable_names(safe_pair, tmp_path):
    safe, _ = safe_pair
    tree = _variant_trees(
        safe,
        tmp_path,
        [
            ("checkNSignatures", "validateQuorum"),
            ("checkSignatures", "validateBundle"),
            ("currentOwner", "candidateSigner"),
            ("lastOwner", "previousSigner"),
            ("requiredSignatures", "neededApprovals"),
            ("owners", "signerLinks"),
            ("threshold", "minimumApprovals"),
        ],
    )
    descriptor = _threshold_descriptor(tree)
    assert descriptor is not None
    assert descriptor["registry"]["variable"] == "signerLinks"
    assert descriptor["threshold"]["variable"] == "minimumApprovals"
    assert descriptor["bound_parameters"] == list(range(9))


@pytest.mark.parametrize(
    "old,new",
    [
        ("owners[currentOwner] != address(0) && ", ""),
        ("currentOwner > lastOwner && ", ""),
    ],
    ids=["membership-removed", "distinctness-removed"],
)
def test_quorum_credit_requires_membership_and_distinctness(safe_pair, tmp_path, old, new):
    safe, _ = safe_pair
    tree = _variant_trees(safe, tmp_path, [(old, new)])
    assert _threshold_descriptor(tree) is None
    if old == "currentOwner > lastOwner && ":
        _assert_authorization_unresolved(safe, tree)


def test_quorum_reports_the_loop_bound_the_code_actually_enforces(safe_pair, tmp_path):
    safe, _ = safe_pair
    tree = _variant_trees(safe, tmp_path, [("i < requiredSignatures", "i < 1")])
    descriptor = _threshold_descriptor(tree)
    assert descriptor is not None
    assert descriptor["threshold"] == {"kind": "constant", "value": 1}


def test_signature_credit_does_not_claim_parameters_the_hash_does_not_bind(safe_pair, tmp_path):
    safe, _ = safe_pair
    tree = _variant_trees(
        safe,
        tmp_path,
        [("checkSignatures(txHash, txHashData, signatures)", "checkSignatures(bytes32(0), txHashData, signatures)")],
    )
    descriptor = _threshold_descriptor(tree)
    assert descriptor is not None
    assert descriptor["bound_parameters"] == []


@pytest.mark.parametrize(
    "old,new",
    [
        (
            OWNER_GUARD,
            "if (v == 99) currentOwner = address(uint160(uint256(r)));\n" + OWNER_GUARD,
        ),
        (
            "ISignatureValidator(currentOwner).isValidSignature(data, contractSignature)",
            'ISignatureValidator(currentOwner).isValidSignature(bytes(""), contractSignature)',
        ),
        ('require(owners[msg.sender] != address(0), "GS030");', ""),
    ],
    ids=["unauthenticated-signer-branch", "validator-not-payload-bound", "public-hash-approval"],
)
def test_every_signer_mode_must_be_authenticated_and_payload_bound(safe_pair, tmp_path, old, new):
    safe, _ = safe_pair
    tree = _variant_trees(safe, tmp_path, [(old, new)])
    assert _threshold_descriptor(tree) is None
    _assert_authorization_unresolved(safe, tree)


def test_broken_twin_really_allows_unsigned_execution(safe_pair):
    _, broken = safe_pair
    assert call(broken.url, broken.address, "getThreshold()", returns=["uint256"])[0] == 3
    assert len(call(broken.url, broken.address, "getOwners()", returns=["address[]"])[0]) == 8
    receipt = send(broken.url, broken.relayer, calldata(EXEC, broken.args() + [b""]), broken.address)
    assert int(receipt["status"], 16) == 1
    assert broken.value() == 42


@requires_postgres
@pytest.mark.parametrize(
    "broken,threshold,module",
    [(False, 3, False), (True, 3, False), (False, 2, False), (False, 3, True)],
    ids=["canonical", "authentication-removed", "live-threshold-changed", "enabled-module"],
)
def test_real_execution_agrees_with_persisted_and_scored_authority(
    safe_pair, db_session, monkeypatch, broken, threshold, module
):
    safe = safe_pair[int(broken)]
    if threshold != 3:
        safe.configure("changeThreshold(uint256)", [threshold])
    if module:
        safe.configure("enableModule(address)", [safe.relayer])
    protocol = Protocol(name="safe-auth-" + str(broken))
    job = Job(address=safe.address, status=JobStatus.completed, request={"chain": "ethereum", "rpc_url": safe.url})
    db_session.add_all([protocol, job])
    db_session.flush()
    contract = Contract(address=safe.address, chain="ethereum", protocol_id=protocol.id, job_id=job.id)
    db_session.add(contract)
    db_session.flush()
    # Only the object-storage boundary is replaced; trees/claims are freshly extracted from the deployed source.
    monkeypatch.setattr(
        "services.resolution.capability_resolver.get_artifact",
        lambda _session, _job_id, name: safe.trees if name == "predicate_trees" else None,
    )
    caps = resolve_contract_capabilities(
        db_session,
        address=safe.address,
        chain_id=1,
        chain="ethereum",
        job_id=job.id,
        block=int(rpc(safe.url, "eth_blockNumber", []), 16),
    )
    assert caps is not None
    permissions = build_effective_permissions(
        safe.analysis, predicate_trees=safe.trees, capability_resolver_output=caps, effects=safe.effects
    )
    write_effective_function_rows(
        db_session,
        contract_id=contract.id,
        function_records=cast(list[dict[str, Any]], permissions["functions"]),
        capability_by_function=caps,
        deployment_address=safe.address,
    )
    db_session.flush()
    execution = db_session.query(EffectiveFunction).filter_by(contract_id=contract.id, abi_signature=EXEC).one()
    expected = "open" if broken else "restricted"
    assert execution.authority_openness == expected, execution.capability_expr
    if not broken:
        assert execution.capability_expr["threshold"]["m"] == threshold
        assert set(execution.capability_expr["threshold"]["signers"]) == set(safe.owners)
        assert len(execution.principals) == 1
        assert execution.principals[0].address == safe.address
        for signature in (
            "execTransactionFromModule(address,uint256,bytes,uint8)",
            "execTransactionFromModuleReturnData(address,uint256,bytes,uint8)",
        ):
            row = db_session.query(EffectiveFunction).filter_by(contract_id=contract.id, abi_signature=signature).one()
            assert row.authority_openness == "restricted"
            assert row.capability_expr["kind"] == "finite_set"
            assert row.capability_expr["members"] == ([safe.relayer] if module else [])
    signals = distill_protocol_in_memory(db_session, protocol.id)
    exec_signals = [s for s in signals if s.selector == execution.selector and s.claim_id == "exec.arbitrary"]
    assert len(exec_signals) == 1
    assert exec_signals[0].authority_openness == expected
    score = compute_protocol_score(db_session, protocol.id, signals=exec_signals)
    if broken:
        assert exec_signals[0].principal_state == "none_required"
        assert not any(f["principal_kind"] == "safe" for f in score.findings)
        # No measured extraction/destination bound was witnessed for the mutant. A withheld score is a disclosed gap,
        # never a benign signature-bound verdict; the source/DB/signal above must still publish its public authority.
        assert score.findings or any(w["kind"] == "destination_not_determined_row_withheld" for w in score.warnings)
    else:
        assert score.findings
        assert all(f["principal_kind"] == "safe" for f in score.findings)


def test_delegated_signer_code_does_not_receive_unproved_quorum_credit(safe_pair):
    safe, _ = safe_pair
    # A code-bearing registry member has an additional authorization mechanism whose policy is not proved here.
    rpc(safe.url, "anvil_setCode", [safe.owners[0], "0x600160005260206000f3"])
    tree = next(t for sig, t in safe.trees["trees"].items() if sig.startswith("execTransaction("))
    _assert_authorization_unresolved(safe, tree)
