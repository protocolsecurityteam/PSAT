"""Upgrade/exec matchers on the production stack: compiled fixtures under ``fixtures/contracts/claims_upgrade_exec``
(a positive, a counterexample and a near-miss per entry), plus ``build_claims`` over synthetic facts so gate
discrimination runs without solc.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("slither")

from tests.support.foundry_project import write_foundry_project

pytestmark = pytest.mark.compile

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "contracts" / "claims_upgrade_exec"

# Other matcher modules share the registry, so assertions scope to these ids.
OWNED_CLAIM_IDS = frozenset(
    {
        "upgrade.implementation",
        "proxy.admin_change",
        "safe.signer_mgmt",
        "safe.module_mgmt",
        "safe.set_guard",
        "timelock.schedule",
        "timelock.execute",
        "timelock.cancel",
        "timelock.set_delay",
        "exec.arbitrary",
    }
)


def _pipeline_claim_records(tmp_path: Path, fixture_file: str, contract_name: str) -> dict[str, list[dict]]:
    """Full rows, so a test can hold the witness to account, not just (claim_id, tier)."""
    from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts

    source = (FIXTURES_DIR / fixture_file).read_text()
    project_dir = write_foundry_project(tmp_path, contract_name, source)
    _analysis, _trees, effects = collect_contract_analysis_with_artifacts(project_dir)
    assert effects is not None and "functions" in effects
    out: dict[str, list[dict]] = {}
    for signature, record in effects["functions"].items():
        assert "claims" in record, signature
        out[signature] = list(record["claims"])
    return out


def _claims_view(records: dict[str, list[dict]]) -> dict[str, set[tuple[str, str]]]:
    return {sig: {(c["claim_id"], c["tier"]) for c in rows} for sig, rows in records.items()}


def _pipeline_claims(tmp_path: Path, fixture_file: str, contract_name: str) -> dict[str, set[tuple[str, str]]]:
    return _claims_view(_pipeline_claim_records(tmp_path, fixture_file, contract_name))


def _claim_witness(records: dict[str, list[dict]], name: str, claim_id: str) -> dict:
    matches = [sig for sig in records if sig.split("(", 1)[0] == name]
    assert len(matches) == 1, f"function {name!r}: {matches}"
    rows = [c for c in records[matches[0]] if c["claim_id"] == claim_id]
    assert len(rows) == 1, f"{name!r} {claim_id!r}: {rows}"
    return rows[0].get("witness") or {}


def _find(claims: dict[str, set[tuple[str, str]]], name: str) -> set[tuple[str, str]]:
    matches = [sig for sig in claims if sig.split("(", 1)[0] == name]
    assert matches, f"no function named {name!r} in {sorted(claims)}"
    assert len(matches) == 1, f"ambiguous {name!r}: {matches}"
    return {claim for claim in claims[matches[0]] if claim[0] in OWNED_CLAIM_IDS}


def _owned_total(claims: dict[str, set[tuple[str, str]]]) -> int:
    return sum(1 for cset in claims.values() for claim in cset if claim[0] in OWNED_CLAIM_IDS)


def test_proxy_shell_upgrade_and_admin_positive(tmp_path):
    claims = _pipeline_claims(tmp_path, "proxy_shell_wbeth.sol", "WBETHProxy")
    assert _find(claims, "upgradeTo") == {("upgrade.implementation", "standard_exact")}
    assert _find(claims, "changeAdmin") == {("proxy.admin_change", "standard_exact")}


def test_safe_family_positive(tmp_path):
    records = _pipeline_claim_records(tmp_path, "safe_wallet.sol", "SafeWallet")
    claims = _claims_view(records)
    signer = ("safe.signer_mgmt", "standard_exact")
    for fn in ("addOwnerWithThreshold", "removeOwner", "swapOwner", "changeThreshold"):
        assert _find(claims, fn) == {signer}, fn
    module = ("safe.module_mgmt", "standard_exact")
    for fn in ("enableModule", "disableModule"):
        assert _find(claims, fn) == {module}, fn
    assert _find(claims, "setGuard") == {("safe.set_guard", "standard_exact")}
    arb = ("exec.arbitrary", "standard_exact")
    for fn in ("execTransaction", "execTransactionFromModule", "execTransactionFromModuleReturnData"):
        assert _find(claims, fn) == {arb}, fn
    assert _find(claims, "getThreshold") == set()
    assert _find(claims, "getOwners") == set()
    # 4 signer + 2 module + 1 guard + 3 exec.
    assert _owned_total(claims) == 10
    # Round-3 R1: execTransaction's destination rides under the owners' signatures, published identically on exec and
    # flow witnesses.
    signed = {"state": "constrained", "guard": "signature_witness", "pins": True, "binding": "standard_gate"}
    assert _claim_witness(records, "execTransaction", "exec.arbitrary")["destination_constraint"] == signed
    exec_flow = _claim_witness(records, "execTransaction", "flow.out")
    assert exec_flow["flows"][0]["target_constraint"] == signed
    # Module exec gates the caller (``modules[msg.sender]``), so the walk proves the destination free; never ``pins:
    # True``.
    free = {"state": "unconstrained_proven"}
    for fn in ("execTransactionFromModule", "execTransactionFromModuleReturnData"):
        assert _claim_witness(records, fn, "exec.arbitrary")["destination_constraint"] == free, fn
        module_flow = _claim_witness(records, fn, "flow.out")
        assert module_flow["flows"][0]["target_constraint"] == free, fn


def test_oz_timelock_family_positive(tmp_path):
    claims = _pipeline_claims(tmp_path, "oz_timelock.sol", "TimelockController")
    sched = ("timelock.schedule", "standard_exact")
    assert _find(claims, "schedule") == {sched}
    assert _find(claims, "scheduleBatch") == {sched}
    both = {("timelock.execute", "standard_exact"), ("exec.arbitrary", "standard_exact")}
    assert _find(claims, "execute") == both
    assert _find(claims, "executeBatch") == both
    assert _find(claims, "cancel") == {("timelock.cancel", "standard_exact")}
    assert _find(claims, "updateDelay") == {("timelock.set_delay", "standard_exact")}
    assert _find(claims, "getMinDelay") == set()
    assert _find(claims, "hashOperation") == set()


def test_the_manage_positive_still_names_its_two_parameters(tmp_path):
    """``manage`` reaches its call through a library and ``manageDirect`` directly; the answer must stay right by
    proof, not by there being one candidate.
    """
    from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts

    source = (FIXTURES_DIR / "boring_vault_manage.sol").read_text()
    project_dir = write_foundry_project(tmp_path, "BoringVault", source)
    _analysis, _trees, effects = collect_contract_analysis_with_artifacts(project_dir)
    assert effects is not None
    witnesses = {
        signature.split("(", 1)[0]: claim["witness"]
        for signature, record in effects["functions"].items()
        for claim in record.get("claims") or []
        if claim["claim_id"] == "exec.arbitrary"
    }
    assert witnesses["manage"]["destination_param"] == "target"
    assert witnesses["manage"]["calldata_param"] == "data"
    assert witnesses["manage"]["destination_basis"] == "library_forwarder"
    assert witnesses["manageDirect"]["destination_param"] == "target"
    assert witnesses["manageDirect"]["calldata_param"] == "data"
    assert witnesses["manageDirect"]["destination_basis"] == "call_destination"
    # The binding names the array the forwarded element came from.
    assert witnesses["manageBatch"]["destination_param"] == "targets"
    assert witnesses["manageBatch"]["calldata_param"] == "data"


def _binding_witnesses(tmp_path: Path) -> dict[str, dict]:
    from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts

    source = (FIXTURES_DIR / "exec_arbitrary_binding.sol").read_text()
    project_dir = write_foundry_project(tmp_path, "ExecBinding", source)
    _analysis, _trees, effects = collect_contract_analysis_with_artifacts(project_dir)
    assert effects is not None
    out: dict[str, dict] = {}
    for signature, record in effects["functions"].items():
        for claim in record.get("claims") or []:
            if claim["claim_id"] == "exec.arbitrary":
                out[signature.split("(", 1)[0]] = claim["witness"]
    return out


def test_a_typed_call_carries_no_caller_chosen_calldata_blob(tmp_path):
    """A typed call fixes the selector; ``call_argument`` is the proven absence, not ``not_determined``."""
    witness = _binding_witnesses(tmp_path)["compose"]
    assert witness["calldata_kind"] == "call_argument"
    assert witness["calldata_param"] is None
    assert witness["calldata_basis"] is None


def test_the_arbitrary_calls_own_revert_surface_is_still_transparent(tmp_path):
    """Transparency is earned per op (singly assigned local, typed call, resolved library forwarder); the
    guard-shaped bodies stay open in both orders.
    """
    witnesses = _binding_witnesses(tmp_path)
    for name in ("singlyAssignedLocal", "compose", "manageViaLibrary"):
        assert witnesses[name]["destination_constraint"] == {"state": "unconstrained_proven"}, name
    for name in ("guardThenExec", "execThenGuard"):
        assert witnesses[name]["destination_constraint"] == {"state": "not_determined"}, name


def test_the_suppression_requires_every_op_to_be_state_var(tmp_path):
    """An open question on any op outranks a proven absence on another."""
    witnesses = _binding_witnesses(tmp_path)
    assert "twoStateVarSinks" not in witnesses
    hedged = witnesses["stateVarThenBranched"]
    assert hedged["destination_kind"] == "not_determined"
    assert hedged["destination_param"] is None


def test_a_library_forwarder_binds_through_its_own_body(tmp_path):
    """``using Lib for address`` puts the library in the destination operand; the body says which argument is the
    real target.
    """
    witnesses = _binding_witnesses(tmp_path)
    for name in ("manageViaLibrary", "manageReversed", "manageViaAssembly"):
        witness = witnesses[name]
        assert (witness["destination_param"], witness["destination_kind"]) == ("target", "param"), name
        assert (witness["calldata_param"], witness["calldata_kind"]) == ("data", "param"), name
        assert witness["destination_basis"] == witness["calldata_basis"] == "library_forwarder", name


def test_a_destination_defined_twice_is_not_determined_not_either_proof(tmp_path):
    """Slither IR isn't SSA, so a multiply-defined name is a control-flow question and both proof states are wrong:
    ``state_var`` is a false absence (``_named_executor_slots`` treats non-``param`` as no binding), and a
    parameter name may be the wrong one. Solmate's ``Auth.setAuthority`` in BoringVault is a live instance.
    """
    witnesses = _binding_witnesses(tmp_path)
    for name in (
        "branchedStateOrParam",
        "branchedParams",
        "reassignedLocal",
        "paramWrittenAfterCall",
        "stateWrittenAfterCall",
    ):
        witness = witnesses[name]
        assert witness["destination_kind"] == "not_determined", name
        assert witness["destination_param"] is None, name
        assert witness["destination_basis"] is None, name


# Facts-level gate negatives that need no solc; the positives are proven on the compiled fixtures above.


def _fn(selector: str, *, sinks: list[dict] | None = None) -> dict:
    return {"selector": selector, "sinks": sinks or [], "effect_labels": []}
