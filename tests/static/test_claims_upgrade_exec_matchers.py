"""Upgrade/exec matchers on the production stack: compiled fixtures under ``fixtures/contracts/claims_upgrade_exec``
(a positive, a counterexample and a near-miss per entry), plus ``build_claims`` over synthetic facts so gate
discrimination runs without solc.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("slither")

from services.static.claims import build_claims
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


def test_uups_upgrade_positive(tmp_path):
    claims = _pipeline_claims(tmp_path, "uups_eeth_upgrade.sol", "EETH")
    assert _find(claims, "upgradeTo") == {("upgrade.implementation", "standard_exact")}
    assert _find(claims, "upgradeToAndCall") == {("upgrade.implementation", "standard_exact")}
    assert _find(claims, "proxiableUUID") == set()
    assert _find(claims, "mintShares") == set()


def test_proxy_shell_upgrade_and_admin_positive(tmp_path):
    claims = _pipeline_claims(tmp_path, "proxy_shell_wbeth.sol", "WBETHProxy")
    assert _find(claims, "upgradeTo") == {("upgrade.implementation", "standard_exact")}
    assert _find(claims, "changeAdmin") == {("proxy.admin_change", "standard_exact")}


def test_non_proxy_upgradeto_is_near_miss_negative(tmp_path):
    claims = _pipeline_claims(tmp_path, "not_a_proxy_upgradeto.sol", "StrategyRegistry")
    assert _find(claims, "upgradeTo") == set()
    assert _find(claims, "changeAdmin") == set()


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


def test_boring_vault_manage_idiom_positive(tmp_path):
    claims = _pipeline_claims(tmp_path, "boring_vault_manage.sol", "BoringVault")
    idiom = ("exec.arbitrary", "idiom_structural")
    assert _find(claims, "manage") == {idiom}
    assert _find(claims, "manageDirect") == {idiom}


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


def test_batch_manage_idiom_positive(tmp_path):
    """Declared types are ``address[]``/``bytes[]`` and the loop reads element references; an executor without
    exec.arbitrary reads as ordinary.
    """
    claims = _pipeline_claims(tmp_path, "boring_vault_manage.sol", "BoringVault")
    idiom = ("exec.arbitrary", "idiom_structural")
    assert _find(claims, "manageBatch") == {idiom}


def test_batch_of_fixed_width_digests_is_a_near_miss_negative(tmp_path):
    """``bytes32`` is not arbitrary calldata."""
    claims = _pipeline_claims(tmp_path, "boring_vault_manage.sol", "BoringVault")
    assert _find(claims, "commitBatch") == set()


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


def test_the_destination_is_read_off_the_operand_not_the_read_set(tmp_path):
    """A read-set pick landed on the wrong parameter in production (``lzCompose`` published ``_from``, a source)."""
    witness = _binding_witnesses(tmp_path)["compose"]
    assert (witness["destination_param"], witness["destination_kind"]) == ("to", "param")
    assert witness["destination_basis"] == "call_destination"
    assert witness["destination_param"] != "from"


def test_a_typed_call_carries_no_caller_chosen_calldata_blob(tmp_path):
    """A typed call fixes the selector; ``call_argument`` is the proven absence, not ``not_determined``."""
    witness = _binding_witnesses(tmp_path)["compose"]
    assert witness["calldata_kind"] == "call_argument"
    assert witness["calldata_param"] is None
    assert witness["calldata_basis"] is None


def test_a_state_variable_destination_mints_no_claim_at_all(tmp_path):
    """Inverted: modelled on LRTSquaredAdmin.rebalance, where the call goes to the storage-held ``swapper``.

    ``state_var`` proves the caller doesn't supply the target, so no claim (and no legacy label or prose).
    """
    assert "rebalance" not in _binding_witnesses(tmp_path)


def test_the_state_var_destination_state_is_still_produced(tmp_path):
    """``state_var`` is a function-wide quantifier, so the multi-op arm proves the suppression still has something
    real to fire on.
    """
    from slither import Slither

    from services.static.claims.context import ClaimContext
    from services.static.claims.matchers._taint import arbitrary_exec_taint
    from services.static.contract_analysis_pipeline.effects import build_effects
    from services.static.contract_analysis_pipeline.shared import _select_subject_contract

    source = (FIXTURES_DIR / "exec_arbitrary_binding.sol").read_text()
    project_dir = write_foundry_project(tmp_path, "ExecBinding", source)
    subject = _select_subject_contract(Slither(str(project_dir)), "ExecBinding")
    assert subject is not None
    ctx = ClaimContext(subject, build_effects(subject), {})
    for signature in ("rebalance(address,address,bytes)", "twoStateVarSinks(address,bytes)"):
        taint = arbitrary_exec_taint(ctx, signature)
        assert taint is not None, "the taint fragment is what the suppression reads"
        assert taint["destination_kind"] == "state_var", signature
        assert taint["destination_param"] is None, signature


def test_a_genuine_arbitrary_call_survives_a_preceding_state_var_op(tmp_path):
    """Safe/Zodiac guard idiom: a fixed guard call then the arbitrary call.

    Answering with the first op suppressed the claim in only this order, so both orders are pinned.
    """
    witnesses = _binding_witnesses(tmp_path)
    fragment_fields = (
        "destination_param",
        "destination_kind",
        "destination_basis",
        "calldata_param",
        "calldata_kind",
        "calldata_basis",
    )
    for name in ("guardThenExec", "execThenGuard"):
        witness = witnesses[name]
        assert (witness["destination_param"], witness["destination_kind"]) == ("target", "param"), name
        assert (witness["calldata_param"], witness["calldata_kind"]) == ("data", "param"), name
    assert {f: witnesses["guardThenExec"][f] for f in fragment_fields} == {
        f: witnesses["execThenGuard"][f] for f in fragment_fields
    }


def test_a_transaction_guard_blocks_the_negative_proof_the_open_control_keeps(tmp_path):
    """Round-5 R1: before per-op transparency both published ``unconstrained_proven``."""
    records = _pipeline_claim_records(tmp_path, "transaction_guard.sol", "GuardedExec")
    guarded = _claim_witness(records, "execGuarded", "exec.arbitrary")
    open_control = _claim_witness(records, "execOpen", "exec.arbitrary")
    for witness in (guarded, open_control):
        assert (witness["destination_param"], witness["destination_kind"]) == ("target", "param")
    assert guarded["destination_constraint"] == {"state": "not_determined"}
    assert open_control["destination_constraint"] == {"state": "unconstrained_proven"}


def test_a_shared_callee_identity_is_withheld_from_the_transparency_set(tmp_path):
    """A tree leaf carries the callee identity but not the receiver, so a shared identity proves vacuousness for
    neither op.
    """
    records = _pipeline_claim_records(tmp_path, "transaction_guard.sol", "GuardedExec")
    shared = _claim_witness(records, "execSharedIdentity", "exec.arbitrary")
    typed = _claim_witness(records, "execTyped", "exec.arbitrary")
    for witness in (shared, typed):
        assert (witness["destination_param"], witness["destination_kind"]) == ("target", "param")
    assert shared["destination_constraint"] == {"state": "not_determined"}
    assert typed["destination_constraint"] == {"state": "unconstrained_proven"}


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


def test_an_unresolved_forwarder_publishes_not_determined_not_the_only_candidate(tmp_path):
    """``functionCall`` forwards to a sibling; a read-set pick would be right by luck since ``target`` is the only
    address parameter.
    """
    witness = _binding_witnesses(tmp_path)["manageViaTwoStepLibrary"]
    assert witness["destination_kind"] == witness["calldata_kind"] == "not_determined"
    assert witness["destination_param"] is None and witness["calldata_param"] is None


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


def test_a_singly_assigned_local_still_binds_to_its_parameter(tmp_path):
    """``t`` is defined once, so it IS the parameter; a local-hedging guard would break ``BoringVault.manage``."""
    witness = _binding_witnesses(tmp_path)["singlyAssignedLocal"]
    assert (witness["destination_param"], witness["destination_kind"]) == ("a", "param")
    assert witness["destination_basis"] == "call_destination"


def test_plain_transfer_is_taint_near_miss_negative(tmp_path):
    claims = _pipeline_claims(tmp_path, "plain_transfer_call.sol", "PayableToken")
    assert _find(claims, "transfer") == set()
    assert _find(claims, "withdraw") == set()
    assert _owned_total(claims) == 0


# Facts-level gate negatives that need no solc; the positives are proven on the compiled fixtures above.


def _fn(selector: str, *, sinks: list[dict] | None = None) -> dict:
    return {"selector": selector, "sinks": sinks or [], "effect_labels": []}


def _external_call_sink(name: str) -> list[dict]:
    return [{"id": f"{name}:sink0:external_call", "kind": "external_call", "target": "to.call", "origin": "body"}]


def test_facts_no_gate_no_upgrade_claim():
    """contract=None means no events."""
    effects = {
        "schema_version": "semantic-2",
        "contract_name": "Registry",
        "functions": {
            "upgradeTo(address)": _fn("0x3659cfe6"),
            "changeAdmin(address)": _fn("0x8f283970"),
        },
    }
    art = build_claims(None, effects, {})
    assert art["functions"]["upgradeTo(address)"] == []
    assert art["functions"]["changeAdmin(address)"] == []


def test_facts_safe_control_functions_need_the_gate():
    effects = {
        "schema_version": "semantic-2",
        "contract_name": "NotASafe",
        "functions": {"swapOwner(address,address,address)": _fn("0xe318b52b")},
    }
    art = build_claims(None, effects, {})
    assert art["functions"]["swapOwner(address,address,address)"] == []


def test_facts_manage_idiom_fails_closed_without_a_contract():
    """Degraded: no Slither contract means taint can't be proven."""
    effects = {
        "schema_version": "semantic-2",
        "contract_name": "Vault",
        "functions": {"manage(address,bytes,uint256)": _fn("0xf6e715d0", sinks=_external_call_sink("manage"))},
    }
    art = build_claims(None, effects, {})
    assert art["functions"]["manage(address,bytes,uint256)"] == []


def test_fixed_destination_batch_forwarder_is_a_near_miss_negative(tmp_path):
    """The array is an argument to a fixed sink; it minted an "arbitrary-call" chip and "manager" tag because it sat
    in the read set.
    """
    claims = _pipeline_claims(tmp_path, "boring_vault_manage.sol", "BoringVault")
    assert _find(claims, "notifyBatch") == set()
