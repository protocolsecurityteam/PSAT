"""Upgrade / exec-family claim matchers, proven on real corpus sources.

Two layers, both driving the production stack (registry, gates, taint helper,
``build_claims``) — nothing under test is faked:

* Slither-driven: each fixture under ``fixtures/contracts/claims_upgrade_exec``
  is compiled by the real static pipeline (``collect_contract_analysis_with_artifacts``
  → Slither → effects → the claims phase) and the minted claims are asserted.
  Every registry entry gets a positive fixture, and the corpus carries the
  mandated counterexample + adversarial near-miss (non-proxy ``upgradeTo``; plain
  ``transfer`` value send).
* Pure-facts: ``build_claims`` over synthetic ``effects``-shaped dicts locks the
  contract-level gate discrimination without a compiler, so the selector/gate
  logic is covered deterministically in every offline run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("slither")

from services.static.claims import build_claims  # noqa: E402
from tests.support.foundry_project import write_foundry_project  # noqa: E402

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "contracts" / "claims_upgrade_exec"

# The claim families this task owns. Other matcher modules share the registry,
# so every assertion scopes to these ids (a sibling ownership/authorized_caller
# claim on the same function is legitimate and not this test's concern).
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


# ---------------------------------------------------------------------------
# Slither-driven: the real static pipeline over compiled corpus fixtures
# ---------------------------------------------------------------------------


def _pipeline_claim_records(tmp_path: Path, fixture_file: str, contract_name: str) -> dict[str, list[dict]]:
    """Run the full static pipeline and return ``{signature: [claim dicts]}`` —
    the full rows, so a test can hold the WITNESS to account, not only the
    (claim_id, tier) pair a false verdict can hide behind."""
    from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts

    source = (FIXTURES_DIR / fixture_file).read_text()
    project_dir = write_foundry_project(tmp_path, contract_name, source)
    _analysis, _trees, effects = collect_contract_analysis_with_artifacts(project_dir)
    assert effects is not None and "functions" in effects
    out: dict[str, list[dict]] = {}
    for signature, record in effects["functions"].items():
        # The claims phase always attaches the field, even when empty.
        assert "claims" in record, signature
        out[signature] = list(record["claims"])
    return out


def _claims_view(records: dict[str, list[dict]]) -> dict[str, set[tuple[str, str]]]:
    return {sig: {(c["claim_id"], c["tier"]) for c in rows} for sig, rows in records.items()}


def _pipeline_claims(tmp_path: Path, fixture_file: str, contract_name: str) -> dict[str, set[tuple[str, str]]]:
    """Run the full static pipeline and return ``{signature: {(claim_id, tier)}}``."""
    return _claims_view(_pipeline_claim_records(tmp_path, fixture_file, contract_name))


def _claim_witness(records: dict[str, list[dict]], name: str, claim_id: str) -> dict:
    """The single ``claim_id`` witness on the single function named ``name``."""
    matches = [sig for sig in records if sig.split("(", 1)[0] == name]
    assert len(matches) == 1, f"function {name!r}: {matches}"
    rows = [c for c in records[matches[0]] if c["claim_id"] == claim_id]
    assert len(rows) == 1, f"{name!r} {claim_id!r}: {rows}"
    return rows[0].get("witness") or {}


def _find(claims: dict[str, set[tuple[str, str]]], name: str) -> set[tuple[str, str]]:
    """Owned-family claims on the single function named ``name``."""
    matches = [sig for sig in claims if sig.split("(", 1)[0] == name]
    assert matches, f"no function named {name!r} in {sorted(claims)}"
    assert len(matches) == 1, f"ambiguous {name!r}: {matches}"
    return {claim for claim in claims[matches[0]] if claim[0] in OWNED_CLAIM_IDS}


def _owned_total(claims: dict[str, set[tuple[str, str]]]) -> int:
    return sum(1 for cset in claims.values() for claim in cset if claim[0] in OWNED_CLAIM_IDS)


def test_uups_upgrade_positive(tmp_path):
    """EETH-class UUPS: proxiableUUID gate → upgradeTo/AndCall both claim."""
    claims = _pipeline_claims(tmp_path, "uups_eeth_upgrade.sol", "EETH")
    assert _find(claims, "upgradeTo") == {("upgrade.implementation", "standard_exact")}
    assert _find(claims, "upgradeToAndCall") == {("upgrade.implementation", "standard_exact")}
    # The gate marker itself (a view) is never a claim.
    assert _find(claims, "proxiableUUID") == set()
    assert _find(claims, "mintShares") == set()


def test_proxy_shell_upgrade_and_admin_positive(tmp_path):
    """wBETH-class zos shell: delegatecall-fallback gate recovers upgradeTo, and
    changeAdmin gets proxy.admin_change (today: nothing)."""
    claims = _pipeline_claims(tmp_path, "proxy_shell_wbeth.sol", "WBETHProxy")
    assert _find(claims, "upgradeTo") == {("upgrade.implementation", "standard_exact")}
    assert _find(claims, "changeAdmin") == {("proxy.admin_change", "standard_exact")}


def test_non_proxy_upgradeto_is_near_miss_negative(tmp_path):
    """Adversarial: same selector, no proxy gate → no upgrade/admin claim."""
    claims = _pipeline_claims(tmp_path, "not_a_proxy_upgradeto.sol", "StrategyRegistry")
    assert _find(claims, "upgradeTo") == set()
    assert _find(claims, "changeAdmin") == set()


def test_safe_family_positive(tmp_path):
    """SafeL2-class: signer/module/guard control claims + exec.arbitrary on the
    execute entries, all under the getThreshold+getOwners+execTransaction gate."""
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
    # Gate views carry no claim.
    assert _find(claims, "getThreshold") == set()
    assert _find(claims, "getOwners") == set()
    # 4 signer + 2 module + 1 guard + 3 exec = 10 owned claims across the Safe family.
    assert _owned_total(claims) == 10
    # Round-3 R1: the WITNESS, not only the (claim_id, tier) pair.
    # execTransaction's destination rides under the owners' threshold
    # signatures — the standard commitment, published identically on the exec
    # and flow witnesses so the two can never contradict on one function.
    signed = {"state": "constrained", "guard": "signature_witness", "pins": True, "binding": "standard_gate"}
    assert _claim_witness(records, "execTransaction", "exec.arbitrary")["destination_constraint"] == signed
    exec_flow = _claim_witness(records, "execTransaction", "flow.out")
    assert exec_flow["flows"][0]["target_constraint"] == signed
    # The module-exec entries share the selectors and the gate, but their guard
    # (`modules[msg.sender]`) is an allowlist on the CALLER: no signature
    # commits `to`, an enabled module calls any target with any calldata. The
    # tree walk sees exactly that caller-keyed gate and PROVES the destination
    # free — the verdict that keeps the caller-chosen hazard standing
    # downstream, and above all never `pins: True`.
    free = {"state": "unconstrained_proven"}
    for fn in ("execTransactionFromModule", "execTransactionFromModuleReturnData"):
        assert _claim_witness(records, fn, "exec.arbitrary")["destination_constraint"] == free, fn
        module_flow = _claim_witness(records, fn, "flow.out")
        assert module_flow["flows"][0]["target_constraint"] == free, fn


def test_oz_timelock_family_positive(tmp_path):
    """TimelockController: per-selector timelock claims; execute/executeBatch
    carry BOTH timelock.execute AND exec.arbitrary."""
    claims = _pipeline_claims(tmp_path, "oz_timelock.sol", "TimelockController")
    sched = ("timelock.schedule", "standard_exact")
    assert _find(claims, "schedule") == {sched}
    assert _find(claims, "scheduleBatch") == {sched}
    both = {("timelock.execute", "standard_exact"), ("exec.arbitrary", "standard_exact")}
    assert _find(claims, "execute") == both
    assert _find(claims, "executeBatch") == both
    assert _find(claims, "cancel") == {("timelock.cancel", "standard_exact")}
    assert _find(claims, "updateDelay") == {("timelock.set_delay", "standard_exact")}
    # 6 timelock.* claims + 2 exec.arbitrary on the execute entries.
    assert _find(claims, "getMinDelay") == set()
    assert _find(claims, "hashOperation") == set()


def test_boring_vault_manage_idiom_positive(tmp_path):
    """BoringVault.manage: parameter-tainted target + calldata → exec.arbitrary at
    the idiom tier (no standard gate)."""
    claims = _pipeline_claims(tmp_path, "boring_vault_manage.sol", "BoringVault")
    idiom = ("exec.arbitrary", "idiom_structural")
    assert _find(claims, "manage") == {idiom}
    assert _find(claims, "manageDirect") == {idiom}


def test_the_manage_positive_still_names_its_two_parameters(tmp_path):
    """The positive control for the binding change: where the answer was already
    right it must stay right, by proof rather than by there being one candidate.

    ``manage`` reaches its call through the library and ``manageDirect`` calls
    directly, so the two bases are exercised on the same contract."""
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
    # The batch overload forwards an ELEMENT of each array; the binding names the
    # array parameter the element came from.
    assert witnesses["manageBatch"]["destination_param"] == "targets"
    assert witnesses["manageBatch"]["calldata_param"] == "data"


def test_batch_manage_idiom_positive(tmp_path):
    """The batch overload is the same executor with one array level added, and it
    minted nothing: the declared types are ``address[]``/``bytes[]`` rather than
    ``address``/``bytes``, and inside the loop the call op reads an element
    reference rather than the parameter. Both had to give for the claim to land.

    Under-claiming here is safe but not harmless — an arbitrary-call executor
    that publishes no exec.arbitrary claim reads as an ordinary function."""
    claims = _pipeline_claims(tmp_path, "boring_vault_manage.sol", "BoringVault")
    idiom = ("exec.arbitrary", "idiom_structural")
    assert _find(claims, "manageBatch") == {idiom}


def test_library_mediated_batch_executor_is_a_deliberate_under_claim(tmp_path):
    """A real arbitrary-call executor that this matcher knowingly stays silent on.

    ``using Address for address`` puts the LIBRARY in the destination and the
    target in argument position, so the only handle the MINTING gate has left is
    "an address parameter appears in the call's read set" — which is exactly what
    a fixed destination forwarder also looks like. For a scalar parameter that
    ambiguity is tolerated (the shape is common and the sibling positive covers
    it); for an array it is not, because the same allowance put a false
    arbitrary-call badge on published output.

    The library body is now read to BIND the published parameter names (see the
    binding tests below), but the minting gate deliberately still is not: the
    claim population is not this fix's to change. So this stays an under-claim,
    which is the safe direction — and a proven effects verdict still catches this
    function if it moves value."""
    claims = _pipeline_claims(tmp_path, "boring_vault_manage.sol", "BoringVault")
    assert _find(claims, "manageBatchViaLibrary") == set()


def test_batch_of_fixed_width_digests_is_a_near_miss_negative(tmp_path):
    """``bytes32[]`` reduces to ``bytes32``, which is not arbitrary calldata —
    widening the element type must not sweep in every batch that happens to carry
    an address array."""
    claims = _pipeline_claims(tmp_path, "boring_vault_manage.sol", "BoringVault")
    assert _find(claims, "commitBatch") == set()


def _binding_witnesses(tmp_path: Path) -> dict[str, dict]:
    """``{function name: exec.arbitrary witness}`` over the binding corpus."""
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
    """Two address parameters, and the destination is the second one.

    A pick taken from the read-set intersection lands on either — and on the two
    production functions where a choice existed it landed on the wrong one both
    times (``lzCompose`` published ``_from``, a SOURCE). The operand position is
    the only thing that separates them, and it is what is published now."""
    witness = _binding_witnesses(tmp_path)["compose"]
    assert (witness["destination_param"], witness["destination_kind"]) == ("to", "param")
    assert witness["destination_basis"] == "call_destination"
    assert witness["destination_param"] != "from"


def test_a_typed_call_carries_no_caller_chosen_calldata_blob(tmp_path):
    """``IComposer(to).compose(from, message, extra)`` fixes the selector, so no
    argument of it is an arbitrary calldata blob. Naming one — as the read-set
    pick did on three production rows — asserts caller-chosen calldata that the
    op does not carry. ``call_argument`` is the proven absence; it is not the
    same fact as ``not_determined``."""
    witness = _binding_witnesses(tmp_path)["compose"]
    assert witness["calldata_kind"] == "call_argument"
    assert witness["calldata_param"] is None
    assert witness["calldata_basis"] is None


def test_a_state_variable_destination_mints_no_claim_at_all(tmp_path):
    """INVERTED. This test previously asserted that the ``rebalance`` shape
    carries an ``exec.arbitrary`` claim whose witness says ``state_var`` — i.e.
    that the claim is minted beside the proof of its own negation. It is a pure
    false positive on the real row it was modelled on (LRTSquaredAdmin.rebalance:
    the call goes to the storage-held ``swapper``, the two address parameters
    ride along as ARGUMENTS of a fixed-selector ``ISwapper.swap``, and no
    arbitrary call exists anywhere in the function).

    The claim's sentence is "forwards a caller-supplied target". ``state_var``
    is the proof that the caller does not supply it, so the honest output is no
    claim — and, through the legacy projection, no ``arbitrary_external_call``
    label and no "Executes arbitrary external calldata" prose either.

    The proven-absent DESTINATION classification is still exercised, and still
    matters: it is what this suppression keys on. See
    ``test_the_state_var_destination_state_is_still_produced`` below."""
    assert "rebalance" not in _binding_witnesses(tmp_path)


def test_the_state_var_destination_state_is_still_produced(tmp_path):
    """R2 for the suppression above: the branch it fires on is reachable, and it
    is reached by real compiler output rather than by construction — on a
    single-op body AND on a multi-op body whose every candidate op resolves to
    storage. The fragment's ``state_var`` is a function-wide quantifier now, so
    the multi-op arm is what proves the suppression still has something real to
    fire on after the quantifier change."""
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
    """R4 — the un-hedged positive the suppression must not eat. The Safe/Zodiac
    transaction-guard idiom calls a FIXED guard with ``(target, data)`` and then
    calls the caller-supplied target with the caller-supplied data. The first op
    resolves ``state_var``; the second IS the arbitrary call. A fragment that
    answered with the first op suppressed the whole claim — silently, and only
    in this statement order — so both orders are pinned to the same param
    binding here."""
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
    # Order-independence, field by field: swapping the two statements must not
    # move a byte of the published binding.
    assert {f: witnesses["guardThenExec"][f] for f in fragment_fields} == {
        f: witnesses["execThenGuard"][f] for f in fragment_fields
    }


def test_a_transaction_guard_blocks_the_negative_proof_the_open_control_keeps(tmp_path):
    """Round-5 R1, on real compiler output: a mandatory NONVIEW guard call
    vetting the caller-supplied ``(target, data)`` — the Safe/Zodiac
    transaction-guard idiom — must leave the destination-constraint answer
    OPEN, while the guardless control alone earns the negative proof. Before
    the per-op transparency proof, both published ``unconstrained_proven``:
    the guard's leaf was swallowed because its callee was a body call, and the
    consumer could not tell the vetted function from the open one."""
    records = _pipeline_claim_records(tmp_path, "transaction_guard.sol", "GuardedExec")
    guarded = _claim_witness(records, "execGuarded", "exec.arbitrary")
    open_control = _claim_witness(records, "execOpen", "exec.arbitrary")
    # Same claim, same binding — only the constraint verdict may differ.
    for witness in (guarded, open_control):
        assert (witness["destination_param"], witness["destination_kind"]) == ("target", "param")
    assert guarded["destination_constraint"] == {"state": "not_determined"}
    assert open_control["destination_constraint"] == {"state": "unconstrained_proven"}


def test_the_arbitrary_calls_own_revert_surface_is_still_transparent(tmp_path):
    """R4 — the un-hedged sibling of the guard test above: transparency is
    earned, not abolished. An op whose destination the IR proves parameter-
    rooted keeps its own revert surface out of the walk — through a singly
    assigned local (``t.exec``), through a typed call on the parameter itself
    (``compose``), and through a resolved library forwarder
    (``manageViaLibrary``) — so the negative proof stays reachable on compiled
    source. The two guard-shaped bodies stay open in BOTH statement orders:
    their ``exec`` leaf belongs to the fixed-destination sibling op — not to
    the arbitrary ``target.call`` — so its identity is withheld and the leaf
    blocks."""
    witnesses = _binding_witnesses(tmp_path)
    for name in ("singlyAssignedLocal", "compose", "manageViaLibrary"):
        assert witnesses[name]["destination_constraint"] == {"state": "unconstrained_proven"}, name
    for name in ("guardThenExec", "execThenGuard"):
        assert witnesses[name]["destination_constraint"] == {"state": "not_determined"}, name


def test_the_suppression_requires_every_op_to_be_state_var(tmp_path):
    """The suppression's quantifier: it may fire only where EVERY candidate op's
    destination is proven storage-held (``twoStateVarSinks``), and an open
    question on any op outranks a proven absence on another
    (``stateVarThenBranched`` mints the hedge)."""
    witnesses = _binding_witnesses(tmp_path)
    assert "twoStateVarSinks" not in witnesses
    hedged = witnesses["stateVarThenBranched"]
    assert hedged["destination_kind"] == "not_determined"
    assert hedged["destination_param"] is None


def test_a_library_forwarder_binds_through_its_own_body(tmp_path):
    """``using Lib for address`` puts the library in the destination operand and
    the real target in argument position. The library body says which argument
    that is — as a low-level call, as inline assembly, and with the library's
    own parameters in either order."""
    witnesses = _binding_witnesses(tmp_path)
    for name in ("manageViaLibrary", "manageReversed", "manageViaAssembly"):
        witness = witnesses[name]
        assert (witness["destination_param"], witness["destination_kind"]) == ("target", "param"), name
        assert (witness["calldata_param"], witness["calldata_kind"]) == ("data", "param"), name
        assert witness["destination_basis"] == witness["calldata_basis"] == "library_forwarder", name


def test_an_unresolved_forwarder_publishes_not_determined_not_the_only_candidate(tmp_path):
    """The third state, reached on a real library shape: OpenZeppelin's own
    ``functionCall`` forwards to a sibling rather than calling, so one level of
    resolution never reaches a call op.

    ``target`` is the only address parameter here, so a read-set pick would name
    it and be right by luck. This is the case that distinguishes "we proved the
    binding" from "there was only one thing to say", and the witness must not
    collapse them — the hedge and the un-hedged value are both reachable, which
    is what keeps this from being a sentinel that never fires."""
    witness = _binding_witnesses(tmp_path)["manageViaTwoStepLibrary"]
    assert witness["destination_kind"] == witness["calldata_kind"] == "not_determined"
    assert witness["destination_param"] is None and witness["calldata_param"] is None


def test_a_destination_defined_twice_is_not_determined_not_either_proof(tmp_path):
    """A name the body defines more than once carries several candidate values
    under ONE Slither variable object — the IR is not in SSA form — so which one
    the call sees is a control-flow question. Both published proof states are
    wrong answers to it, in both directions:

    * ``branchedStateOrParam`` reaches the call from storage on one path and from
      a parameter on the other. ``state_var`` there is a proven ABSENCE of a
      caller-chosen destination over a function that has one, and the consumer
      acts on it (``_named_executor_slots`` reads any non-``param`` kind as "no
      binding"), so the false absence suppresses a real one.
    * ``branchedParams`` / ``reassignedLocal`` / ``paramWrittenAfterCall`` publish
      a parameter NAME — a proof of presence on the wrong parameter, which is the
      defect class this binding work exists to remove.

    ``stateWrittenAfterCall`` is the same shape on a state variable, and it is not
    hypothetical: Solmate's ``Auth.setAuthority``, deployed inside BoringVault,
    calls ``authority.canCall(...)`` and assigns ``authority`` afterwards."""
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
    """R4 — the un-hedged sibling of the test above, and the whole difference
    between a resolver and a resolver-shaped hedge.

    ``address t = a; IExec(t).exec(a, d)`` defines ``t`` exactly once, so the
    local IS the parameter and the name is published. A guard that hedged on
    "the destination came through a local" would pass the not-determined test
    above and fail here — and would take ``BoringVault.manage`` with it."""
    witness = _binding_witnesses(tmp_path)["singlyAssignedLocal"]
    assert (witness["destination_param"], witness["destination_kind"]) == ("a", "param")
    assert witness["destination_basis"] == "call_destination"


def test_every_binding_state_is_reachable_on_one_corpus(tmp_path):
    """R2: a state that cannot be produced is not a mitigation. All three
    destination states and all three calldata states are minted by this corpus."""
    witnesses = _binding_witnesses(tmp_path)
    # ``state_var`` is absent from the CLAIMS because it now suppresses the claim
    # (it is the proof that the caller does not choose the destination); the
    # state itself is still produced and asserted in
    # ``test_the_state_var_destination_state_is_still_produced``.
    assert {w["destination_kind"] for w in witnesses.values()} == {"param", "not_determined"}
    assert {w["calldata_kind"] for w in witnesses.values()} == {"param", "call_argument", "not_determined"}


def test_plain_transfer_is_taint_near_miss_negative(tmp_path):
    """Address-tainted destination but no arbitrary calldata parameter → the
    value send earns no exec.arbitrary claim."""
    claims = _pipeline_claims(tmp_path, "plain_transfer_call.sol", "PayableToken")
    assert _find(claims, "transfer") == set()
    assert _find(claims, "withdraw") == set()
    assert _owned_total(claims) == 0


# ---------------------------------------------------------------------------
# Pure-facts: gate discrimination without a compiler.
#
# The gate POSITIVES (uups / proxy-shell / safe / timelock) are proven on the
# compiled fixtures above; this layer keeps only the facts-level NEGATIVES —
# deterministic gate discrimination that needs no solc and so runs in every
# offline suite even when a compiled positive skips.
# ---------------------------------------------------------------------------


def _fn(selector: str, *, sinks: list[dict] | None = None) -> dict:
    return {"selector": selector, "sinks": sinks or [], "effect_labels": []}


def _external_call_sink(name: str) -> list[dict]:
    return [{"id": f"{name}:sink0:external_call", "kind": "external_call", "target": "to.call", "origin": "body"}]


def test_facts_no_gate_no_upgrade_claim():
    """Selector present, no proxiableUUID sibling / delegatecall fallback /
    marker event (contract=None ⇒ no events) → the gate blocks the claim."""
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
    """swapOwner without the Safe sibling triple is not a Safe signer op."""
    effects = {
        "schema_version": "semantic-2",
        "contract_name": "NotASafe",
        "functions": {"swapOwner(address,address,address)": _fn("0xe318b52b")},
    }
    art = build_claims(None, effects, {})
    assert art["functions"]["swapOwner(address,address,address)"] == []


def test_facts_manage_idiom_fails_closed_without_a_contract():
    """A body external_call sink but no Slither contract (degraded) cannot prove
    taint, so the idiom arm emits nothing rather than guessing."""
    effects = {
        "schema_version": "semantic-2",
        "contract_name": "Vault",
        "functions": {"manage(address,bytes,uint256)": _fn("0xf6e715d0", sinks=_external_call_sink("manage"))},
    }
    art = build_claims(None, effects, {})
    assert art["functions"]["manage(address,bytes,uint256)"] == []


def test_facts_all_new_claim_ids_are_registered():
    from services.static.claims import registry

    build_claims(None, {"schema_version": "semantic-2", "functions": {}}, {})  # force discovery
    registered = set(registry())
    for claim_id in (
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
    ):
        assert claim_id in registered, claim_id


def test_fixed_destination_batch_forwarder_is_a_near_miss_negative(tmp_path):
    """The address array is an ARGUMENT to a fixed sink, not the thing being
    called: no caller chooses a destination here, so this is not arbitrary
    execution. It minted anyway because the array sits in the call's read set,
    and the claim reaches published output ungated as an "arbitrary-call"
    capability chip and a "manager" principal tag.

    The direct test is what proves a real batch executor — its destination
    resolves to the array itself — so argument position buys nothing for an
    array and costs a false badge on every forwarder of this shape."""
    claims = _pipeline_claims(tmp_path, "boring_vault_manage.sol", "BoringVault")
    assert _find(claims, "notifyBatch") == set()
