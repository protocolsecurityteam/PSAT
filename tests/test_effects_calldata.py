"""Per-class calldata / entry-point synthesis + the prober wiring
(EFFECTS_RESOLUTION_SPEC Phase 4).

Recorded static facts in → concrete probe inputs out. Everything here is offline:
the pure synthesizers take hand-built artifact shapes, the DB-backed cases use the
test Postgres, and NOTHING spawns anvil or touches a wire (the fork factory is
exercised against a stubbed spawn).
"""

from __future__ import annotations

import copy
import inspect
import sys
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.models import Contract, EffectiveFunction, FunctionPrincipal, Protocol  # noqa: E402
from db.queue import create_job, store_artifact  # noqa: E402
from services.effects import calldata as cd  # noqa: E402
from services.effects.anvil import ForkFixture, pause_recipe  # noqa: E402
from services.effects.config import (  # noqa: E402
    EFFECT_CLASS_AUTHORITY_CHANGE,
    EFFECT_CLASS_FREEZE_PAUSE,
    EFFECT_CLASS_SUPPLY,
    EFFECT_CLASS_VALUE_OUT,
)
from services.effects.orchestrator import ProbeContext, default_prober  # noqa: E402
from services.effects.selection import Candidate  # noqa: E402
from tests.cache_helpers import requires_postgres  # noqa: E402
from tests.test_effects_anvil import GUARDED, PAUSE, RecordingStore, StubAnvil  # noqa: E402
from workers.effects_worker import EffectsWorker, _Seams  # noqa: E402

TRANSFER = "0xa9059cbb"  # transfer(address,uint256)
MINT = "0x40c10f19"  # mint(address,uint256)
PAUSE_SEL = "0x8456cb59"  # pause()
DEPOSIT = "0xd0e30db0"  # deposit()
ADMIN_ONLY = "0xc976a359"  # adminOnly()
PRINCIPAL = "0x" + "22" * 20
CONTRACT = "0x" + "a1" * 20


# ---------------------------------------------------------------------------
# fact builders
# ---------------------------------------------------------------------------


def _leaf(
    *operands: dict[str, Any],
    authority_role: str | None = None,
    absorbed: list[dict[str, Any]] | None = None,
    operator: str | None = None,
) -> dict[str, Any]:
    leaf: dict[str, Any] = {"operands": list(operands)}
    if authority_role is not None:
        leaf["authority_role"] = authority_role
    if operator is not None:
        # ``operands`` is the comparison's two slots in IR left-right order and the
        # operator says which side the constant bounds — both are load-bearing for the
        # pause-window harvest (L-58). Every leaf the production builder emits carries
        # an operator (5,089/5,089 persisted leaves locally); set it wherever a test
        # asserts a resolved window, and leave it off to exercise the undecidable case.
        leaf["operator"] = operator
    if absorbed is not None:
        # The sub-operands a two-slot comparison discarded (``absorbed_operands``,
        # stamped by the predicate builder). Only set where a test exercises them,
        # so every other leaf here stays byte-identical to a pre-A7 tree.
        leaf["absorbed_operands"] = absorbed
    return {"op": "LEAF", "leaf": leaf}


def _and(*children: dict[str, Any]) -> dict[str, Any]:
    return _built_by_current_builder({"op": "AND", "children": list(children)})


def _or(*children: dict[str, Any]) -> dict[str, Any]:
    return _built_by_current_builder({"op": "OR", "children": list(children)})


def _built_by_current_builder(tree: dict[str, Any]) -> dict[str, Any]:
    """Stamp the root marker the predicate builder stamps (``operand_absorption``).

    Default for every hand-built tree here BECAUSE it is what solc-built trees carry:
    it says the absorbed-operand recorder ran, so a leaf with no ``absorbed_operands``
    read no additive sub-expression. Trees WITHOUT it are the persisted pre-A7 shape,
    where the same missing key means "unknown", and
    ``test_a_pre_widening_tree_can_never_prove_an_indefinite_latch`` is the arm that
    builds one deliberately."""
    tree["operand_absorption"] = "recorded"
    return tree


def _state(var: str, member: str | None = None, **extra: Any) -> dict[str, Any]:
    op: dict[str, Any] = {"source": "state_variable", "state_variable_name": var}
    if member:
        op["member_path"] = [member]
    op.update(extra)
    return op


def _param(name: str, index: int) -> dict[str, Any]:
    return {"source": "parameter", "parameter_name": name, "parameter_index": index}


def _effect_info(
    full_name: str,
    selector: str,
    *,
    state_writes: list[dict[str, Any]] | None = None,
    effect_labels: list[str] | None = None,
    value_flows: list[dict[str, Any]] | None = None,
    parameter_names: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "function": full_name,
        "selector": selector,
        "abi_signature": full_name,
        "sinks": [],
        "state_writes": state_writes or [],
        "value_flows": value_flows or [],
        "effect_labels": effect_labels or [],
        "effect_targets": [],
        "state_changing": True,
        # Real artifacts always carry these; the prober needs a NAMED quantity
        # before it may substitute one (``integer_param_roles``).
        "parameter_names": parameter_names or [],
    }


def _write(var: str, declared_type: str, member: str | None = None) -> dict[str, Any]:
    return {
        "var": var,
        "declared_type": declared_type,
        "member_path": [member] if member else [],
        "granularity": "member" if member else "var",
        "hygiene_class": "normal",
        "origin": "body",
    }


OWNER_GATE = _and(_leaf(_state("owner"), authority_role="caller_authority"))
PAUSE_GATE = _and(_leaf(_state("paused")))


def _token_facts(**overrides: Any) -> cd.ContractFacts:
    """A token-ish contract: transfer/mint/pause + a paused-gated deposit and an
    owner-gated admin entry point."""
    effects = {
        "transfer(address,uint256)": _effect_info(
            "transfer(address,uint256)",
            TRANSFER,
            value_flows=[{"kind": "callee_erc20_selector", "direction": "out", "origin": "body"}],
            parameter_names=["to", "amount"],
        ),
        "mint(address,uint256)": _effect_info(
            "mint(address,uint256)", MINT, effect_labels=["mint"], parameter_names=["to", "amount"]
        ),
        "pause()": _effect_info("pause()", PAUSE_SEL, state_writes=[_write("paused", "bool")]),
        "deposit()": _effect_info("deposit()", DEPOSIT),
        "adminOnly()": _effect_info("adminOnly()", ADMIN_ONLY),
    }
    trees = {
        "transfer(address,uint256)": _and(_leaf(_param("token", 0))),
        "mint(address,uint256)": _and(_leaf(_state("owner"), _param("to", 0), authority_role="caller_authority")),
        "pause()": OWNER_GATE,
        "deposit()": PAUSE_GATE,
        "adminOnly()": OWNER_GATE,
    }
    canonical = {name: name for name in effects}
    by_selector = {info["selector"]: name for name, info in effects.items()}
    kwargs: dict[str, Any] = {
        "address": CONTRACT,
        "job_id": "job-1",
        "effects": effects,
        "trees": trees,
        "canonical_signatures": canonical,
        "legacy_value_flows": {},
        "by_selector": by_selector,
    }
    kwargs.update(overrides)
    return cd.ContractFacts(**kwargs)


def _candidate(
    selector: str,
    *,
    principals: tuple[str, ...] = (PRINCIPAL,),
    function_id: int = 1,
    authority_public: bool = False,
    holdings: tuple[str, ...] = (),
) -> Candidate:
    return Candidate(
        function_id=function_id,
        contract_id=1,
        contract_address=CONTRACT,
        selector=selector,
        function_name="f",
        authority_public=authority_public,
        principal_addresses=principals,
        input_token_addresses=holdings,
    )


# ---------------------------------------------------------------------------
# encoding
# ---------------------------------------------------------------------------


def test_encode_calldata_defaults_all_args():
    data = cd.encode_calldata(TRANSFER, "transfer(address,uint256)")
    assert data == TRANSFER + "00" * 64


def test_encode_calldata_substitutes_positionally():
    data = cd.encode_calldata(TRANSFER, "transfer(address,uint256)", substitutions={0: PRINCIPAL, 1: 7})
    assert data is not None
    assert data[10:74].endswith("22" * 20)
    assert int(data[74:], 16) == 7


def test_encode_calldata_fails_closed_on_bad_signature():
    assert cd.encode_calldata(TRANSFER, "transfer(address") is None
    assert cd.encode_calldata("0xzz", "transfer()") is None
    assert cd.encode_calldata(TRANSFER, "transfer(MyStruct)") is None


# ---------------------------------------------------------------------------
# §4.2 value-out
# ---------------------------------------------------------------------------


def test_value_out_uses_principal_and_nonzero_amount():
    facts = _token_facts()
    fn = cd.resolve_function(facts, TRANSFER)
    assert fn is not None
    spec = cd.synthesize_value_out(_candidate(TRANSFER), fn)
    assert spec is not None
    assert spec.principal == PRINCIPAL
    assert spec.calldata.startswith(TRANSFER)
    assert spec.calldata[10:74].endswith("22" * 20)  # recipient = principal
    assert int(spec.calldata[74:], 16) == cd.ARG_AMOUNT
    assert spec.sentinel_calldata is None  # no taint fact recorded
    assert spec.gate_ref == "gate:none"


def test_value_out_sentinel_lands_in_taint_slot():
    facts = _token_facts(
        legacy_value_flows={
            "transfer(address,uint256)": [
                {"direction": "out", "token_var": "token", "is_parameter": True, "method": "transfer"}
            ]
        }
    )
    fn = cd.resolve_function(facts, TRANSFER)
    assert fn is not None
    spec = cd.synthesize_value_out(_candidate(TRANSFER), fn)
    assert spec is not None
    assert spec.taint_param_reaches_sink is True
    assert spec.sentinel_address == cd.SENTINEL_ADDRESS
    assert spec.sentinel_calldata is not None
    # param 0 is the taint index → sentinel there, base calldata keeps the principal.
    assert spec.sentinel_calldata[10:74].endswith("ee" * 20)
    assert spec.calldata[10:74].endswith("22" * 20)


BATCH_SIG = "batchClaim(uint256[],address[])"
BATCH_SEL = "0x55556666"


def _batch_fn(signature: str = BATCH_SIG, names: list[str] | None = None) -> cd.FunctionFacts:
    return cd.FunctionFacts(
        full_name=signature,
        selector=BATCH_SEL,
        canonical_signature=signature,
        effect_info=_effect_info(
            signature,
            BATCH_SEL,
            value_flows=[{"kind": "callee_erc20_selector", "direction": "out", "origin": "body"}],
            parameter_names=names or ["ids", "recipients"],
        ),
        tree=None,
        legacy_value_flows=(),
    )


def _decode(calldata: str, signature: str) -> tuple[Any, ...]:
    from eth_abi.abi import decode as abi_decode

    types = cd._parse_arg_types(signature)
    assert types is not None
    return abi_decode(types, bytes.fromhex(calldata[10:]))


def test_a_batch_function_is_probed_with_a_non_empty_array():
    """G6-B. The encoder's default for a dynamic array is empty, and an empty
    array is a loop body that never runs — so the probe executed, moved nothing,
    and that non-observation was published and cached as a structural fact about
    a function whose body it never entered."""
    spec = cd.synthesize_value_out(_candidate(BATCH_SEL), _batch_fn())
    assert spec is not None
    ids, recipients = _decode(spec.calldata, BATCH_SIG)
    # Each element is what the SCALAR policy proves for that element type: ``ids``
    # is a handle, ``recipients`` is where a payout can be observed.
    assert ids == (cd.ARG_IDENTIFIER,)
    assert [a.lower() for a in recipients] == [PRINCIPAL.lower()]


def test_an_array_element_the_policy_cannot_prove_still_gets_a_slot():
    """A ``bytes[]`` has no honest element, and that is not a reason to send a
    length-0 array: an empty one is the cacheable false negative, a length-1 one
    is a call the contract itself gets to reject."""
    sig = "submit(bytes[])"
    spec = cd.synthesize_value_out(_candidate(BATCH_SEL), _batch_fn(sig, names=["payloads"]))
    assert spec is not None
    (payloads,) = _decode(spec.calldata, sig)
    assert payloads == (b"",)


# ---------------------------------------------------------------------------
# G6-A vacuous inputs
# ---------------------------------------------------------------------------


def test_an_unresolved_quantity_makes_the_inputs_vacuous():
    """``n`` is in no vocabulary and no lattice fact names it, so the probe sends
    a zero — and a zero-amount call that moves nothing says nothing about the
    function."""
    spec = cd.synthesize_value_out(_candidate(UNWRAP), _unwrap_fn())
    assert spec is not None
    assert int(spec.calldata[10:74], 16) == 0
    assert spec.inputs_vacuous is True


def test_a_probe_whose_every_slot_is_proven_is_not_vacuous():
    """The control that keeps the predicate honest: fire on these inputs and the
    flag would suppress every legitimate negative in the corpus."""
    facts = _token_facts()
    fn = cd.resolve_function(facts, TRANSFER)
    assert fn is not None
    spec = cd.synthesize_value_out(_candidate(TRANSFER), fn)
    assert spec is not None
    assert spec.inputs_vacuous is False


def test_an_array_of_proven_elements_is_not_vacuous():
    spec = cd.synthesize_value_out(_candidate(BATCH_SEL), _batch_fn())
    assert spec is not None
    assert spec.inputs_vacuous is False


def test_an_array_whose_element_is_filler_is_vacuous():
    """A length-1 array is the honest attempt, not a witness: the loop ran over a
    value nobody proved, so an empty result is a fact about the filler."""
    spec = cd.synthesize_value_out(_candidate(BATCH_SEL), _batch_fn("submit(bytes[])", names=["payloads"]))
    assert spec is not None
    assert spec.inputs_vacuous is True


def test_the_supply_plan_carries_the_same_fact():
    """G6-A spans both classes — ``no_supply_delta`` is cached on the same
    argument."""
    spec = cd.synthesize_supply(_candidate(BURN_SEL), _redeem_fn())
    assert spec is not None
    assert spec.inputs_vacuous is False


# ---------------------------------------------------------------------------
# §16.6-A executor inner-call synthesis
# ---------------------------------------------------------------------------

HELD_TOKEN = "0x" + "ab" * 20
_FORWARDS_PARAM = {
    "kind": "low_level_value_call",
    "direction": "out",
    "origin": "body",
    "from_is_self": True,
    "target_kind": {"kind": "param", "tier": "static_trace"},
}


def _exec_fn(signature: str, names: list[str], *, flows: list[dict[str, Any]], claims: Any = None) -> cd.FunctionFacts:
    info = _effect_info(signature, BATCH_SEL, value_flows=flows, parameter_names=names)
    if claims is not None:
        info["claims"] = claims
    return cd.FunctionFacts(
        full_name=signature,
        selector=BATCH_SEL,
        canonical_signature=signature,
        effect_info=info,
        tree=None,
        legacy_value_flows=(),
    )


def _executor_for(signature: str, names: list[str], **kw: Any) -> Any:
    fn = _exec_fn(signature, names, **kw)
    types = cd._parse_arg_types(signature)
    assert types is not None
    return cd.executor_call(fn, types, held_tokens=(HELD_TOKEN,), recipient=PRINCIPAL)


def test_an_upgrade_hook_is_not_an_executor():
    """The over-claim this recognizer has to refuse. ``upgradeToAndCall`` has the
    same ABI shape as an executor, but nothing proves it forwards a call — and
    writing a token into a proxy's implementation slot would run that token's code
    in the proxy's own storage, manufacturing a transfer out of the contract under
    probe."""
    assert _executor_for("upgradeToAndCall(address,bytes)", ["newImplementation", "data"], flows=[]) is None


def test_an_executor_with_two_payload_slots_synthesizes_nothing():
    """Fail closed on ambiguity: static proved the destination is caller-supplied
    but not WHICH argument is the forwarded calldata, and a transfer written into
    an argument that is not calldata is a probe input nobody can justify."""
    assert (
        _executor_for(
            "execTransaction(address,bytes,bytes)",
            ["to", "data", "signatures"],
            flows=[_FORWARDS_PARAM],
        )
        is None
    )


def test_the_lattice_names_the_executor_slots_when_the_claim_does_not():
    """OZ ``TimelockController.execute`` — non-etherfi, and its ``exec.arbitrary``
    claim carries no parameter names, so the slots come from the lattice's proof
    plus the only pair the ABI admits."""
    executor = _executor_for(
        "execute(address,uint256,bytes,bytes32,bytes32)",
        ["target", "value", "payload", "predecessor", "salt"],
        flows=[_FORWARDS_PARAM],
    )
    assert executor is not None
    assert executor.slots == (0, 2)
    assert executor.values[0] == HELD_TOKEN
    # An ERC-20 transfer to the probe's own identity — the standard selector, and
    # a recipient that is never the sentinel on the BASE probe.
    assert executor.values[2].hex().startswith("a9059cbb")
    assert PRINCIPAL[2:].lower() in executor.values[2].hex()


def test_the_claim_witness_names_the_executor_slots_directly():
    """Where static PROVED the two parameters, they are used verbatim rather than
    inferred from the ABI. A name counts only with its ``param`` kind — the kind
    is what separates a proved binding from a guess."""
    executor = _executor_for(
        "rebalance(address,address,uint256,bytes)",
        ["fromAsset", "toAsset", "amount", "swapData"],
        flows=[],
        claims=[
            {
                "claim_id": "exec.arbitrary",
                "witness": {
                    "kind": "param_taint",
                    "destination_param": "fromAsset",
                    "destination_kind": "param",
                    "calldata_param": "swapData",
                    "calldata_kind": "param",
                },
            }
        ],
    )
    assert executor is not None
    assert executor.slots == (0, 3)


def test_a_witness_that_names_no_binding_does_not_get_treated_as_one():
    """``state_var`` says no parameter is the destination — the LRTSquaredAdmin
    shape, where the call goes to a storage-held swapper. With two address
    parameters the ABI admits no unique pair either, so nothing is synthesized.

    The pre-fix witness named ``fromAsset`` here and this probe built an inner
    call around it."""
    executor = _executor_for(
        "rebalance(address,address,uint256,bytes)",
        ["fromAsset", "toAsset", "amount", "swapData"],
        flows=[],
        claims=[
            {
                "claim_id": "exec.arbitrary",
                "witness": {
                    "kind": "param_taint",
                    "destination_param": None,
                    "destination_kind": "state_var",
                    "calldata_param": None,
                    "calldata_kind": "call_argument",
                },
            }
        ],
    )
    assert executor is None


def test_a_kindless_legacy_witness_is_an_unread_question_not_a_proof():
    """Rows minted before the binding was proven carry two names and no kind.
    Absent is not-determined: the names are not used, and the slots fall through
    to the ABI-uniqueness reasoning, which needs the lattice's own proof."""
    witness = {"kind": "param_taint", "destination_param": "fromAsset", "calldata_param": "swapData"}
    claims = [{"claim_id": "exec.arbitrary", "witness": witness}]
    assert (
        _executor_for(
            "rebalance(address,address,uint256,bytes)",
            ["fromAsset", "toAsset", "amount", "swapData"],
            flows=[],
            claims=claims,
        )
        is None
    )
    # …and with the lattice's proof the ABI still admits no unique pair here, so
    # the fallback does not quietly reinstate the old answer either.
    assert (
        _executor_for(
            "rebalance(address,address,uint256,bytes)",
            ["fromAsset", "toAsset", "amount", "swapData"],
            flows=[_FORWARDS_PARAM],
            claims=claims,
        )
        is None
    )


def test_an_executor_with_no_inner_call_reports_vacuous_inputs():
    """The payload slot kept the encoder's empty bytes, so the call forwarded
    nothing — and forwarding nothing succeeds. Without this flag that success is
    published and CACHED as "this function moves no value"."""
    fn = _exec_fn("forward(address,bytes,uint256)", ["target", "data", "value"], flows=[_FORWARDS_PARAM])
    spec = cd.synthesize_value_out(_candidate(BATCH_SEL), fn)
    assert spec is not None
    assert spec.inputs_vacuous is True


def test_a_synthesized_inner_call_is_not_vacuous():
    """And the other direction: with the inner call built, the executor's other
    zeros are deliberate, not unfilled — a negative here IS about the function."""
    fn = _exec_fn("forward(address,bytes,uint256)", ["target", "data", "value"], flows=[_FORWARDS_PARAM])
    spec = cd.synthesize_value_out(_candidate(BATCH_SEL, holdings=(HELD_TOKEN,)), fn)
    assert spec is not None
    assert spec.inputs_vacuous is False


def test_an_executor_with_nothing_to_move_claims_nothing():
    """No measured holding, no honest inner call — the shape is still known, but
    the payload slot keeps the encoder's default."""
    fn = _exec_fn("forward(address,bytes,uint256)", ["target", "data", "value"], flows=[_FORWARDS_PARAM])
    types = cd._parse_arg_types(fn.canonical_signature)
    assert types is not None
    executor = cd.executor_call(fn, types, held_tokens=(), recipient=PRINCIPAL)
    assert executor is not None and not executor.values


def test_the_executor_probe_attaches_no_native_value_it_cannot_prove():
    """The quantity vocabulary would put one wei in ``values``, and a vault that
    does not hold it reverts on the very call this synthesis exists to observe."""
    fn = _exec_fn("forward(address[],bytes[],uint256[])", ["targets", "data", "values"], flows=[_FORWARDS_PARAM])
    spec = cd.synthesize_value_out(_candidate(BATCH_SEL, holdings=(HELD_TOKEN,)), fn)
    assert spec is not None
    _targets, _data, values = _decode(spec.calldata, "forward(address[],bytes[],uint256[])")
    assert values == (0,)


def test_value_out_none_without_a_value_flow():
    facts = _token_facts()
    fn = cd.resolve_function(facts, DEPOSIT)
    assert fn is not None
    assert cd.synthesize_value_out(_candidate(DEPOSIT), fn) is None


def test_value_out_none_without_a_resolved_principal():
    facts = _token_facts()
    fn = cd.resolve_function(facts, TRANSFER)
    assert fn is not None
    assert cd.synthesize_value_out(_candidate(TRANSFER, principals=()), fn) is None


def test_value_out_public_falls_back_to_neutral_caller():
    # A public value-mover has no FunctionPrincipal rows; it is still probed, from
    # the neutral identity, instead of being skipped.
    facts = _token_facts()
    fn = cd.resolve_function(facts, TRANSFER)
    assert fn is not None
    spec = cd.synthesize_value_out(_candidate(TRANSFER, principals=(), authority_public=True), fn)
    assert spec is not None
    assert spec.principal == cd.NEUTRAL_CALLER


def test_value_out_gated_without_principal_stays_none():
    facts = _token_facts()
    fn = cd.resolve_function(facts, TRANSFER)
    assert fn is not None
    assert cd.synthesize_value_out(_candidate(TRANSFER, principals=(), authority_public=False), fn) is None


def test_taint_without_a_recoverable_param_index_emits_no_sentinel():
    facts = _token_facts(
        legacy_value_flows={
            "transfer(address,uint256)": [
                {"direction": "out", "token_var": "unmapped", "is_parameter": True, "method": "transfer"}
            ]
        }
    )
    fn = cd.resolve_function(facts, TRANSFER)
    assert fn is not None
    spec = cd.synthesize_value_out(_candidate(TRANSFER), fn)
    assert spec is not None
    assert spec.sentinel_calldata is None
    assert spec.taint_param_reaches_sink is False


# --- the static lattice's recipient slot (``target_param_index``) ----------
#
# 76 of 78 live fund-out flows are native ETH sends, whose recipient the legacy
# ``token_var``/``is_parameter`` shape never named and whose slot the gate-operand
# name map cannot recover when no gate mentions the recipient. The flow lattice
# resolves the destination interprocedurally and reports WHICH entry parameter it
# is; that index is what makes a sentinel probe possible at all.

REDEEM = "0x7bde82f2"  # redeem(uint256,address)
REDEEM_SIG = "redeem(uint256,address)"


def _redeem_facts(*, flows: list[dict[str, Any]], legacy: list[dict[str, Any]] | None = None) -> cd.ContractFacts:
    """An ETH-redeem entry point whose recipient appears in NO gate — the shape
    the name->slot map is blind to."""
    effects = {REDEEM_SIG: _effect_info(REDEEM_SIG, REDEEM, value_flows=flows, parameter_names=["amount", "recipient"])}
    return cd.ContractFacts(
        address=CONTRACT,
        job_id="job-1",
        effects=effects,
        trees={REDEEM_SIG: OWNER_GATE},
        canonical_signatures={REDEEM_SIG: REDEEM_SIG},
        legacy_value_flows={REDEEM_SIG: legacy} if legacy else {},
        by_selector={REDEEM: REDEEM_SIG},
    )


def _eth_flow(**extra: Any) -> dict[str, Any]:
    flow: dict[str, Any] = {
        "kind": "low_level_value_call",
        "direction": "out",
        "origin": "body",
        "target_kind": {"kind": "param", "tier": "static_trace"},
    }
    flow.update(extra)
    return flow


def _redeem_spec(facts: cd.ContractFacts) -> Any:
    fn = cd.resolve_function(facts, REDEEM)
    assert fn is not None
    spec = cd.synthesize_value_out(_candidate(REDEEM), fn)
    assert spec is not None
    return spec


def test_lattice_param_index_plants_the_sentinel_without_a_gate_operand():
    spec = _redeem_spec(_redeem_facts(flows=[_eth_flow(target_param_index=1)]))
    assert spec.taint_param_reaches_sink is True
    assert spec.sentinel_address == cd.SENTINEL_ADDRESS
    assert spec.sentinel_calldata is not None
    # Slot 1 (the recipient) carries the sentinel; slot 0 (the amount) is
    # untouched, and the base probe keeps the principal in the recipient slot.
    assert int(spec.sentinel_calldata[10:74], 16) == cd.ARG_AMOUNT
    assert spec.sentinel_calldata[74:].endswith("ee" * 20)
    assert spec.calldata[74:].endswith("22" * 20)


def test_lattice_index_ignored_unless_the_kind_is_param():
    """The index only ever accompanies ``param``; a stale/foreign index on any
    other kind must not plant a probe."""
    for kind in ("immutable", "msg_sender", "storage_setter", "indeterminate"):
        flow = _eth_flow(target_param_index=1, target_kind={"kind": kind, "tier": "static_trace"})
        spec = _redeem_spec(_redeem_facts(flows=[flow]))
        assert spec.sentinel_calldata is None, kind
        assert spec.taint_param_reaches_sink is False, kind


def test_lattice_index_ignored_when_the_slot_is_not_an_address():
    spec = _redeem_spec(_redeem_facts(flows=[_eth_flow(target_param_index=0)]))  # uint256 amount
    assert spec.sentinel_calldata is None
    spec = _redeem_spec(_redeem_facts(flows=[_eth_flow(target_param_index=7)]))  # out of range
    assert spec.sentinel_calldata is None


def test_lattice_indexes_that_disagree_plant_nothing():
    flows = [_eth_flow(target_param_index=1), _eth_flow(kind="native_transfer_send", target_param_index=0)]
    spec = _redeem_spec(_redeem_facts(flows=flows))
    assert spec.sentinel_calldata is None


def test_lattice_guard_origin_flow_is_not_a_recipient():
    flow = _eth_flow(target_param_index=1, origin="guard")
    spec = _redeem_spec(_redeem_facts(flows=[flow, _eth_flow()]))
    assert spec.sentinel_calldata is None


def test_legacy_name_path_still_serves_a_flow_without_an_index():
    """The ERC-20 shape keeps resolving through the predicate-tree name map."""
    facts = _token_facts(
        legacy_value_flows={
            "transfer(address,uint256)": [
                {"direction": "out", "token_var": "token", "is_parameter": True, "method": "transfer"}
            ]
        }
    )
    fn = cd.resolve_function(facts, TRANSFER)
    assert fn is not None
    spec = cd.synthesize_value_out(_candidate(TRANSFER), fn)
    assert spec is not None and spec.sentinel_calldata is not None
    assert spec.sentinel_calldata[10:74].endswith("ee" * 20)


# --- the static lattice's QUANTITY slot (``amount_param_index``) ------------
#
# Which integer argument is the quantity was previously answered by a parameter
# NAME vocabulary (``_AMOUNT_WORDS``). For the whole ERC-4626 redemption class the
# amount is not an argument at all — it is a conversion of one — so the lattice
# publishes ``param_derived`` plus the slot of the input that fed the conversion,
# and the prober fills THAT slot. Every case below names the slot ``n``, a word in
# no vocabulary, so only a lattice fact can produce a role.

UNWRAP_SIG = "unwrap(uint256,address)"
UNWRAP = "0x11112222"


def _unwrap_fn(**flow_extra: Any) -> cd.FunctionFacts:
    flow: dict[str, Any] = {"kind": "callee_erc20_selector", "direction": "out", "origin": "body"}
    flow.update(flow_extra)
    return cd.FunctionFacts(
        full_name=UNWRAP_SIG,
        selector=UNWRAP,
        canonical_signature=UNWRAP_SIG,
        effect_info=_effect_info(UNWRAP_SIG, UNWRAP, value_flows=[flow], parameter_names=["n", "to"]),
        tree=None,
        legacy_value_flows=(),
    )


def test_param_derived_lattice_names_the_quantity_slot_without_a_name_hint():
    """The point of the change: ``n`` is in no word vocabulary, so a role here can
    only have come from the proven lattice fact."""
    fn = _unwrap_fn(amount_kind={"kind": "param_derived", "tier": "static_trace"}, amount_param_index=0)
    roles = cd.integer_param_roles(fn, ["uint256", "address"])
    assert roles == {0: cd.ROLE_AMOUNT}, roles


def test_unnamed_quantity_without_a_lattice_fact_gets_no_role():
    """The control: identical facts minus the lattice's answer leave the slot with
    no evidence, and the prober substitutes nothing."""
    fn = _unwrap_fn()
    assert cd.integer_param_roles(fn, ["uint256", "address"]) == {}
    fn = _unwrap_fn(amount_kind={"kind": "indeterminate", "tier": "static_trace"})
    assert cd.integer_param_roles(fn, ["uint256", "address"]) == {}


def test_param_derived_index_still_needs_an_integer_slot():
    """The type check is unchanged: a slot the lattice names but that is not an
    integer takes no quantity."""
    fn = _unwrap_fn(amount_kind={"kind": "param_derived", "tier": "static_trace"}, amount_param_index=1)
    assert cd.integer_param_roles(fn, ["uint256", "address"]) == {}


# ---------------------------------------------------------------------------
# §4.5 supply
# ---------------------------------------------------------------------------


def test_supply_from_mint_label():
    facts = _token_facts()
    fn = cd.resolve_function(facts, MINT)
    assert fn is not None
    spec = cd.synthesize_supply(_candidate(MINT), fn)
    assert spec is not None
    assert spec.token_address == CONTRACT
    assert spec.mint_calldata.startswith(MINT)
    assert int(spec.mint_calldata[74:], 16) == cd.ARG_AMOUNT
    assert spec.gate_ref == "gate:caller_authority"


BURN_SIG = "redeem(uint256,address)"
BURN_SEL = "0x33334444"


def _redeem_fn() -> cd.FunctionFacts:
    """A burn whose quantity and recipient slots carry no vocabulary name, so the
    only evidence about either is the static flow lattice — and the lattice
    records the burn's own movement under the direction the artifact actually
    emits (an outbound payout), never under ``burn``."""
    flow = {
        "kind": "callee_erc20_selector",
        "direction": "out",
        "origin": "body",
        "amount_kind": {"kind": "param", "tier": "static_trace"},
        "amount_param_index": 0,
        "target_kind": {"kind": "param", "tier": "static_trace"},
        "target_param_index": 1,
    }
    return cd.FunctionFacts(
        full_name=BURN_SIG,
        selector=BURN_SEL,
        canonical_signature=BURN_SIG,
        effect_info=_effect_info(
            BURN_SIG, BURN_SEL, effect_labels=["burn"], value_flows=[flow], parameter_names=["n", "dst"]
        ),
        tree=None,
        legacy_value_flows=(),
    )


def test_supply_reads_its_lattice_through_the_directions_flows_actually_carry():
    """S1. Filtering the supply plan's lattice reads by ``mint``/``burn`` rejected
    every flow an artifact emits, so the class got no quantity and no recipient."""
    spec = cd.synthesize_supply(_candidate(BURN_SEL), _redeem_fn())
    assert spec is not None
    # Nothing but the lattice can put the amount in slot 0: ``n`` is in no word
    # vocabulary, so a zero here means the plan never read the lattice.
    assert int(spec.mint_calldata[10:74], 16) == cd.ARG_AMOUNT
    # And the recipient the lattice named earns the sentinel probe the supply
    # class could never synthesize.
    assert spec.sentinel_calldata is not None
    assert spec.sentinel_calldata[74:138].endswith("ee" * 20)
    assert spec.taint_param_reaches_sink is True


def test_supply_none_for_a_non_supply_function():
    facts = _token_facts()
    fn = cd.resolve_function(facts, TRANSFER)
    assert fn is not None
    assert cd.synthesize_supply(_candidate(TRANSFER), fn) is None


def test_supply_public_falls_back_to_neutral_caller():
    facts = _token_facts()
    fn = cd.resolve_function(facts, MINT)
    assert fn is not None
    spec = cd.synthesize_supply(_candidate(MINT, principals=(), authority_public=True), fn)
    assert spec is not None
    assert spec.principal == cd.NEUTRAL_CALLER


def test_supply_gated_without_principal_stays_none():
    facts = _token_facts()
    fn = cd.resolve_function(facts, MINT)
    assert fn is not None
    assert cd.synthesize_supply(_candidate(MINT, principals=(), authority_public=False), fn) is None


# ---------------------------------------------------------------------------
# §4.4 authority-change
# ---------------------------------------------------------------------------


def test_authority_targets_the_gate_the_function_writes():
    effects = dict(_token_facts().effects)
    effects["setOwner(address)"] = _effect_info(
        "setOwner(address)", "0x13af4035", state_writes=[_write("owner", "address")]
    )
    facts = _token_facts(
        effects=effects,
        by_selector={info["selector"]: name for name, info in effects.items()},
        canonical_signatures={name: name for name in effects},
        trees={**_token_facts().trees, "setOwner(address)": OWNER_GATE},
    )
    fn = cd.resolve_function(facts, "0x13af4035")
    assert fn is not None
    spec = cd.synthesize_authority(_candidate("0x13af4035"), facts, fn)
    assert spec is not None
    # adminOnly() sorts before mint()/pause() among the owner-gated readers.
    assert spec.probe_function == "adminOnly()"
    assert spec.probe_calldata == ADMIN_ONLY
    assert spec.mutate_calldata == "0x13af4035" + "00" * 32


def test_guard_origin_normal_write_is_not_a_gate_target_basis():
    """The §4.4 analogue of the pause reader/writer split: a guard-origin ``normal``
    write is the modifier's own bookkeeping on F's gate, not an effect F causes, so
    it must not be read as "the state F mutates" when picking a gate target.

    Measured impact on the etherfi candidate set was zero (10 candidates carry such
    a write; none selected a different target) — the test exists so the filter is
    not dropped as dead code."""
    guard_write = {**_write("owner", "address"), "origin": "guard"}
    effects = dict(_token_facts().effects)
    effects["setOwner(address)"] = _effect_info("setOwner(address)", "0x13af4035", state_writes=[guard_write])
    facts = _token_facts(
        effects=effects,
        by_selector={info["selector"]: name for name, info in effects.items()},
        canonical_signatures={name: name for name in effects},
        trees={**_token_facts().trees, "setOwner(address)": OWNER_GATE},
    )
    fn = cd.resolve_function(facts, "0x13af4035")
    assert fn is not None
    # Same var and hygiene class as the body-origin case above — origin is the
    # only difference, and it is enough to withhold the plan.
    assert fn.effect_info["state_writes"][0]["var"] == "owner"
    assert fn.effect_info["state_writes"][0]["hygiene_class"] == "normal"
    assert cd._normal_state_pairs(fn) == set()
    assert cd.synthesize_authority(_candidate("0x13af4035"), facts, fn) is None


def test_authority_none_when_nothing_reads_the_written_state():
    facts = _token_facts()
    fn = cd.resolve_function(facts, PAUSE_SEL)
    assert fn is not None
    # `paused` is read by deposit(), but deposit()'s gate is not caller-authority.
    assert cd.synthesize_authority(_candidate(PAUSE_SEL), facts, fn) is None


# ---------------------------------------------------------------------------
# guard-set derivation + duration reading
# ---------------------------------------------------------------------------


def test_guarded_functions_only_counts_mandatory_paths():
    trees = {
        "mandatory()": _and(_leaf(_state("paused"))),
        "escapable()": _or(_leaf(_state("paused")), _leaf(_state("other"))),
        "unrelated()": _and(_leaf(_state("other"))),
    }
    assert cd.guarded_functions(trees, {("paused", None)}) == ["mandatory()"]


def test_guarded_functions_matches_a_namespaced_latch_across_member_paths():
    """The ERC-7201 shape: the WRITE fact has an empty member path, the READ
    operand carries ``["paused"]``. A strict pair match would find nothing."""
    trees = {"withdraw()": _and(_leaf(_state("PAUSABLE_STORAGE_SLOT", "paused")))}
    assert cd.guarded_functions(trees, {("PAUSABLE_STORAGE_SLOT", None)}) == ["withdraw()"]
    assert cd.guarded_functions(trees, {("OTHER_SLOT", None)}) == []


def _timestamp() -> dict[str, Any]:
    return {"source": "block_context", "block_context_kind": "timestamp"}


def _const(value: str) -> dict[str, Any]:
    return {"source": "constant", "constant_value": value}


def test_max_pause_duration_needs_a_comparison_SHAPE_not_three_facts_in_one_leaf():
    """INVERTED at Wave 4 (L-58). It used to assert ``(2592000, "guard_constant")``
    for a leaf holding the latch, the clock and the constant as three DIRECT operands
    — an arrangement no Solidity comparison produces (two slots) and one in which
    "which side is the constant on" has no answer at all. Since the harvest is now
    side- and operator-aware, that leaf is honestly undecidable.

    The three facts still resolve in the arrangement a compiler DOES emit, which the
    second half asserts: the clock-and-latch difference on one side, the constant on
    the other. So the inversion costs no real coverage — it removes a positive that
    could only ever be reached by a hand-built leaf, and 560 of the 5,089 persisted
    leaves locally really do carry three or more operands (threshold/oracle shapes),
    so admitting the arity was not free."""
    three_slots = _token_facts(
        trees={
            "unpause()": _and(
                _leaf(
                    _state("TIMED_SLOT", "pausedUntil"),
                    _timestamp(),
                    _const("2592000"),
                    operator="lt",
                )
            )
        }
    )
    assert cd.read_max_pause_duration(three_slots, {"TIMED_SLOT"}) == (None, "not_determined")

    # The same three facts as solc lowers them: ``block.timestamp - pausedUntil <
    # 2592000`` — two slots, the clock recovered from ``absorbed_operands``.
    compiled_shape = _token_facts(
        trees={
            "unpause()": _and(
                _leaf(
                    _state("TIMED_SLOT", "pausedUntil"),
                    _const("2592000"),
                    absorbed=[_timestamp(), _state("TIMED_SLOT", "pausedUntil")],
                    operator="lt",
                )
            )
        }
    )
    assert cd.read_max_pause_duration(compiled_shape, {"TIMED_SLOT"}) == (2592000, "guard_constant")


def test_max_pause_duration_is_not_determined_when_the_leaf_has_no_operator():
    """A leaf with no ``operator`` cannot say which side the constant bounds, so the
    harvest declines. Measured before relying on it: every one of the 5,089 predicate
    leaves persisted in the local database carries an operator, so this refuses
    nothing real — it keeps a hand-built or future partially-built leaf from being
    read as a proof by defaulting the direction."""
    facts = _token_facts(
        trees={
            "unpause()": _and(
                _leaf(
                    _state("TIMED_SLOT", "pausedUntil"),
                    _const("2592000"),
                    absorbed=[_timestamp(), _state("TIMED_SLOT", "pausedUntil")],
                )
            )
        }
    )
    assert cd.read_max_pause_duration(facts, {"TIMED_SLOT"}) == (None, "not_determined")


def test_max_pause_duration_treats_every_clock_spelling_as_a_clock():
    """``now`` (the pre-0.7 spelling of ``block.timestamp``) and ``block.number``
    arrive as ``block_context_kind`` "now" / "number". Both deny the
    proven-indefinite state — a block-number gate expires on its own schedule just
    as a timestamp gate does — so a latch compared against either lands on
    ``not_determined``, exactly like its ``block.timestamp`` twin."""
    for kind in ("now", "number"):
        facts = _token_facts(
            trees={
                "transfer(address)": _and(
                    _leaf(
                        _state("LATCH_SLOT", "frozen"),
                        {"source": "block_context", "block_context_kind": kind},
                    )
                )
            }
        )
        assert cd.read_max_pause_duration(facts, {"LATCH_SLOT"}) == (None, "not_determined"), kind


def test_max_pause_duration_never_publishes_a_block_count_as_seconds():
    """The units trap: ``require(block.number - pausedUntilBlock < 216000)`` holds a
    latch, a clock and a constant in one leaf — but the constant is a BLOCK COUNT.
    Harvesting it would publish 216000 "seconds" (2.5 days) for a ~30-day gate, a
    fabricated mitigating credit. Only second-denominated clocks (timestamp, now)
    feed the constant harvest; the block-number clock still demotes the proven
    state."""
    facts = _token_facts(
        trees={
            "transfer(address)": _and(
                _leaf(
                    _state("LATCH_SLOT", "pausedUntilBlock"),
                    {"source": "block_context", "block_context_kind": "number"},
                    {"source": "constant", "constant_value": "216000"},
                )
            )
        }
    )
    assert cd.read_max_pause_duration(facts, {"LATCH_SLOT"}) == (None, "not_determined")
    # ``now`` IS the seconds clock, so the same guard one clock spelling over — the
    # difference-and-ceiling shape, as solc lowers it — resolves the window.
    now_facts = _token_facts(
        trees={
            "transfer(address)": _and(
                _leaf(
                    _state("LATCH_SLOT", "pausedUntil"),
                    _const("2592000"),
                    absorbed=[
                        {"source": "block_context", "block_context_kind": "now"},
                        _state("LATCH_SLOT", "pausedUntil"),
                    ],
                    operator="lt",
                )
            )
        }
    )
    assert cd.read_max_pause_duration(now_facts, {"LATCH_SLOT"}) == (2592000, "guard_constant")


def test_max_pause_duration_refuses_a_leaf_that_mixes_two_CLOCKS():
    """L-60: a leaf whose operand union carries BOTH a seconds clock and
    ``block.number`` cannot say which clock its constant is denominated against, and
    the seconds clock alone used to be enough to enter the harvest — so 216000 blocks
    (~30 days) would publish as 216000 seconds (2.5 days), the fabricated mitigating
    credit the units trap exists to stop. No single compiled comparison produces this
    (one comparison holds one comparison); operand ABSORPTION across a mixed
    expression is what makes it reachable, which is why it is built by hand here."""
    facts = _token_facts(
        trees={
            "transfer(address)": _and(
                _leaf(
                    _state("LATCH_SLOT", "pausedUntil"),
                    _const("216000"),
                    absorbed=[
                        _timestamp(),
                        {"source": "block_context", "block_context_kind": "number"},
                        _state("LATCH_SLOT", "pausedUntil"),
                    ],
                    operator="lt",
                )
            )
        }
    )
    assert cd.read_max_pause_duration(facts, {"LATCH_SLOT"}) == (None, "not_determined")


def test_max_pause_duration_reads_a_constant_the_comparison_absorbed():
    """THE POSITIVE CASE ON REAL COMPILER OUTPUT (A7 / L-16, R4), narrowed at Wave 4
    to the shape it can actually PROVE (L-58).

    A Solidity comparison lowers to a leaf with two operands and the reader needs
    three facts, so ``absorbed_operands`` is the sibling list that recovers the third.
    What the union alone does NOT say is which side each fact sat on and with which
    sign — and the harvest used to take the largest plausible constant out of it, so
    ``require(block.timestamp + 3600 < pausedUntil)`` published 3600 as the freeze
    window (a LEAD TIME) and ``require(block.timestamp > pausedUntil + 300)``
    published 300 (a COOLDOWN offset), for latches whose real expiry is a storage
    timestamp. Both are severity REDUCERS, which is the direction that matters.

    The provable shape, and the only one admitted: the CLOCK and the LATCH sit in the
    same absorbed additive group (so the compared side is their signed time
    difference — which no lossy two-slot list can fake and both subtraction orders
    bound identically) and the constant is that difference's ceiling by side and
    operator. Three compiled variants of it, all asserted below.

    ``require(block.timestamp < pausedUntil + MAX_PAUSE)`` — absorbed group
    ``{latch, constant}`` — is the recall this narrowing costs, and it is a MISSING
    PRODUCER FACT rather than a judgment: ``predicates._stamp_absorbed_operands``
    sorts both inner operands of an ADDITION or a SUBTRACTION into one list and keeps
    neither the sign nor the side, so ``pausedUntil + MAX_PAUSE`` and
    ``pausedUntil - MAX_PAUSE`` are byte-identical here and only the first makes the
    constant a window. Stamping the sign in the static plane restores it provably.
    Pinned as ``not_determined`` below so the day that lands, this test is what
    records the change."""
    latch = _state("TIMED_SLOT", "pausedUntil")
    difference = [_timestamp(), _state("TIMED_SLOT", "pausedUntil")]

    # `block.timestamp - pausedUntil < 2592000` → constant on the right under `lt`.
    right = _token_facts(
        trees={
            "transferTimed(address,uint256)": _and(_leaf(latch, _const("2592000"), absorbed=difference, operator="lt"))
        }
    )
    assert cd.read_max_pause_duration(right, {"TIMED_SLOT"}) == (2592000, "guard_constant")
    # `2592000 > block.timestamp - pausedUntil` → the same fact, mirrored.
    left = _token_facts(
        trees={
            "transferTimed(address,uint256)": _and(_leaf(_const("2592000"), latch, absorbed=difference, operator="gt"))
        }
    )
    assert cd.read_max_pause_duration(left, {"TIMED_SLOT"}) == (2592000, "guard_constant")
    # NEGATIVE CONTROL: the absorbed operands are still scoped to the latch, so a
    # different latch in the same contract inherits nothing.
    assert cd.read_max_pause_duration(right, {"OTHER_SLOT"}) == (None, "not_determined")

    # `block.timestamp - pausedUntil > 600` — the SAME operand union, the operator
    # flipped: a MINIMUM elapsed (a cooldown), not a window ceiling.
    cooldown = _token_facts(
        trees={"transferTimed(address,uint256)": _and(_leaf(latch, _const("600"), absorbed=difference, operator="gt"))}
    )
    assert cd.read_max_pause_duration(cooldown, {"TIMED_SLOT"}) == (None, "not_determined")

    # `block.timestamp + 3600 < pausedUntil` (L-58a): the absorbed group is
    # {clock, constant} — a lead time on the CLOCK, and the latch is the other slot.
    lead_time = _token_facts(
        trees={
            "transferTimed(address,uint256)": _and(
                _leaf(
                    {"source": "computed", "computed_kind": "BinaryType.ADDITION"},
                    latch,
                    absorbed=[_timestamp(), _const("3600")],
                    operator="lt",
                )
            )
        }
    )
    assert cd.read_max_pause_duration(lead_time, {"TIMED_SLOT"}) == (None, "not_determined")

    # `block.timestamp > pausedUntil + 300` (L-58b) and
    # `block.timestamp < pausedUntil + MAX_PAUSE` (the deferred family): absorbed group
    # {latch, constant}, sign unrecorded → undecidable either way.
    for operator, constant in (("gt", "300"), ("lt", "2592000")):
        offset = _token_facts(
            trees={
                "transferTimed(address,uint256)": _and(
                    _leaf(
                        _timestamp(),
                        latch,
                        absorbed=[_const(constant), _state("TIMED_SLOT", "pausedUntil")],
                        operator=operator,
                    )
                )
            }
        )
        assert cd.read_max_pause_duration(offset, {"TIMED_SLOT"}) == (None, "not_determined"), operator


def test_max_pause_duration_ignores_a_constant_belonging_to_another_latch():
    """Two latches, one timed: the indefinite one must NOT inherit the bound."""
    facts = _token_facts(
        trees={
            "unpauseUntil()": _and(
                _leaf(
                    _state("TIMED_SLOT", "pausedUntil"),
                    {"source": "block_context", "block_context_kind": "timestamp"},
                    {"source": "constant", "constant_value": "2592000"},
                )
            )
        }
    )
    # ``not_determined``, NOT the proven-indefinite state: this contract's other
    # latch was never seen in a lowered guard here, and absence of a bound is not
    # proof that no bound exists.
    assert cd.read_max_pause_duration(facts, {"INDEFINITE_SLOT"}) == (None, "not_determined")


def test_max_pause_duration_is_never_scraped_from_a_constant_name():
    """A bound reaches the claim witness as a severity REDUCER, so it may only come
    from a constant the latch's own guard leaf compares ``block.timestamp``
    against. Source text naming a PAUSE/FREEZE constant is identifier matching: the
    same pattern catches a cooldown or a minimum, and publishing one of those would
    discount an indefinite freeze."""
    facts = _token_facts(trees={"unpause()": _and(_leaf(_state("TIMED_SLOT", "pausedUntil")))})
    # The guard reads the latch but compares it against nothing time-shaped, so no
    # constant in the unit is provably this latch's window — and because a lowered
    # guard DOES read the latch and no clock appears beside it, that is the PROVEN
    # indefinite state rather than an unmeasured one.
    assert cd.read_max_pause_duration(facts, {"TIMED_SLOT"}) == (None, "no_time_reference")
    # And the reader takes no session at all: there is no source plane to consult.
    assert "session" not in inspect.signature(cd.read_max_pause_duration).parameters


def test_a_clock_in_a_sibling_leaf_denies_the_proven_indefinite_state():
    """A lowered ``||`` splits the latch and the clock into SEPARATE leaves, so
    "no leaf reading the latch touches a clock" is not proof that time cannot lift
    the freeze.

    The two leaves below are copied from compiled output: ``require(!frozen ||
    block.timestamp > unpauseAt)`` at solc 0.8.27 yields one leaf whose operands are
    ``{frozen}`` and a sibling whose operands are ``{timestamp, unpauseAt}``. The
    freeze DEMONSTRABLY expires, and the leaf-local reading published
    ``no_time_reference`` — documented as *PROVEN indefinite, the most severe freeze
    there is* — for it.

    This is the whole two-variable timed-pause family, not a curiosity:
    ``_latch_pairs`` admits only ``bool``-typed writes (or the ERC-7201 pseudo-slot),
    and a ``bool`` can never be compared against ``block.timestamp`` in ANY leaf, so
    ``bool paused`` + ``uint pauseExpiry`` could only ever land on ``not_determined``
    or on the proven-most-severe state."""
    disjunction = _or(
        _leaf(_state("frozen")),
        _leaf(
            {"source": "block_context", "block_context_kind": "timestamp"},
            _state("unpauseAt"),
        ),
    )
    facts = _token_facts(trees={"transfer(address,uint256)": disjunction})
    assert cd.read_max_pause_duration(facts, {"frozen"}) == (None, "not_determined")
    # The clock-bearing var is not a latch this reader can bound either — the window
    # is a stored timestamp, not an offset in the code.
    assert cd.read_max_pause_duration(facts, {"unpauseAt"}) == (None, "not_determined")
    # POSITIVE CONTROL, same reader, same run: a latch whose OWN tree reads no clock
    # anywhere still reaches the proven state, so this is a discrimination and not a
    # blanket demotion.
    with_indefinite = _token_facts(
        trees={
            "transfer(address,uint256)": disjunction,
            "transferFreezable(address,uint256)": _and(_leaf(_state("halted"))),
        }
    )
    assert cd.read_max_pause_duration(with_indefinite, {"halted"}) == (None, "no_time_reference")


def test_a_pre_widening_tree_can_never_prove_an_indefinite_latch():
    """``absorbed_operands`` absent means two different things, and only the root
    marker separates them.

    ``require(block.timestamp - pausedUntil < 2592000)`` compiles to ONE leaf whose
    ``operands`` are ``{pausedUntil, 2592000}`` — the clock is absorbed into the
    subtraction and dropped. Read with the absorbed list, that is
    ``(2592000, "guard_constant")``. Read WITHOUT it — the shape of every
    ``contract_materializations.predicate_trees`` row written before A7, and an R5
    bump does not re-run the static stage — the clock is simply not there, and the
    leaf-local reader called it PROVEN INDEFINITE: the same source, the opposite
    answer, in the severe direction.

    So the proven state requires the marker the builder stamps. Its practical effect
    is that ``no_time_reference`` has zero realised rows in this database until the
    static stage re-runs, which is the honest reading of the evidence rather than a
    dead branch (it fires from compiled source in
    ``test_label_corpus_discrimination``)."""
    absorbed = [
        {"source": "block_context", "block_context_kind": "timestamp"},
        _state("pausedUntil"),
    ]
    leaf = _leaf(
        _state("pausedUntil"), {"source": "constant", "constant_value": "2592000"}, absorbed=absorbed, operator="lt"
    )
    post = _token_facts(trees={"transfer(address,uint256)": _and(leaf)})
    assert cd.read_max_pause_duration(post, {"pausedUntil"}) == (2592000, "guard_constant")

    # The persisted pre-A7 shape: the sibling key never existed, so the clock is gone.
    stripped = copy.deepcopy(post.trees["transfer(address,uint256)"])
    for stripped_leaf in cd._all_leaves(stripped):
        stripped_leaf.pop("absorbed_operands", None)
    stripped.pop("operand_absorption", None)
    pre = _token_facts(trees={"transfer(address,uint256)": stripped})
    assert cd.read_max_pause_duration(pre, {"pausedUntil"}) == (None, "not_determined")

    # And the marker is not a rubber stamp for the CLOCK-FREE shape either: the same
    # unmarked tree carrying a genuinely clock-free latch guard is still unknown,
    # because a two-slot list may have dropped the clock there too.
    unmarked_bool = {"op": "AND", "children": [_leaf(_state("halted"))]}
    assert cd.read_max_pause_duration(_token_facts(trees={"t()": unmarked_bool}), {"halted"}) == (
        None,
        "not_determined",
    )
    # POSITIVE CONTROL: mark it and the same tree proves the indefinite latch.
    assert cd.read_max_pause_duration(_token_facts(trees={"t()": _and(_leaf(_state("halted")))}), {"halted"}) == (
        None,
        "no_time_reference",
    )


OPAQUE_OPERANDS = (
    {"source": "computed", "computed_kind": "arithmetic"},
    {"source": "top"},
    # An operand that only NAMES a callee: the recorder is additive and one level
    # deep, and it never enters a function body, so ``_blockTimestamp()`` (Uniswap
    # V3), ``clock()`` (OZ Governor) or a time oracle is a clock nobody read.
    {"source": "view_call", "callee": "_clock()"},
    {"source": "external_call", "callee": "nowSeconds"},
)


def test_an_unread_operand_denies_the_proven_indefinite_state():
    """The marker promises only what the recorder does — ADDITIVE, one level deep,
    and never into a callee — so an operand standing for an expression nobody
    decomposed denies the proof.

    ``block.timestamp / 2 > pausedUntil`` records ``{computed, pausedUntil}``: the
    recorder skips a quotient by design (an offset is additive; a product or a
    quotient carries no window length), so the clock sits INSIDE an operand that was
    never read. Concluding "no leaf reading this latch touches a clock" from that is
    the same proof-by-absence in a marked tree. ``view_call``/``external_call`` are
    the same fact about a callee — see ``test_pause_duration_clock_opacity.py`` for
    the compiled shape."""
    for opaque in OPAQUE_OPERANDS:
        facts = _token_facts(trees={"transfer(address,uint256)": _and(_leaf(_state("pausedUntil"), opaque))})
        assert cd.read_max_pause_duration(facts, {"pausedUntil"}) == (None, "not_determined"), opaque
    # POSITIVE CONTROL: the same leaf shape with a FULLY READ second operand keeps
    # the proven state — the demotion is about the unread operand, not arity.
    readable = _and(_leaf(_state("pausedUntil"), {"source": "constant", "constant_value": "0"}))
    assert cd.read_max_pause_duration(_token_facts(trees={"t()": readable}), {"pausedUntil"}) == (
        None,
        "no_time_reference",
    )


def test_an_unread_operand_in_a_sibling_leaf_denies_the_proven_indefinite_state():
    """The opacity test is asked of the whole latch-reading TREE, exactly like the
    clock walk — a lowered ``||`` puts the unread operand in the sibling leaf.

    ``require(!frozen || _clock() > unpauseAt)`` compiles to ``{frozen}`` and
    ``{view_call _clock(), unpauseAt}``. The leaf that reads the latch is a
    single-operand equality — fully read, no clock — so a leaf-local opacity test saw
    a clean tree and published PROVEN indefinite for a freeze that expires at
    ``unpauseAt``. Neither precondition caught it: there is no ``block_context``
    operand anywhere for the clock walk to find."""
    for opaque in OPAQUE_OPERANDS:
        disjunction = _or(_leaf(_state("frozen")), _leaf(opaque, _state("unpauseAt")))
        facts = _token_facts(trees={"transfer(address,uint256)": disjunction})
        assert cd.read_max_pause_duration(facts, {"frozen"}) == (None, "not_determined"), opaque
    # POSITIVE CONTROL, same disjunction shape: a sibling leaf whose operands were
    # ALL read keeps the proven state, so the demotion tracks opacity and not the
    # mere presence of a sibling leaf.
    read_sibling = _or(
        _leaf(_state("frozen")),
        _leaf(_state("minDeposit"), {"source": "parameter", "parameter_name": "amount"}),
    )
    assert cd.read_max_pause_duration(_token_facts(trees={"t()": read_sibling}), {"frozen"}) == (
        None,
        "no_time_reference",
    )


# ---------------------------------------------------------------------------
# §4.1 pause (DB-backed: claims / principals / entry points)
# ---------------------------------------------------------------------------


def _pause_contract(session) -> tuple[Contract, dict[str, int]]:
    proto = Protocol(name=f"p4-{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()
    contract = Contract(protocol_id=proto.id, address=CONTRACT, chain="ethereum", is_proxy=False)
    session.add(contract)
    session.flush()
    ids: dict[str, int] = {}
    for name, selector in (("pause", PAUSE_SEL), ("deposit", DEPOSIT), ("adminOnly", ADMIN_ONLY)):
        fn = EffectiveFunction(
            contract_id=contract.id,
            function_name=name,
            selector=selector,
            authority_public=False,
            effect_targets=["paused"],
        )
        session.add(fn)
        session.flush()
        ids[selector] = fn.id
    session.add(FunctionPrincipal(function_id=ids[DEPOSIT], address=PRINCIPAL))
    session.commit()
    return contract, ids


@requires_postgres
def test_synthesize_pause_entry_points_fixtures_and_denominator(db_session):
    contract, ids = _pause_contract(db_session)
    facts = _token_facts()
    fn = cd.resolve_function(facts, PAUSE_SEL)
    assert fn is not None
    candidate = Candidate(
        function_id=ids[PAUSE_SEL],
        contract_id=contract.id,
        contract_address=CONTRACT,
        selector=PAUSE_SEL,
        function_name="pause",
        authority_public=False,
        principal_addresses=(PRINCIPAL,),
    )
    spec = cd.synthesize_pause(db_session, candidate, facts, fn)
    assert spec is not None
    assert spec.pause_calldata == PAUSE_SEL
    assert spec.predicted_guard_set == ("deposit()",)
    assert [ep.key for ep in spec.entry_points] == ["deposit()"]
    # deposit() has a resolved principal, so the probe impersonates it.
    assert spec.entry_points[0].from_addr == PRINCIPAL
    assert spec.entry_points[0].calldata == DEPOSIT
    assert [fx.kind for fx in spec.entry_points[0].fixtures] == ["set_balance"]
    assert spec.entry_points[0].fixtures[0].address == PRINCIPAL
    assert all(fx.kind == "set_balance" for fx in spec.fixtures)
    assert {fx.address for fx in spec.fixtures} == {PRINCIPAL}


@requires_postgres
def test_synthesize_pause_falls_back_to_state_changing_entry_points(db_session):
    """No tree predicts a reader (static under-enumerated) ⇒ probe every
    state-changing entry point, keep the empty denominator, let §9 file the
    vocabulary-growth discrepancy for anything the diff witnesses."""
    contract, ids = _pause_contract(db_session)
    facts = _token_facts(trees={"pause()": OWNER_GATE})  # nothing reads `paused`
    fn = cd.resolve_function(_token_facts(), PAUSE_SEL)
    assert fn is not None
    candidate = Candidate(
        function_id=ids[PAUSE_SEL],
        contract_id=contract.id,
        contract_address=CONTRACT,
        selector=PAUSE_SEL,
        function_name="pause",
        authority_public=False,
        principal_addresses=(PRINCIPAL,),
    )
    spec = cd.synthesize_pause(db_session, candidate, facts, fn)
    assert spec is not None
    assert spec.predicted_guard_set == ()  # the scored denominator stays static's
    probed = {ep.key for ep in spec.entry_points}
    assert "deposit()" in probed and "transfer(address,uint256)" in probed
    assert "pause()" not in probed
    # An entry point with no resolved principal is still probed, from a neutral
    # identity that is NOT the attacker sentinel.
    transfer_ep = next(ep for ep in spec.entry_points if ep.key == "transfer(address,uint256)")
    assert transfer_ep.from_addr == cd.NEUTRAL_CALLER


@requires_postgres
def test_synthesize_pause_adds_pauser_identity_probe_for_unresolved_victim(db_session):
    """§1 A2 follow-up (cause a): a PREDICTED victim with no resolved principal is
    additionally probed from the PAUSE principal, so a freeze the neutral caller
    can't reach pre-pause is still witnessed. Union semantics via a shared key."""
    proto = Protocol(name=f"pauser-probe-{uuid.uuid4().hex[:8]}")
    db_session.add(proto)
    db_session.flush()
    contract = Contract(protocol_id=proto.id, address=CONTRACT, chain="ethereum", is_proxy=False)
    db_session.add(contract)
    db_session.flush()
    ids: dict[str, int] = {}
    for name, selector in (("pause", PAUSE_SEL), ("deposit", DEPOSIT), ("transfer", TRANSFER)):
        f = EffectiveFunction(
            contract_id=contract.id,
            function_name=name,
            selector=selector,
            authority_public=False,
            effect_targets=["paused"],
        )
        db_session.add(f)
        db_session.flush()
        ids[selector] = f.id
    # deposit() has a resolved principal; transfer() does NOT (the unresolved victim).
    db_session.add(FunctionPrincipal(function_id=ids[DEPOSIT], address=PRINCIPAL))
    db_session.commit()

    # Both deposit() and transfer() read the `paused` latch → both predicted victims.
    # transfer() is ALSO behind a caller-authority gate (its principal is unresolved),
    # so the neutral caller can't reach it — the pauser-identity probe target.
    pause_and_auth = _and(_leaf(_state("paused")), _leaf(_state("owner"), authority_role="caller_authority"))
    facts = _token_facts(
        trees={
            "pause()": OWNER_GATE,
            "deposit()": PAUSE_GATE,
            "transfer(address,uint256)": pause_and_auth,
        }
    )
    fn = cd.resolve_function(facts, PAUSE_SEL)
    assert fn is not None
    candidate = Candidate(
        function_id=ids[PAUSE_SEL],
        contract_id=contract.id,
        contract_address=CONTRACT,
        selector=PAUSE_SEL,
        function_name="pause",
        authority_public=False,
        principal_addresses=(PRINCIPAL,),
    )
    spec = cd.synthesize_pause(db_session, candidate, facts, fn)
    assert spec is not None
    by_key: dict[str, list[str | None]] = {}
    for ep in spec.entry_points:
        by_key.setdefault(ep.key, []).append(ep.from_addr)
    # transfer() (unresolved) is probed from BOTH the neutral caller and the pauser.
    assert set(by_key["transfer(address,uint256)"]) == {cd.NEUTRAL_CALLER, PRINCIPAL}
    # deposit() (resolved) keeps a single probe from its own principal — no dup.
    assert by_key["deposit()"] == [PRINCIPAL]


@requires_postgres
def test_pause_fallback_set_gets_no_pauser_identity_probes(db_session):
    """When static predicts nothing (empty guard set → probe-everything fallback),
    NO pauser-identity probes are added — the recovery is scoped to the predicted
    victims, so a contract whose pause gates nothing gains no extra work."""
    contract, ids = _pause_contract(db_session)
    facts = _token_facts(trees={"pause()": OWNER_GATE})  # nothing reads `paused`
    fn = cd.resolve_function(_token_facts(), PAUSE_SEL)
    assert fn is not None
    candidate = Candidate(
        function_id=ids[PAUSE_SEL],
        contract_id=contract.id,
        contract_address=CONTRACT,
        selector=PAUSE_SEL,
        function_name="pause",
        authority_public=False,
        principal_addresses=(PRINCIPAL,),
    )
    spec = cd.synthesize_pause(db_session, candidate, facts, fn)
    assert spec is not None
    assert spec.predicted_guard_set == ()
    # No key appears twice: no pauser-identity probe was added to the fallback set.
    keys = [ep.key for ep in spec.entry_points]
    assert len(keys) == len(set(keys))


# ---------------------------------------------------------------------------
# fact loading / thin-fact fail-closed
# ---------------------------------------------------------------------------


@requires_postgres
def test_synthesize_is_empty_without_artifacts(db_session):
    assert cd.synthesize(db_session, _candidate(TRANSFER)) == cd.CandidatePlanInputs()


@requires_postgres
def test_load_contract_facts_indexes_the_canonical_selector(db_session):
    address = "0x" + "cd" * 20
    job = create_job(db_session, {"address": address, "name": "T"})
    # abi_signature/full_name carries a contract-typed param; the canonical map is
    # the only source that recovers the real selector for it.
    full_name = "sweep(IERC20,uint256)"
    canonical = "sweep(address,uint256)"
    store_artifact(
        db_session,
        job.id,
        "effects",
        data={"functions": {full_name: _effect_info(full_name, "0xdeadbeef")}},
    )
    store_artifact(
        db_session,
        job.id,
        "predicate_trees",
        data={"trees": {full_name: OWNER_GATE}, "canonical_signatures": {full_name: canonical}},
    )
    cd._FACTS_CACHE.pop(db_session, None)
    facts = cd.load_contract_facts(db_session, address)
    assert facts is not None
    selector = cd._selector_of(canonical)
    assert selector is not None
    assert facts.by_selector[selector] == full_name
    resolved = cd.resolve_function(facts, selector)
    assert resolved is not None
    assert resolved.canonical_signature == canonical


# ---------------------------------------------------------------------------
# Live-acceptance fixtures (recorded from the 2026-07-21 mainnet-fork run).
# Expected VALUES only — the logic below never matches on any of these names.
# ---------------------------------------------------------------------------

EETH_IMPL = "0xd1901dd36cbf4a81386d0162df2707f7ddb60527"
EETH_PROXY = "0x35fa164735182de50811e8e2e824cfb9b6118ac2"
LIQUIDITY_POOL = "0x308861a430be4cce5502d0a12724771fc6daf216"
OPERATING_MULTISIG = "0x2aca71020de61bb532008049e1bd41e451ae8adc"
PAUSABLE_SLOT = "PAUSABLE_STORAGE_SLOT"
PAUSABLE_UNTIL_SLOT = "PAUSABLE_UNTIL_STORAGE_SLOT"

# The four functions eETH's whenNotPaused actually covers.
EETH_GUARDED = (
    "burnShares(address,uint256)",
    "mintShares(address,uint256)",
    "transfer(address,uint256)",
    "transferFrom(address,address,uint256)",
)


def _eeth_facts(latch_var: str) -> cd.ContractFacts:
    """eETH-shaped artifacts: an ERC-7201 latch written with an EMPTY member path
    and read with member ``paused``; ``canonical_signatures`` ABSENT (the common
    case — the artifact omits it when canonical == full_name)."""
    guarded_tree = _and(_leaf(_state(latch_var, "paused")))
    effects = {
        "pause()": _effect_info(
            "pause()",
            "0x8456cb59",
            state_writes=[
                {
                    "var": latch_var,
                    "declared_type": "bytes32",
                    "member_path": [],
                    "granularity": "var",
                    "hygiene_class": "storage_location_pseudo",
                    "origin": "body",
                }
            ],
        ),
        "approve(address,uint256)": _effect_info("approve(address,uint256)", "0x095ea7b3"),
    }
    trees = {"pause()": OWNER_GATE}
    for name in EETH_GUARDED:
        # Faithful to the real artifact: a guarded function records the SAME latch
        # var and hygiene class as the pauser, distinguished only by origin.
        effects[name] = _effect_info(
            name,
            "",
            state_writes=[
                {
                    "var": latch_var,
                    "declared_type": "bytes32",
                    "member_path": [],
                    "granularity": "var",
                    "hygiene_class": "storage_location_pseudo",
                    "origin": "guard",
                }
            ],
            # eETH's real ABI names: the trailing quantity is ``_amount`` on each.
            parameter_names=["_sender", "_recipient", "_amount"]
            if name.startswith("transferFrom")
            else ["_recipient", "_amount"],
        )
        trees[name] = guarded_tree
    return cd.ContractFacts(
        address=EETH_IMPL,
        job_id="4d804a6d-2699-436b-9282-861eb8233600",
        effects=effects,
        trees=trees,
        canonical_signatures={},
        legacy_value_flows={},
        by_selector={cd._selector_of(name) or name: name for name in effects},
    )


def _eeth_candidate(session, latch_var: str) -> tuple[Candidate, dict[str, int]]:
    proto = Protocol(name=f"eeth-{uuid.uuid4().hex[:8]}")
    session.add(proto)
    session.flush()
    contract = Contract(protocol_id=proto.id, address=EETH_IMPL, chain="ethereum", is_proxy=False)
    session.add(contract)
    session.flush()
    ids: dict[str, int] = {}
    for full_name in ("pause()", *EETH_GUARDED, "approve(address,uint256)"):
        fn = EffectiveFunction(
            contract_id=contract.id,
            deployment_address=EETH_PROXY,
            function_name=full_name.split("(")[0],
            selector=cd._selector_of(full_name),
            authority_public=False,
            effect_targets=[latch_var],
        )
        session.add(fn)
        session.flush()
        ids[full_name] = fn.id
    # mintShares/burnShares are gated to the LiquidityPool — their own principal.
    for full_name in ("mintShares(address,uint256)", "burnShares(address,uint256)"):
        session.add(FunctionPrincipal(function_id=ids[full_name], address=LIQUIDITY_POOL))
    session.add(FunctionPrincipal(function_id=ids["pause()"], address=OPERATING_MULTISIG))
    session.commit()
    candidate = Candidate(
        function_id=ids["pause()"],
        contract_id=contract.id,
        contract_address=EETH_IMPL,
        selector=cd._selector_of("pause()"),
        function_name="pause",
        authority_public=False,
        principal_addresses=(OPERATING_MULTISIG,),
        deployment_address=EETH_PROXY,
    )
    return candidate, ids


@requires_postgres
def test_acceptance_eeth_pause_matches_the_live_fork_run(db_session):
    """Live target: guard set {transfer, transferFrom, mintShares, burnShares},
    per-entry-point principals, 1-wei amounts, probes against the PROXY, and no
    duration bound for the indefinite latch."""
    facts = _eeth_facts(PAUSABLE_SLOT)
    candidate, _ids = _eeth_candidate(db_session, PAUSABLE_SLOT)
    fn = cd.resolve_function(facts, candidate.selector)
    assert fn is not None
    spec = cd.synthesize_pause(db_session, candidate, facts, fn)
    assert spec is not None

    assert spec.predicted_guard_set == EETH_GUARDED
    assert tuple(ep.key for ep in spec.entry_points) == EETH_GUARDED
    # REQUIREMENT C: every probe targets the deployment, never the implementation.
    assert spec.contract_address == EETH_PROXY
    # REQUIREMENT A: per-entry-point principals.
    by_key = {ep.key: ep for ep in spec.entry_points}
    assert by_key["mintShares(address,uint256)"].from_addr == LIQUIDITY_POOL
    assert by_key["burnShares(address,uint256)"].from_addr == LIQUIDITY_POOL
    assert by_key["transfer(address,uint256)"].from_addr == cd.NEUTRAL_CALLER
    # REQUIREMENT B: 1-wei amount, address params filled with the caller.
    transfer_data = by_key["transfer(address,uint256)"].calldata
    assert transfer_data.startswith(cd._selector_of("transfer(address,uint256)") or "")
    assert int(transfer_data[74:], 16) == 1
    assert spec.principal == OPERATING_MULTISIG
    # The indefinite latch carries NO bound (no auto-expiry probe, no false witness)
    # — and now says WHY: a lowered guard reads the latch with no clock beside it.
    assert spec.max_pause_duration is None
    assert spec.duration_bound_source == "no_time_reference"


@requires_postgres
def test_guard_origin_latch_write_is_a_reader_not_a_pauser(db_session):
    """A ``whenNotPaused`` VICTIM records the same latch var, hygiene class and
    member path as the pauser — only ``origin`` separates them. Treating the
    readers as pausers puts a pause's whole blast radius on the fork tier to probe
    functions that cannot flip the latch."""
    facts = _eeth_facts(PAUSABLE_SLOT)
    candidate, ids = _eeth_candidate(db_session, PAUSABLE_SLOT)
    victim = "mintShares(address,uint256)"

    guarded_fn = cd.resolve_function(facts, cd._selector_of(victim))
    assert guarded_fn is not None
    # Same var, same hygiene class as the pauser's write — origin is the only difference.
    assert guarded_fn.effect_info["state_writes"][0]["var"] == PAUSABLE_SLOT
    assert cd._latch_pairs(guarded_fn) == set()

    guarded_candidate = Candidate(
        function_id=ids[victim],
        contract_id=candidate.contract_id,
        contract_address=EETH_IMPL,
        selector=cd._selector_of(victim),
        function_name="mintShares",
        authority_public=False,
        principal_addresses=(LIQUIDITY_POOL,),
        deployment_address=EETH_PROXY,
    )
    assert cd.synthesize_pause(db_session, guarded_candidate, facts, guarded_fn) is None

    # ...while the body-origin writer still produces its plan.
    pauser = cd.resolve_function(facts, candidate.selector)
    assert pauser is not None
    assert cd._latch_pairs(pauser) == {(PAUSABLE_SLOT, None)}
    assert cd.synthesize_pause(db_session, candidate, facts, pauser) is not None


@requires_postgres
def test_acceptance_timed_latch_publishes_not_determined_not_indefinite(db_session):
    """The same contract's ``*_UNTIL_*`` latch DECLARES a MAX_PAUSE_DURATION in
    source, and that is still not enough: nothing here proves the latch's guard
    reads it. No bound is the conservative output — never a scraped constant.

    INVERTED (A7, R4). This test previously asserted only ``is None`` and called
    that "conservative", but ``None`` was consumed as *proven indefinite latch, the
    most severe freeze*: ``claimsVocab`` rendered "(indefinite)" and "indefinite
    latch (no self-recovery bound)" from it. The etherfi shape reaching this
    assertion is ``pauseUntil`` — a latch that DOES expire, whose window is a
    storage value — so the severe reading was false on all four proven verdicts in
    the corpus. The conservative answer is ``not_determined``: the guard compares
    the latch against ``block.timestamp`` (so time is involved) and the window is
    not in the code."""
    pausable_until_source = """
        library PausableUntilStorage {
            bytes32 internal constant PAUSABLE_UNTIL_STORAGE_SLOT = keccak256("pausableUntil.storage");
            uint256 public constant MIN_PAUSE_DURATION = 8 hours;
            uint256 public constant MAX_PAUSE_DURATION = 30 days;
            uint256 public constant PAUSER_UNTIL_COOLDOWN = 7 days;
        }
    """
    # Declared in source, and deliberately unreachable from here.
    assert "MAX_PAUSE_DURATION" in pausable_until_source
    facts = _eeth_facts(PAUSABLE_UNTIL_SLOT)
    # The guard shape is copied from the persisted WeETH artifact verbatim
    # (``_pausedUntil >= block.timestamp``, operator ``lt`` after the polarity fold,
    # no third operand and nothing absorbed) — the leaf all four proven
    # ``freeze_pause`` verdicts in the local corpus are gated by.
    timed_facts = cd.ContractFacts(
        address=facts.address,
        job_id=facts.job_id,
        effects=facts.effects,
        trees={
            **facts.trees,
            "transfer(address,uint256)": _and(
                _leaf(
                    _state(PAUSABLE_UNTIL_SLOT, "pausedUntil"),
                    {"source": "block_context", "block_context_kind": "timestamp"},
                )
            ),
        },
        canonical_signatures=facts.canonical_signatures,
        by_selector=facts.by_selector,
    )
    assert cd.read_max_pause_duration(timed_facts, {PAUSABLE_UNTIL_SLOT}) == (None, "not_determined")
    # A latch NO lowered leaf reads is also ``not_determined`` — not indefinite.
    # This is the tree-absent case, and it is the governing rule: absence of a
    # proven bound is not proof that no bound exists.
    assert cd.read_max_pause_duration(timed_facts, {"NEVER_READ_SLOT"}) == (None, "not_determined")
    # ...while the plain boolean latch, whose guard reads it beside no clock at all,
    # gets no bound either — but a DIFFERENT no-bound: that one is PROVEN
    # indefinite, and the two must never render as the same sentence.
    assert cd.read_max_pause_duration(_eeth_facts(PAUSABLE_SLOT), {PAUSABLE_SLOT}) == (None, "no_time_reference")


def test_acceptance_liquidity_pool_withdraw_value_out():
    """Live target: sentinel at the taint-identified param 0 of
    ``withdraw(address,uint256)``, 1 wei, probing the PROXY."""
    full_name = "withdraw(address,uint256)"
    selector = cd._selector_of(full_name)
    assert selector == "0xf3fef3a3"
    facts = cd.ContractFacts(
        address="0x17a16747d03006c9754548ac0d0aff48783a4a45",
        job_id="lp-job",
        effects={
            full_name: _effect_info(
                full_name,
                selector,
                value_flows=[{"kind": "native_transfer_send", "direction": "out", "origin": "body"}],
                parameter_names=["_recipient", "_amount"],
            )
        },
        trees={full_name: _and(_leaf(_param("_recipient", 0)))},
        canonical_signatures={},
        legacy_value_flows={full_name: [{"direction": "out", "token_var": "_recipient", "is_parameter": True}]},
        by_selector={selector: full_name},
    )
    candidate = Candidate(
        function_id=1,
        contract_id=1,
        contract_address="0x17a16747d03006c9754548ac0d0aff48783a4a45",
        selector=selector,
        function_name="withdraw",
        authority_public=False,
        principal_addresses=("0x3d320286e014c3e1ce99af6d6b00f0c1d63e3000",),
        deployment_address=LIQUIDITY_POOL,
    )
    fn = cd.resolve_function(facts, selector)
    assert fn is not None
    spec = cd.synthesize_value_out(candidate, fn)
    assert spec is not None
    assert spec.contract_address == LIQUIDITY_POOL  # REQUIREMENT C
    assert spec.taint_param_reaches_sink is True
    assert spec.sentinel_calldata is not None
    assert spec.sentinel_calldata[10:74].endswith("ee" * 20)  # sentinel at param 0
    assert int(spec.sentinel_calldata[74:], 16) == 1  # uint256 stays the 1-wei default


# ---------------------------------------------------------------------------
# §9.5 Tier-2 timelock synthesis
# ---------------------------------------------------------------------------

EXECUTE_SIG = "execute(address,uint256,bytes,bytes32,bytes32)"
SCHEDULE_SIG = "schedule(address,uint256,bytes,bytes32,bytes32,uint256)"
EXECUTE_BATCH_SIG = "executeBatch(address[],uint256[],bytes[],bytes32,bytes32)"
SCHEDULE_BATCH_SIG = "scheduleBatch(address[],uint256[],bytes[],bytes32,bytes32,uint256)"


def _timelock_facts(*, signatures: list[str] | None = None) -> cd.ContractFacts:
    """A delayed executor's own ABI. Nothing here is protocol-specific: the plan
    finds the scheduling half by SHAPE (the executed tuple plus a trailing
    delay), so the same facts stand for any timelock."""
    names = signatures if signatures is not None else [EXECUTE_SIG, SCHEDULE_SIG, "getMinDelay()"]
    effects = {
        name: _effect_info(
            name,
            cd._selector_of(name) or "0x00000000",
            value_flows=(
                [
                    {
                        "kind": "low_level_value_call",
                        "direction": "out",
                        "origin": "body",
                        "from_is_self": True,
                        "target_kind": {"kind": "param", "tier": "static_trace"},
                    }
                ]
                if name.startswith("execute")
                else []
            ),
            parameter_names=(
                ["target", "value", "payload", "predecessor", "salt"] if name.startswith("execute") else []
            ),
        )
        for name in names
    }
    return cd.ContractFacts(
        address=CONTRACT,
        job_id="job-1",
        effects=effects,
        trees={},
        canonical_signatures={name: name for name in effects},
        legacy_value_flows={},
        by_selector={info["selector"]: name for name, info in effects.items()},
    )


def _timelock_session(schedule_principal: str | None = None) -> Any:
    session = MagicMock()
    rows = [(cd._selector_of(SCHEDULE_SIG), schedule_principal)] if schedule_principal else []
    session.execute.return_value.all.return_value = rows
    return session


def _timelock_spec(*, holdings: tuple[str, ...] = (), signature: str = EXECUTE_SIG, session: Any = None):
    facts = _timelock_facts()
    fn = cd.resolve_function(facts, cd._selector_of(signature) or "")
    assert fn is not None
    return cd.synthesize_timelock(
        session or _timelock_session(),
        _candidate(cd._selector_of(signature) or "", holdings=holdings),
        facts,
        fn,
    )


def test_the_timelock_plan_schedules_and_executes_one_operation_tuple():
    """OZ's ``execute`` recomputes the operation id from its own arguments, so the
    two calls only have to agree — and if they ever stop agreeing the timelock
    executes an operation nobody scheduled, which reverts and proves nothing."""
    spec = _timelock_spec()
    assert spec is not None
    executed = _decode(spec.execute_calldata, EXECUTE_SIG)
    scheduled = _decode(spec.schedule_calldata(864000), SCHEDULE_SIG)
    assert scheduled[:5] == executed
    assert scheduled[5] == 864000  # the delay, and only the delay, is added


def test_the_timelock_plan_targets_the_sentinel_when_the_contract_holds_nothing():
    """The normal case: a timelock holds authority, not funds. The operation is
    still one the proposer chose, and the value question is left to the recipe to
    answer honestly rather than answered here by an invented asset."""
    spec = _timelock_spec()
    assert spec is not None
    target, value, payload, predecessor, _salt = _decode(spec.execute_calldata, EXECUTE_SIG)
    assert target.lower() == cd.SENTINEL_ADDRESS.lower()
    assert payload == b""
    # No native value the timelock does not hold, and no dependency on another op.
    assert value == 0
    assert predecessor == b"\x00" * 32
    assert spec.witness_token is None and spec.witness_calldata is None


def test_the_timelock_plan_moves_an_asset_the_contract_provably_holds():
    spec = _timelock_spec(holdings=(HELD_TOKEN,))
    assert spec is not None
    target, _value, payload, _pred, _salt = _decode(spec.execute_calldata, EXECUTE_SIG)
    assert target.lower() == HELD_TOKEN.lower()
    assert payload.hex().startswith("a9059cbb")
    assert spec.witness_token == HELD_TOKEN
    assert spec.witness_calldata is not None and cd.SENTINEL_ADDRESS[2:].lower() in spec.witness_calldata.lower()


def test_the_timelock_plan_finds_the_scheduling_half_of_the_batch_arity_too():
    """Same rule, no second code path: the batch tuple plus a trailing delay."""
    facts = _timelock_facts(signatures=[EXECUTE_BATCH_SIG, SCHEDULE_BATCH_SIG, "getMinDelay()"])
    fn = cd.resolve_function(facts, cd._selector_of(EXECUTE_BATCH_SIG) or "")
    assert fn is not None
    spec = cd.synthesize_timelock(_timelock_session(), _candidate(cd._selector_of(EXECUTE_BATCH_SIG) or ""), facts, fn)
    assert spec is not None
    targets, values, payloads, _pred, _salt = _decode(spec.execute_calldata, EXECUTE_BATCH_SIG)
    assert [t.lower() for t in targets] == [cd.SENTINEL_ADDRESS.lower()]
    assert values == (0,) and payloads == (b"",)


def test_no_timelock_plan_without_the_scheduling_half():
    """An executor that cannot be scheduled is not a timelock, and probing it as
    one would schedule nothing and execute an operation that does not exist."""
    facts = _timelock_facts(signatures=[EXECUTE_SIG, "getMinDelay()"])
    fn = cd.resolve_function(facts, cd._selector_of(EXECUTE_SIG) or "")
    assert fn is not None
    assert cd.synthesize_timelock(_timelock_session(), _candidate(EXECUTE_SIG), facts, fn) is None


def test_no_timelock_plan_without_the_contracts_own_delay():
    """The delay is read, never assumed — so a contract that will not tell us its
    minimum yields no plan rather than a guessed one."""
    facts = _timelock_facts(signatures=[EXECUTE_SIG, SCHEDULE_SIG])
    fn = cd.resolve_function(facts, cd._selector_of(EXECUTE_SIG) or "")
    assert fn is not None
    assert cd.synthesize_timelock(_timelock_session(), _candidate(EXECUTE_SIG), facts, fn) is None


def test_the_timelock_plan_prefers_a_principal_behind_both_gates():
    """Scheduling and executing are separately gated. Picking the address the
    resolution plane put behind BOTH is what keeps the probe from having to grant
    itself a role — which §9.3 forbids outright."""
    spec = _timelock_spec(session=_timelock_session(schedule_principal=PRINCIPAL))
    assert spec is not None
    assert spec.principal == PRINCIPAL.lower()


def test_the_timelock_plan_still_probes_as_the_executor_when_the_roles_diverge():
    """No intersection is not a reason to invent one: probe as the executor and
    let the contract reject the schedule, which the recipe records verbatim."""
    spec = _timelock_spec(session=_timelock_session(schedule_principal="0x" + "99" * 20))
    assert spec is not None
    assert spec.principal == PRINCIPAL.lower()


def test_the_timelock_plan_reads_the_delay_off_the_contract():
    delay_selector = cd._selector_of("getMinDelay()")
    spec = _timelock_spec()
    assert spec is not None
    assert spec.delay_calldata == delay_selector
    # A delay we could not read is not defaulted to something plausible: zero goes
    # to the contract, whose own minimum rejects it.
    assert spec.schedule_calldata(0) == spec.schedule_calldata_zero


# ---------------------------------------------------------------------------
# prober wiring
# ---------------------------------------------------------------------------


def _ctx(*, anvil_factory=None) -> ProbeContext:
    return ProbeContext(
        chain_id=1,
        block=21_000_000,
        hardfork="prague",
        simulate=MagicMock(),
        simulate_supported=True,
        transcript_store=RecordingStore(),
        anvil_factory=anvil_factory,
    )


def _stub_session() -> Any:
    """Session stand-in for the prober: no proxy contract row, and the synthesizer
    is monkeypatched, so nothing else is executed."""
    session = MagicMock()
    session.execute.return_value.scalar_one_or_none.return_value = None
    session.execute.return_value.all.return_value = []
    return session


def test_prober_emits_one_plan_per_synthesized_class(monkeypatch):
    inputs = cd.CandidatePlanInputs(
        value_out=cd.ValueOutPlanInputs(
            contract_address=CONTRACT, principal=PRINCIPAL, calldata=TRANSFER, gate_ref="gate:none"
        ),
        supply=cd.SupplyPlanInputs(
            token_address=CONTRACT, principal=PRINCIPAL, mint_calldata=MINT, gate_ref="gate:none"
        ),
        authority=cd.AuthorityPlanInputs(
            contract_address=CONTRACT,
            principal=PRINCIPAL,
            mutate_calldata=MINT,
            probe_calldata=ADMIN_ONLY,
            probe_function="adminOnly()",
            gate_ref="gate:caller_authority",
        ),
        pause=cd.PausePlanInputs(
            contract_address=CONTRACT,
            principal=PRINCIPAL,
            pause_calldata=PAUSE_SEL,
            entry_points=(),
            predicted_guard_set=("deposit()",),
            max_pause_duration=None,
            gate_ref="gate:caller_authority",
        ),
    )
    monkeypatch.setattr(cd, "synthesize", lambda *_a, **_k: inputs)
    plans = default_prober(
        _stub_session(),
        _candidate(TRANSFER),
        _ctx(anvil_factory=lambda: StubAnvil(guarded=set(), pause_calldata=PAUSE, duration=None)),
    )
    assert {p.effect_class for p in plans} == {
        EFFECT_CLASS_VALUE_OUT,
        EFFECT_CLASS_SUPPLY,
        EFFECT_CLASS_AUTHORITY_CHANGE,
        EFFECT_CLASS_FREEZE_PAUSE,
    }


def _both_plans_inputs() -> cd.CandidatePlanInputs:
    """A delayed executor as the synthesizer sees it: Tier-1 has a probe for it,
    and so does Tier 2. The two gate_refs are what tells the plans apart."""
    spec = _timelock_spec()
    assert spec is not None
    return cd.CandidatePlanInputs(
        value_out=cd.ValueOutPlanInputs(
            contract_address=CONTRACT, principal=PRINCIPAL, calldata=TRANSFER, gate_ref="gate:tier1"
        ),
        timelock=cd.TimelockPlanInputs(
            contract_address=spec.contract_address,
            principal=spec.principal,
            execute_calldata=spec.execute_calldata,
            schedule_selector=spec.schedule_selector,
            schedule_signature=spec.schedule_signature,
            schedule_arguments=spec.schedule_arguments,
            delay_index=spec.delay_index,
            schedule_calldata_zero=spec.schedule_calldata_zero,
            delay_calldata=spec.delay_calldata,
            gate_ref="gate:tier2",
        ),
    )


def test_the_timelock_plan_replaces_the_tier1_probe_for_a_delayed_executor(monkeypatch):
    """Tier 1 cannot satisfy a block.timestamp gate at all, so its row is a revert
    that says nothing about the function — and both plans carry the same effect
    class, scope and gate, so they would stage under one cache key."""
    monkeypatch.setattr(cd, "synthesize", lambda *_a, **_k: _both_plans_inputs())
    plans = default_prober(
        _stub_session(),
        _candidate(TRANSFER),
        _ctx(anvil_factory=lambda: StubAnvil(guarded=set(), pause_calldata=PAUSE, duration=None)),
    )
    assert [p.gate_ref for p in plans] == ["gate:tier2"]
    assert [p.effect_class for p in plans] == [EFFECT_CLASS_VALUE_OUT]


def test_without_a_fork_the_tier1_probe_still_stands(monkeypatch):
    """No fork, no Tier-2 sequence — and dropping the Tier-1 probe as well would
    lose the row entirely."""
    monkeypatch.setattr(cd, "synthesize", lambda *_a, **_k: _both_plans_inputs())
    plans = default_prober(_stub_session(), _candidate(TRANSFER), _ctx())
    assert [p.gate_ref for p in plans] == ["gate:tier1"]


def test_prober_drops_the_pause_plan_without_a_fork(monkeypatch):
    inputs = cd.CandidatePlanInputs(
        pause=cd.PausePlanInputs(
            contract_address=CONTRACT,
            principal=PRINCIPAL,
            pause_calldata=PAUSE_SEL,
            entry_points=(),
            predicted_guard_set=("deposit()",),
            max_pause_duration=None,
            gate_ref="gate:caller_authority",
        )
    )
    monkeypatch.setattr(cd, "synthesize", lambda *_a, **_k: inputs)
    assert default_prober(_stub_session(), _candidate(PAUSE_SEL), _ctx()) == []


def test_prober_emits_nothing_when_facts_are_thin(monkeypatch):
    monkeypatch.setattr(cd, "synthesize", lambda *_a, **_k: cd.CandidatePlanInputs())
    assert default_prober(_stub_session(), _candidate(TRANSFER), _ctx()) == []


# ---------------------------------------------------------------------------
# token-precondition seeding: slot math + fixture synthesis
# ---------------------------------------------------------------------------

from eth_utils.crypto import keccak  # noqa: E402

CALLER = "0x" + "22" * 20
SPENDER = "0x" + "33" * 20


def _slot(base: int, *keys: int) -> str:
    """Independent reference: fold keys outermost-first over a 32-byte base."""
    word = base.to_bytes(32, "big")
    for key in keys:
        word = keccak(key.to_bytes(32, "big") + word)
    return "0x" + word.hex()


def test_mapping_entry_slot_single_address_key_golden():
    # Solidity mapping at slot 9 (a common ERC-20 `_balances` slot), key = CALLER.
    base = "0x" + "00" * 31 + "09"
    got = cd._mapping_entry_slot(base, [int(CALLER, 16)])
    assert got == _slot(9, int(CALLER, 16))
    # The classic "mapping at slot 0, key = address(0)" constant.
    assert cd._mapping_entry_slot(cd._word_hex(0), [0]) == "0x" + keccak(b"\x00" * 64).hex()


def test_mapping_entry_slot_nested_address_address_key_golden():
    base = "0x" + "00" * 31 + "0a"
    got = cd._mapping_entry_slot(base, [int(CALLER, 16), int(SPENDER, 16)])
    assert got == _slot(10, int(CALLER, 16), int(SPENDER, 16))


def test_mapping_entry_slot_uint_key_golden():
    got = cd._mapping_entry_slot(cd._word_hex(2), [cd.ARG_AMOUNT])
    assert got == _slot(2, cd.ARG_AMOUNT)


def test_mapping_entry_slot_rejects_malformed_base():
    assert cd._mapping_entry_slot("0xnothex", [0]) is None
    assert cd._mapping_entry_slot("0x" + "ab" * 33, [0]) is None  # > 32 bytes


def _slot_entry(**over: Any) -> dict[str, Any]:
    entry = {
        "getter": "balanceOf(address)",
        "role": "balance",
        "key_kind": "address",
        "base_slot": "0x" + "00" * 31 + "09",
        "derivation": "storage_layout",
        "variable": "_balances",
    }
    entry.update(over)
    return entry


def test_seed_fixture_balance_carries_verified_readback():
    fx = cd._seed_fixture_for_role(_slot_entry(), CALLER, CONTRACT)
    assert fx is not None
    assert fx.kind == "set_storage_at"
    assert fx.address == CONTRACT  # the state-bearing deployment
    assert fx.slot == cd._mapping_entry_slot(_slot_entry()["base_slot"], [int(CALLER, 16)])
    assert fx.value == cd._word_hex(cd.SEED_AMOUNT)
    # read-back anchor: the contract's own balanceOf(CALLER) must echo the seed.
    assert fx.verify_to == CONTRACT
    assert fx.verify_expected == fx.value
    sel = cd._selector_of("balanceOf(address)")
    assert sel is not None
    assert fx.verify_calldata == cd.encode_calldata(sel, "balanceOf(address)", substitutions={0: CALLER.lower()})


def test_seed_fixture_allowance_seeds_owner_equals_spender():
    entry = _slot_entry(
        getter="allowance(address,address)", role="allowance", key_kind="address_address", base_slot=cd._word_hex(10)
    )
    fx = cd._seed_fixture_for_role(entry, CALLER, CONTRACT)
    assert fx is not None
    # owner == spender == the prober, matching the synthesizer's identity policy.
    assert fx.slot == cd._mapping_entry_slot(cd._word_hex(10), [int(CALLER, 16), int(CALLER, 16)])
    assert fx.value == cd._word_hex(cd.SEED_AMOUNT)
    sel = cd._selector_of("allowance(address,address)")
    assert sel is not None
    assert fx.verify_calldata == cd.encode_calldata(
        sel, "allowance(address,address)", substitutions={0: CALLER.lower(), 1: CALLER.lower()}
    )


def test_seed_fixture_owner_stores_caller_at_probed_tokenid():
    entry = _slot_entry(getter="ownerOf(uint256)", role="owner", key_kind="uint256", base_slot=cd._word_hex(2))
    fx = cd._seed_fixture_for_role(entry, CALLER, CONTRACT)
    assert fx is not None
    # key is the EXACT uint the arg synthesizer uses; stored word is the caller.
    assert fx.slot == cd._mapping_entry_slot(cd._word_hex(2), [cd.ARG_AMOUNT])
    assert fx.value == cd._word_hex(int(CALLER, 16))
    assert fx.verify_expected == cd._word_hex(int(CALLER, 16))
    sel = cd._selector_of("ownerOf(uint256)")
    assert sel is not None
    assert fx.verify_calldata == cd.encode_calldata(sel, "ownerOf(uint256)", substitutions={0: cd.ARG_AMOUNT})


@pytest.mark.parametrize(
    "entry",
    [
        _slot_entry(base_slot=123),  # non-string base
        _slot_entry(getter=42),  # non-string getter
        _slot_entry(getter="not a signature"),  # unparseable getter
        _slot_entry(role="balance", key_kind="uint256"),  # role/kind mismatch
        _slot_entry(role="mystery"),  # unknown role
        _slot_entry(base_slot="0xzz"),  # bad hex
    ],
)
def test_seed_fixture_malformed_entry_is_skipped(entry):
    assert cd._seed_fixture_for_role(entry, CALLER, CONTRACT) is None


def test_seed_fixture_bad_caller_is_skipped():
    assert cd._seed_fixture_for_role(_slot_entry(), "not-an-address", CONTRACT) is None


def test_token_seed_fixtures_one_per_caller_and_entry():
    entries = (
        _slot_entry(),
        _slot_entry(getter="ownerOf(uint256)", role="owner", key_kind="uint256", base_slot=cd._word_hex(2)),
    )
    fixtures = cd._token_seed_fixtures(entries, [CALLER, SPENDER], CONTRACT)
    # Caller-keyed entries seed every caller; the owner entry seeds only the
    # FIRST caller — its slot is tokenId-keyed, so a second seed would overwrite
    # the first (last-writer-wins) while both read-backs claimed ok.
    assert len(fixtures) == 3  # balance x 2 callers + owner x first caller only
    assert all(fx.kind == "set_storage_at" and fx.verify_calldata is not None for fx in fixtures)
    owner_seeds = [fx for fx in fixtures if fx.value == cd._word_hex(int(CALLER, 16))]
    assert len(owner_seeds) == 1


def test_token_seed_fixtures_empty_without_slots():
    assert cd._token_seed_fixtures((), [CALLER], CONTRACT) == ()


# ---------------------------------------------------------------------------
# synthesize_pause emits token seeds (+ the no-token_slots regression)
# ---------------------------------------------------------------------------


@requires_postgres
def test_synthesize_pause_emits_token_seed_fixtures(db_session):
    contract, ids = _pause_contract(db_session)
    facts = _token_facts(token_slots=(_slot_entry(),))
    fn = cd.resolve_function(facts, PAUSE_SEL)
    assert fn is not None
    candidate = Candidate(
        function_id=ids[PAUSE_SEL],
        contract_id=contract.id,
        contract_address=CONTRACT,
        selector=PAUSE_SEL,
        function_name="pause",
        authority_public=False,
        principal_addresses=(PRINCIPAL,),
    )
    spec = cd.synthesize_pause(db_session, candidate, facts, fn)
    assert spec is not None
    # The lone prober is deposit()'s principal, so exactly one token seed lands.
    storage = [fx for fx in spec.fixtures if fx.kind == "set_storage_at"]
    assert len(storage) == 1
    seed = storage[0]
    assert seed.address == candidate.probe_target
    assert seed.slot == cd._mapping_entry_slot(_slot_entry()["base_slot"], [int(PRINCIPAL, 16)])
    assert seed.verify_to == candidate.probe_target
    assert seed.verify_expected == cd._word_hex(cd.SEED_AMOUNT)
    # the principal set_balance is still present and unchanged.
    assert any(fx.kind == "set_balance" and fx.address == PRINCIPAL for fx in spec.fixtures)


@requires_postgres
def test_synthesize_pause_without_token_slots_is_unchanged(db_session):
    """Regression: no token_slots key ⇒ the fixture list is exactly today's — one
    set_balance for the principal, nothing else."""
    contract, ids = _pause_contract(db_session)
    facts = _token_facts()  # no token_slots
    fn = cd.resolve_function(facts, PAUSE_SEL)
    assert fn is not None
    candidate = Candidate(
        function_id=ids[PAUSE_SEL],
        contract_id=contract.id,
        contract_address=CONTRACT,
        selector=PAUSE_SEL,
        function_name="pause",
        authority_public=False,
        principal_addresses=(PRINCIPAL,),
    )
    spec = cd.synthesize_pause(db_session, candidate, facts, fn)
    assert spec is not None
    assert all(fx.kind == "set_balance" for fx in spec.fixtures)
    assert {fx.address for fx in spec.fixtures} == {PRINCIPAL}
    assert all(fx.verify_calldata is None for fx in spec.fixtures)


# ---------------------------------------------------------------------------
# pause fork fixtures
# ---------------------------------------------------------------------------


def test_pause_fixtures_are_applied_before_the_pre_pause_probe():
    transport = StubAnvil(guarded={GUARDED}, pause_calldata=PAUSE, duration=None)
    store = RecordingStore()
    from services.effects.anvil import EntryPoint
    from services.effects.harness import SimContext

    effect = pause_recipe(
        transport=transport,
        store=store,
        ctx=SimContext(chain_id=1, block=1, hardfork="prague"),
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        pause_calldata=PAUSE,
        entry_points=[EntryPoint(key="guarded()", calldata=GUARDED, from_addr=PRINCIPAL)],
        predicted_guard_set=["guarded()"],
        max_pause_duration=None,
        fixtures=(
            ForkFixture(kind="set_balance", address=PRINCIPAL, value="0x64"),
            ForkFixture(kind="set_storage_at", address=CONTRACT, value="0x1", slot="0x0"),
            ForkFixture(kind="bogus", address=CONTRACT, value="0x0"),
        ),
    )
    assert transport.balances == {PRINCIPAL: "0x64"}
    assert transport.storage == {(CONTRACT, "0x0"): "0x1"}
    applied = store.stored[0]["fixtures"]
    assert [f["kind"] for f in applied] == ["set_balance", "set_storage_at", "bogus"]
    assert applied[2]["skipped"] == "unknown_kind"
    assert effect.details["observed_blast_radius"] == ["guarded()"]


# ---------------------------------------------------------------------------
# worker: block pinning + single-flight anvil
# ---------------------------------------------------------------------------


def _stub_seams(*, block_number=None) -> _Seams:
    from services.effects.preflight import InMemoryCapabilityStore

    store = InMemoryCapabilityStore()
    store.set_simulate_support(1, True)
    return _Seams(
        simulate=MagicMock(),
        transcript_store=RecordingStore(),
        capability_store=store,
        chain_id=1,
        block_number=block_number,
    )


def test_preflight_pins_the_real_head_block():
    worker = EffectsWorker()
    supported, block = worker._preflight(_stub_seams(block_number=lambda: 21_000_123), {})
    assert supported is True
    assert block == 21_000_123


def test_preflight_without_a_pinned_head_disables_tier1():
    from utils.logging import degraded_errors_var

    worker = EffectsWorker()
    errors: list = []
    token = degraded_errors_var.set(errors)
    try:
        supported, block = worker._preflight(_stub_seams(block_number=lambda: None), {})
    finally:
        degraded_errors_var.reset(token)
    assert supported is False
    assert block == 0
    assert any(getattr(e, "phase", None) == "effects_block_pin" for e in errors)


def test_anvil_factory_is_single_flight_and_closed(monkeypatch):
    spawns: list[dict[str, Any]] = []

    class _FakeAnvil:
        def __init__(self, **kwargs):
            spawns.append(kwargs)
            self.closed = False

        def close(self):
            self.closed = True

    monkeypatch.setattr("services.effects.anvil.SubprocessAnvil", _FakeAnvil)
    monkeypatch.setattr("utils.rpc.rpc_headers", lambda url, extra=None: {"X-Test": "1"})
    monkeypatch.setenv("PSAT_EFFECTS_FORK", "1")

    worker = EffectsWorker()
    factory = worker._anvil_factory(1, "http://rpc.example/1")
    assert factory is not None
    first = factory()
    assert factory() is first  # memoized: one fork per run per chain
    assert len(spawns) == 1
    assert spawns[0]["fork_url"] == "http://rpc.example/1"
    assert spawns[0]["fork_headers"] == {"X-Test": "1"}
    worker._close_anvil()
    assert first.closed is True
    assert worker._anvil is None


def test_anvil_spawn_failure_is_memoized_and_raises_per_plan(monkeypatch):
    from services.effects.exceptions import AnvilSpawnError

    calls = {"n": 0}

    def _boom(**_kwargs):
        calls["n"] += 1
        raise OSError("no anvil")

    monkeypatch.setattr("services.effects.anvil.SubprocessAnvil", _boom)
    monkeypatch.setattr("utils.rpc.rpc_headers", lambda url, extra=None: {})
    monkeypatch.setenv("PSAT_EFFECTS_FORK", "1")

    worker = EffectsWorker()
    factory = worker._anvil_factory(1, "http://rpc.example/1")
    assert factory is not None
    for _ in range(3):
        with pytest.raises(AnvilSpawnError):
            factory()
    assert calls["n"] == 1  # never retried per candidate


def test_fork_kill_switch_disables_the_factory(monkeypatch):
    monkeypatch.setenv("PSAT_EFFECTS_FORK", "0")
    assert EffectsWorker()._anvil_factory(1, "http://rpc.example/1") is None
