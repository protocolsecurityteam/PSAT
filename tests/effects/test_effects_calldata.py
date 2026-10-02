"""Recorded static facts in, concrete probe inputs out. Offline: nothing spawns anvil or touches a wire."""

from __future__ import annotations

import copy
import uuid
from typing import Any
from unittest.mock import MagicMock

import pytest

from db.models import Contract, EffectiveFunction, FunctionPrincipal, Protocol
from db.queue import create_job, store_artifact
from services.effects import calldata as cd
from services.effects.anvil import ForkFixture, pause_recipe
from services.effects.config import (
    EFFECT_CLASS_AUTHORITY_CHANGE,
    EFFECT_CLASS_FREEZE_PAUSE,
    EFFECT_CLASS_SUPPLY,
    EFFECT_CLASS_VALUE_OUT,
)
from services.effects.orchestrator import ProbeContext, default_prober
from services.effects.selection import Candidate
from tests.cache_helpers import requires_postgres
from tests.support.effects_stubs import GUARDED, PAUSE, RecordingStore, StubAnvil
from workers.effects_worker import EffectsWorker, _Seams

TRANSFER = "0xa9059cbb"  # transfer(address,uint256)
MINT = "0x40c10f19"  # mint(address,uint256)
PAUSE_SEL = "0x8456cb59"  # pause()
DEPOSIT = "0xd0e30db0"  # deposit()
ADMIN_ONLY = "0xc976a359"  # adminOnly()
PRINCIPAL = "0x" + "22" * 20
CONTRACT = "0x" + "a1" * 20


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
        # ``operands`` order and ``operator`` decide which side the constant bounds; omit them to exercise the
        # undecidable case.
        leaf["operator"] = operator
    if absorbed is not None:
        # Set only where a test exercises them, so other leaves stay byte-identical to a pre-widening tree.
        leaf["absorbed_operands"] = absorbed
    return {"op": "LEAF", "leaf": leaf}


def _and(*children: dict[str, Any]) -> dict[str, Any]:
    return _built_by_current_builder({"op": "AND", "children": list(children)})


def _or(*children: dict[str, Any]) -> dict[str, Any]:
    return _built_by_current_builder({"op": "OR", "children": list(children)})


def _built_by_current_builder(tree: dict[str, Any]) -> dict[str, Any]:
    """Without the marker (the persisted pre-widening shape) a missing ``absorbed_operands`` means unknown."""
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
        # The prober needs a named quantity before it may substitute one.
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
    assert spec.sentinel_calldata[10:74].endswith("ee" * 20)
    assert spec.calldata[10:74].endswith("22" * 20)
    # The declared name wins; it is the join key the exec witness's ``destination_param`` speaks.
    assert spec.sentinel_param == "to"


def test_a_slot_the_static_plane_never_named_publishes_no_sentinel_subject():
    """``arg0`` is a name nothing else speaks, so the field stays absent even though the sentinel is planted."""
    fn = cd.FunctionFacts(
        full_name="transfer(address,uint256)",
        selector=TRANSFER,
        canonical_signature="transfer(address,uint256)",
        effect_info=_effect_info(
            "transfer(address,uint256)",
            TRANSFER,
            value_flows=[
                {
                    "kind": "callee_erc20_selector",
                    "direction": "out",
                    "origin": "body",
                    "target_kind": {"kind": "param", "tier": "static_trace"},
                    "target_param_index": 0,
                }
            ],
            parameter_names=[],
        ),
        tree=None,
        legacy_value_flows=(),
    )
    spec = cd.synthesize_value_out(_candidate(TRANSFER), fn)
    assert spec is not None
    assert spec.sentinel_calldata is not None
    assert spec.sentinel_param is None


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
    """An empty default array runs no loop body, and that non-observation was cached as structural fact."""
    spec = cd.synthesize_value_out(_candidate(BATCH_SEL), _batch_fn())
    assert spec is not None
    ids, recipients = _decode(spec.calldata, BATCH_SIG)
    assert ids == (cd.ARG_IDENTIFIER,)
    assert [a.lower() for a in recipients] == [PRINCIPAL.lower()]


def test_an_unresolved_quantity_makes_the_inputs_vacuous():
    """A zero-amount call that moves nothing says nothing about the function."""
    spec = cd.synthesize_value_out(_candidate(UNWRAP), _unwrap_fn())
    assert spec is not None
    assert int(spec.calldata[10:74], 16) == 0
    assert spec.inputs_vacuous is True


def test_an_array_whose_element_is_filler_is_vacuous():
    """An empty result is a fact about the filler."""
    spec = cd.synthesize_value_out(_candidate(BATCH_SEL), _batch_fn("submit(bytes[])", names=["payloads"]))
    assert spec is not None
    assert spec.inputs_vacuous is True


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


def test_the_claim_witness_names_the_executor_slots_directly():
    """A name counts only with its ``param`` kind."""
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


def test_a_synthesized_inner_call_is_not_vacuous():
    fn = _exec_fn("forward(address,bytes,uint256)", ["target", "data", "value"], flows=[_FORWARDS_PARAM])
    spec = cd.synthesize_value_out(_candidate(BATCH_SEL, holdings=(HELD_TOKEN,)), fn)
    assert spec is not None
    assert spec.inputs_vacuous is False


def test_value_out_none_without_a_resolved_principal():
    facts = _token_facts()
    fn = cd.resolve_function(facts, TRANSFER)
    assert fn is not None
    assert cd.synthesize_value_out(_candidate(TRANSFER, principals=()), fn) is None


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


# 76 of 78 live fund-out flows are native sends whose recipient no name map recovers; the lattice's slot index makes a
# sentinel probe possible.

REDEEM = "0x7bde82f2"  # redeem(uint256,address)
REDEEM_SIG = "redeem(uint256,address)"


def _redeem_facts(*, flows: list[dict[str, Any]], legacy: list[dict[str, Any]] | None = None) -> cd.ContractFacts:
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


def test_lattice_index_ignored_when_the_slot_is_not_an_address():
    spec = _redeem_spec(_redeem_facts(flows=[_eth_flow(target_param_index=0)]))  # uint256 amount
    assert spec.sentinel_calldata is None
    spec = _redeem_spec(_redeem_facts(flows=[_eth_flow(target_param_index=7)]))  # out of range
    assert spec.sentinel_calldata is None


def test_lattice_guard_origin_flow_is_not_a_recipient():
    flow = _eth_flow(target_param_index=1, origin="guard")
    spec = _redeem_spec(_redeem_facts(flows=[flow, _eth_flow()]))
    assert spec.sentinel_calldata is None


# For ERC-4626 redemptions the amount is a conversion of an argument; every case names the slot ``n`` so only a lattice
# fact can produce a role.

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


BURN_SIG = "redeem(uint256,address)"
BURN_SEL = "0x33334444"


def _redeem_fn() -> cd.FunctionFacts:
    """The lattice records the burn as an outbound payout, never under ``burn``."""
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
    """S1: filtering by ``mint``/``burn`` rejected every flow an artifact emits."""
    spec = cd.synthesize_supply(_candidate(BURN_SEL), _redeem_fn())
    assert spec is not None
    assert int(spec.mint_calldata[10:74], 16) == cd.ARG_AMOUNT
    assert spec.sentinel_calldata is not None
    assert spec.sentinel_calldata[74:138].endswith("ee" * 20)
    assert spec.taint_param_reaches_sink is True


def test_supply_gated_without_principal_stays_none():
    facts = _token_facts()
    fn = cd.resolve_function(facts, MINT)
    assert fn is not None
    assert cd.synthesize_supply(_candidate(MINT, principals=(), authority_public=False), fn) is None


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
    assert spec.probe_function == "adminOnly()"
    assert spec.probe_calldata == ADMIN_ONLY
    assert spec.mutate_calldata == "0x13af4035" + "00" * 32


def test_guarded_functions_only_counts_mandatory_paths():
    trees = {
        "mandatory()": _and(_leaf(_state("paused"))),
        "escapable()": _or(_leaf(_state("paused")), _leaf(_state("other"))),
        "unrelated()": _and(_leaf(_state("other"))),
    }
    assert cd.guarded_functions(trees, {("paused", None)}) == ["mandatory()"]


def _timestamp() -> dict[str, Any]:
    return {"source": "block_context", "block_context_kind": "timestamp"}


def _const(value: str) -> dict[str, Any]:
    return {"source": "constant", "constant_value": value}


def test_max_pause_duration_never_publishes_a_block_count_as_seconds():
    """The constant here is a block count; harvesting it would publish 216000 "seconds" for a ~30-day gate."""
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
    """A leaf mixing a seconds clock and ``block.number`` can't say which unit its constant is in."""
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


def test_max_pause_duration_ignores_a_constant_belonging_to_another_latch():
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
    # Absence of a bound is not proof that none exists.
    assert cd.read_max_pause_duration(facts, {"INDEFINITE_SLOT"}) == (None, "not_determined")


def test_a_clock_in_a_sibling_leaf_denies_the_proven_indefinite_state():
    """A lowered ``||`` puts the latch and the clock in separate leaves, so the whole tree must be checked
    (``require(!frozen || block.timestamp > unpauseAt)``).
    """
    disjunction = _or(
        _leaf(_state("frozen")),
        _leaf(
            {"source": "block_context", "block_context_kind": "timestamp"},
            _state("unpauseAt"),
        ),
    )
    facts = _token_facts(trees={"transfer(address,uint256)": disjunction})
    assert cd.read_max_pause_duration(facts, {"frozen"}) == (None, "not_determined")
    # The window is a stored timestamp.
    assert cd.read_max_pause_duration(facts, {"unpauseAt"}) == (None, "not_determined")
    with_indefinite = _token_facts(
        trees={
            "transfer(address,uint256)": disjunction,
            "transferFreezable(address,uint256)": _and(_leaf(_state("halted"))),
        }
    )
    assert cd.read_max_pause_duration(with_indefinite, {"halted"}) == (None, "no_time_reference")


def test_a_pre_widening_tree_can_never_prove_an_indefinite_latch():
    """A missing ``absorbed_operands`` means two things; only the root marker separates them.

    Rows written before the widening dropped the absorbed clock, and the leaf-local reader called them proven
    indefinite. The proven state therefore requires the builder's marker.
    """
    absorbed = [
        {"source": "block_context", "block_context_kind": "timestamp"},
        _state("pausedUntil"),
    ]
    leaf = _leaf(
        _state("pausedUntil"), {"source": "constant", "constant_value": "2592000"}, absorbed=absorbed, operator="lt"
    )
    post = _token_facts(trees={"transfer(address,uint256)": _and(leaf)})
    assert cd.read_max_pause_duration(post, {"pausedUntil"}) == (2592000, "guard_constant")

    stripped = copy.deepcopy(post.trees["transfer(address,uint256)"])
    for stripped_leaf in cd._all_leaves(stripped):
        stripped_leaf.pop("absorbed_operands", None)
    stripped.pop("operand_absorption", None)
    pre = _token_facts(trees={"transfer(address,uint256)": stripped})
    assert cd.read_max_pause_duration(pre, {"pausedUntil"}) == (None, "not_determined")

    # An unmarked clock-free latch guard is still unknown.
    unmarked_bool = {"op": "AND", "children": [_leaf(_state("halted"))]}
    assert cd.read_max_pause_duration(_token_facts(trees={"t()": unmarked_bool}), {"halted"}) == (
        None,
        "not_determined",
    )
    assert cd.read_max_pause_duration(_token_facts(trees={"t()": _and(_leaf(_state("halted")))}), {"halted"}) == (
        None,
        "no_time_reference",
    )


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
def test_synthesize_pause_falls_back_to_state_changing_entry_points(db_session):
    """Keep the empty denominator and let the discrepancy router file vocabulary growth."""
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
    # The neutral identity is not the attacker sentinel.
    transfer_ep = next(ep for ep in spec.entry_points if ep.key == "transfer(address,uint256)")
    assert transfer_ep.from_addr == cd.NEUTRAL_CALLER


@requires_postgres
def test_synthesize_pause_adds_pauser_identity_probe_for_unresolved_victim(db_session):
    """A victim the neutral caller can't reach is also probed from the pause principal."""
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
    db_session.add(FunctionPrincipal(function_id=ids[DEPOSIT], address=PRINCIPAL))
    db_session.commit()

    # transfer() is behind a caller-authority gate with an unresolved principal.
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
    assert set(by_key["transfer(address,uint256)"]) == {cd.NEUTRAL_CALLER, PRINCIPAL}
    assert by_key["deposit()"] == [PRINCIPAL]


@requires_postgres
def test_load_contract_facts_indexes_the_canonical_selector(db_session):
    address = "0x" + "cd" * 20
    job = create_job(db_session, {"address": address, "name": "T"})
    # Only the canonical map recovers the real selector for a contract-typed param.
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


# Live-acceptance fixtures from the 2026-07-21 mainnet-fork run. Expected values only; the logic never matches on these
# names.

EETH_IMPL = "0xd1901dd36cbf4a81386d0162df2707f7ddb60527"
EETH_PROXY = "0x35fa164735182de50811e8e2e824cfb9b6118ac2"
LIQUIDITY_POOL = "0x308861a430be4cce5502d0a12724771fc6daf216"
OPERATING_MULTISIG = "0x2aca71020de61bb532008049e1bd41e451ae8adc"
PAUSABLE_SLOT = "PAUSABLE_STORAGE_SLOT"

EETH_GUARDED = (
    "burnShares(address,uint256)",
    "mintShares(address,uint256)",
    "transfer(address,uint256)",
    "transferFrom(address,address,uint256)",
)


def _eeth_facts(latch_var: str) -> cd.ContractFacts:
    """``canonical_signatures`` is omitted when canonical equals full_name."""
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
    facts = _eeth_facts(PAUSABLE_SLOT)
    candidate, _ids = _eeth_candidate(db_session, PAUSABLE_SLOT)
    fn = cd.resolve_function(facts, candidate.selector)
    assert fn is not None
    spec = cd.synthesize_pause(db_session, candidate, facts, fn)
    assert spec is not None

    assert spec.predicted_guard_set == EETH_GUARDED
    assert tuple(ep.key for ep in spec.entry_points) == EETH_GUARDED
    assert spec.contract_address == EETH_PROXY
    by_key = {ep.key: ep for ep in spec.entry_points}
    assert by_key["mintShares(address,uint256)"].from_addr == LIQUIDITY_POOL
    assert by_key["burnShares(address,uint256)"].from_addr == LIQUIDITY_POOL
    assert by_key["transfer(address,uint256)"].from_addr == cd.NEUTRAL_CALLER
    transfer_data = by_key["transfer(address,uint256)"].calldata
    assert transfer_data.startswith(cd._selector_of("transfer(address,uint256)") or "")
    assert int(transfer_data[74:], 16) == 1
    assert spec.principal == OPERATING_MULTISIG
    # A lowered guard reads the latch with no clock beside it.
    assert spec.max_pause_duration is None
    assert spec.duration_bound_source == "no_time_reference"


EXECUTE_SIG = "execute(address,uint256,bytes,bytes32,bytes32)"
SCHEDULE_SIG = "schedule(address,uint256,bytes,bytes32,bytes32,uint256)"
EXECUTE_BATCH_SIG = "executeBatch(address[],uint256[],bytes[],bytes32,bytes32)"
SCHEDULE_BATCH_SIG = "scheduleBatch(address[],uint256[],bytes[],bytes32,bytes32,uint256)"


def _timelock_facts(*, signatures: list[str] | None = None) -> cd.ContractFacts:
    """The plan finds the scheduling half by shape: the executed tuple plus a trailing delay."""
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
    """``execute`` recomputes the operation id, so a mismatch executes an unscheduled operation and proves nothing."""
    spec = _timelock_spec()
    assert spec is not None
    executed = _decode(spec.execute_calldata, EXECUTE_SIG)
    scheduled = _decode(spec.schedule_calldata(864000), SCHEDULE_SIG)
    assert scheduled[:5] == executed
    assert scheduled[5] == 864000  # the delay, and only the delay, is added


def test_the_timelock_plan_moves_an_asset_the_contract_provably_holds():
    spec = _timelock_spec(holdings=(HELD_TOKEN,))
    assert spec is not None
    target, _value, payload, _pred, _salt = _decode(spec.execute_calldata, EXECUTE_SIG)
    assert target.lower() == HELD_TOKEN.lower()
    assert payload.hex().startswith("a9059cbb")
    assert spec.witness_token == HELD_TOKEN
    assert spec.witness_calldata is not None and cd.SENTINEL_ADDRESS[2:].lower() in spec.witness_calldata.lower()


def test_the_timelock_plan_finds_the_scheduling_half_of_the_batch_arity_too():
    facts = _timelock_facts(signatures=[EXECUTE_BATCH_SIG, SCHEDULE_BATCH_SIG, "getMinDelay()"])
    fn = cd.resolve_function(facts, cd._selector_of(EXECUTE_BATCH_SIG) or "")
    assert fn is not None
    spec = cd.synthesize_timelock(_timelock_session(), _candidate(cd._selector_of(EXECUTE_BATCH_SIG) or ""), facts, fn)
    assert spec is not None
    targets, values, payloads, _pred, _salt = _decode(spec.execute_calldata, EXECUTE_BATCH_SIG)
    assert [t.lower() for t in targets] == [cd.SENTINEL_ADDRESS.lower()]
    assert values == (0,) and payloads == (b"",)


def test_the_timelock_plan_prefers_a_principal_behind_both_gates():
    """A read-only probe must never grant itself a role."""
    spec = _timelock_spec(session=_timelock_session(schedule_principal=PRINCIPAL))
    assert spec is not None
    assert spec.principal == PRINCIPAL.lower()


def test_the_timelock_plan_still_probes_as_the_executor_when_the_roles_diverge():
    spec = _timelock_spec(session=_timelock_session(schedule_principal="0x" + "99" * 20))
    assert spec is not None
    assert spec.principal == PRINCIPAL.lower()


def test_the_timelock_plan_reads_the_delay_off_the_contract():
    delay_selector = cd._selector_of("getMinDelay()")
    spec = _timelock_spec()
    assert spec is not None
    assert spec.delay_calldata == delay_selector
    # The contract's own minimum rejects zero.
    assert spec.schedule_calldata(0) == spec.schedule_calldata_zero


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
    """Tier 1 can't satisfy a block.timestamp gate, and both plans would stage under one cache key."""
    monkeypatch.setattr(cd, "synthesize", lambda *_a, **_k: _both_plans_inputs())
    plans = default_prober(
        _stub_session(),
        _candidate(TRANSFER),
        _ctx(anvil_factory=lambda: StubAnvil(guarded=set(), pause_calldata=PAUSE, duration=None)),
    )
    assert [p.gate_ref for p in plans] == ["gate:tier2"]
    assert [p.effect_class for p in plans] == [EFFECT_CLASS_VALUE_OUT]


def test_without_a_fork_the_tier1_probe_still_stands(monkeypatch):
    monkeypatch.setattr(cd, "synthesize", lambda *_a, **_k: _both_plans_inputs())
    plans = default_prober(_stub_session(), _candidate(TRANSFER), _ctx())
    assert [p.gate_ref for p in plans] == ["gate:tier1"]


from eth_utils.crypto import keccak  # noqa: E402

CALLER = "0x" + "22" * 20
SPENDER = "0x" + "33" * 20


def _slot(base: int, *keys: int) -> str:
    word = base.to_bytes(32, "big")
    for key in keys:
        word = keccak(key.to_bytes(32, "big") + word)
    return "0x" + word.hex()


def test_mapping_entry_slot_single_address_key_golden():
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


def test_token_seed_fixtures_one_per_caller_and_entry():
    entries = (
        _slot_entry(),
        _slot_entry(getter="ownerOf(uint256)", role="owner", key_kind="uint256", base_slot=cd._word_hex(2)),
    )
    fixtures = cd._token_seed_fixtures(entries, [CALLER, SPENDER], CONTRACT)
    # The owner slot is tokenId-keyed, so a second seed would overwrite the first.
    assert len(fixtures) == 3  # balance x 2 callers + owner x first caller only
    assert all(fx.kind == "set_storage_at" and fx.verify_calldata is not None for fx in fixtures)
    owner_seeds = [fx for fx in fixtures if fx.value == cd._word_hex(int(CALLER, 16))]
    assert len(owner_seeds) == 1


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
            self._pin = kwargs.get("fork_block_number")

        def fork_block_number(self):
            return self._pin

        def close(self):
            self.closed = True

    monkeypatch.setattr("services.effects.anvil.SubprocessAnvil", _FakeAnvil)
    monkeypatch.setattr("services.clients.rpc.rpc_headers", lambda url, extra=None: {"X-Test": "1"})
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
