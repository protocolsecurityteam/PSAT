"""Value-out and supply recipes on a real EVM.

Scripted simulate seams assumed EVM behaviour, which let a wrapped ``unchecked`` burn publish as dilution and a
guarded zero payout publish as an outflow. The compiled fixture runs on a local non-forking anvil through its
own ``eth_simulateV1``; skips without anvil.

Ports: 8547-8548 are ``test_effects_anvil.py``, 8551-8556 ``test_effects_token_fixtures_e2e.py``, this file
8560. Start ad-hoc anvils above that.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from services.effects import calldata as cd
from services.effects import recipes
from services.effects.anvil import SubprocessAnvil, anvil_available
from services.effects.calldata import _mapping_entry_slot, encode_calldata
from services.effects.config import VERDICT_PROVEN, VERDICT_UNKNOWN
from services.effects.harness import SimContext
from services.effects.selection import Candidate
from services.effects.simulate import SimCall, eth_simulate_v1

_FIXTURE = Path(__file__).parents[1] / "fixtures" / "effects" / "vault_value_supply.json"
_BATCH_FIXTURE = Path(__file__).parents[1] / "fixtures" / "effects" / "batch_executor_vault.json"

_PORT = 8560

CTX = SimContext(chain_id=31337, block=1, hardfork="prague")

pytestmark = [pytest.mark.skipif(not anvil_available(), reason="anvil not on PATH"), pytest.mark.anvil]

# Slots: 0 owner, 1 totalSupply, 2 balanceOf, 3 _allowances (treasury is immutable).
_BALANCE_BASE = "0x" + format(2, "064x")
_TOTAL_SUPPLY_SLOT = "0x" + format(1, "064x")

TREASURY = "0x" + "77" * 20


class RecordingStore:
    def __init__(self) -> None:
        self.stored: list[dict[str, Any]] = []

    def __call__(self, transcript: dict[str, Any]) -> str:
        self.stored.append(transcript)
        return f"artifact://transcript/{len(self.stored)}"


def _fixture() -> dict[str, Any]:
    return json.loads(_FIXTURE.read_text())


def _cd(fx: dict[str, Any], signature: str, **kw: Any) -> str:
    """A ``None`` calldata would probe the zero selector and assert nothing."""
    calldata = encode_calldata(fx["selectors"][signature], signature, **kw)
    assert calldata is not None, f"fixture cannot encode {signature}"
    return calldata


def _word(value: int) -> str:
    return "0x" + format(value, "064x")


@pytest.fixture(scope="module")
def chain():
    with SubprocessAnvil(port=_PORT) as anvil:
        yield anvil


@pytest.fixture(scope="module")
def deployed(chain):
    fx = _fixture()
    owner = chain.accounts()[0]
    ctor_arg = TREASURY[2:].rjust(64, "0")
    address = chain.deploy(owner, fx["creation_bytecode"] + ctor_arg)

    def simulate(calls, block_tag, overrides=None):
        return eth_simulate_v1(chain._url, list(calls), block_tag, overrides)

    return address, owner, simulate, fx


def _slot_overrides(address: str, entries: dict[str, str]) -> dict[str, Any]:
    return {address.lower(): {"stateDiff": dict(entries)}}


def _seeded_holder(address: str, holder: str, shares: int, supply: int) -> dict[str, Any]:
    slot = _mapping_entry_slot(_BALANCE_BASE, [int(holder, 16)])
    assert slot is not None
    return _slot_overrides(address, {slot: _word(shares), _TOTAL_SUPPLY_SLOT: _word(supply)})


def test_a_burn_whose_supply_wraps_is_published_as_a_burn(deployed):
    """The seed gives the caller more shares than exist, so the decrement wraps on a real EVM."""
    address, _owner, simulate, fx = deployed
    holder = "0x" + "22" * 20
    burned = 10**18
    shares = 2**128  # what the seeder used to write, unconditionally
    supply = 26_078_429_092_482  # a real supply, far BELOW the amount burned

    overrides = _seeded_holder(address, holder, shares, supply)

    def seeded(calls, tag, ov=None):
        return simulate(calls, tag, _merge(ov, overrides))

    calldata = _cd(fx, "exit(uint256)", substitutions={0: burned})

    # The EVM really wrapped.
    probe = seeded(
        [
            SimCall(to=address, data=calldata, from_addr=holder),
            SimCall(to=address, data=_cd(fx, "totalSupply()")),
        ],
        "latest",
    )
    assert probe.calls[0].success, "the burn itself must execute"
    assert int(probe.calls[1].return_data, 16) > 2**250, "fixture no longer wraps; the test would prove nothing"

    eff = recipes.supply(
        simulate=seeded,
        store=RecordingStore(),
        ctx=CTX,
        token_address=address,
        principal=holder,
        mint_calldata=calldata,
        simulate_supported=True,
        token_param_indexes=(),
    )

    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["supply_delta_sign"] == "burn"
    assert "backing" not in eff.details


def test_a_real_mint_is_published_as_a_mint(deployed):
    address, owner, simulate, fx = deployed
    calldata = _cd(fx, "mintTo(address,uint256)", substitutions={0: owner, 1: 1000})
    eff = recipes.supply(
        simulate=simulate,
        store=RecordingStore(),
        ctx=CTX,
        token_address=address,
        principal=owner,
        mint_calldata=calldata,
        simulate_supported=True,
        token_param_indexes=(),
    )

    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["supply_delta_sign"] == "mint"
    assert eff.details["backing"]["minted"] is True
    assert eff.details["backing"]["inflow_observed"] is False


def test_a_zero_amount_payout_moves_nothing_and_is_not_proven(deployed):
    """The call succeeds and moves nothing (``if (amount > 0)``), so it must not be proven."""
    address, owner, simulate, fx = deployed
    calldata = _cd(fx, "sweepToTreasury(uint256)", substitutions={0: 0})
    eff = recipes.value_out(
        simulate=simulate,
        store=RecordingStore(),
        ctx=CTX,
        contract_address=address,
        principal=owner,
        calldata=calldata,
        simulate_supported=True,
    )

    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.details["value_moved"] is False
    assert eff.details["observation"] == "executed"
    assert eff.reason == "no_value_observed"


def test_a_funded_payout_to_the_immutable_treasury_is_proven_fixed(deployed):
    address, owner, simulate, fx = deployed
    vault_slot = _mapping_entry_slot(_BALANCE_BASE, [int(address, 16)])
    assert vault_slot is not None
    funded = _slot_overrides(address, {vault_slot: _word(10**18)})
    calldata = _cd(fx, "sweepToTreasury(uint256)", substitutions={0: 500})

    eff = recipes.value_out(
        simulate=lambda calls, tag, ov=None: simulate(calls, tag, _merge(ov, funded)),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=address,
        principal=owner,
        calldata=calldata,
        simulate_supported=True,
        static_shape="immutable_fixed",
    )

    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["value_moved"] is True
    assert eff.details["observation"] == "executed"
    assert eff.details["destination_shape"] == "immutable_fixed"
    assert eff.details["shape_proved_by"] == "static"
    assert eff.concrete["destination"] == TREASURY.lower()


def _batch_fixture() -> dict[str, Any]:
    return json.loads(_BATCH_FIXTURE.read_text())


_BATCH_BALANCE_BASE = "0x" + format(0, "064x")


def _fn_facts(signature: str, selector: str, *, names: list[str], flows: list[dict[str, Any]]) -> cd.FunctionFacts:
    return cd.FunctionFacts(
        full_name=signature,
        selector=selector,
        canonical_signature=signature,
        effect_info={
            "function": signature,
            "selector": selector,
            "abi_signature": signature,
            "sinks": [],
            "state_writes": [],
            "value_flows": flows,
            "effect_labels": [],
            "effect_targets": [],
            "state_changing": True,
            "parameter_names": names,
        },
        tree=None,
        legacy_value_flows=(),
    )


def _candidate_for(address: str, principal: str, selector: str, **kw: Any) -> Candidate:
    return Candidate(
        function_id=1,
        contract_id=1,
        contract_address=address,
        selector=selector,
        function_name="f",
        authority_public=True,
        principal_addresses=(principal,),
        **kw,
    )


_OUT_FLOW = [{"kind": "callee_erc20_selector", "direction": "out", "origin": "body"}]


@pytest.fixture(scope="module")
def batch_vault(chain):
    """Before its deployment block the address is codeless and calls succeed vacuously, so recipes simulate at
    ``ctx.block``.
    """
    fx = _batch_fixture()
    owner = chain.accounts()[0]
    address = chain.deploy(owner, fx["creation_bytecode"])
    block = int(chain._rpc("eth_blockNumber", []), 16)
    assert chain._rpc("eth_getCode", [address, hex(block)]) not in ("0x", "0x0", None)
    ctx = SimContext(chain_id=31337, block=block, hardfork="prague")

    def simulate(calls, block_tag, overrides=None):
        return eth_simulate_v1(chain._url, list(calls), block_tag, overrides)

    return address, owner, simulate, fx, ctx


@pytest.fixture(scope="module")
def held_token(chain, batch_vault):
    """It lands in a later block, so simulating earlier would test against no token."""
    _address, owner, _simulate, fx, _ctx = batch_vault
    token = chain.deploy(owner, fx["creation_bytecode"])
    block = int(chain._rpc("eth_blockNumber", []), 16)
    assert chain._rpc("eth_getCode", [token, hex(block)]) not in ("0x", "0x0", None)
    return token, SimContext(chain_id=31337, block=block, hardfork="prague")


def _funded_vault(address: str, units: int = 10**18) -> dict[str, Any]:
    return _funded_holder(address, address, units)


def _funded_holder(token: str, holder: str, units: int = 10**18) -> dict[str, Any]:
    slot = _mapping_entry_slot(_BATCH_BALANCE_BASE, [int(holder, 16)])
    assert slot is not None
    return _slot_overrides(token, {slot: _word(units)})


_EXECUTOR_FLOW = [
    {
        "kind": "low_level_value_call",
        "direction": "out",
        "origin": "body",
        "from_is_self": True,
        "target_kind": {"kind": "param", "tier": "static_trace"},
    }
]


def test_a_batch_payout_probed_with_an_empty_array_is_the_cached_false_negative(batch_vault):
    """The encoder's empty array makes the call succeed and move nothing, a negative about a loop body never entered."""
    address, owner, simulate, fx, ctx = batch_vault
    empty = encode_calldata(fx["selectors"]["batchPay(uint256[],address[])"], "batchPay(uint256[],address[])")
    assert empty is not None

    eff = recipes.value_out(
        simulate=lambda calls, tag, ov=None: simulate(calls, tag, _merge(ov, _funded_vault(address))),
        store=RecordingStore(),
        ctx=ctx,
        contract_address=address,
        principal=owner,
        calldata=empty,
        simulate_supported=True,
    )
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.details["observation"] == "executed"
    assert eff.details["value_moved"] is False
    assert eff.reason == "no_value_observed"


def test_the_synthesized_batch_probe_reaches_the_loop_body(batch_vault):
    address, owner, simulate, fx, ctx = batch_vault
    signature = "batchPay(uint256[],address[])"
    fn = _fn_facts(
        signature,
        fx["selectors"][signature],
        names=["amounts", "recipients"],
        flows=_OUT_FLOW,
    )
    spec = cd.synthesize_value_out(_candidate_for(address, owner, fx["selectors"][signature]), fn)
    assert spec is not None

    eff = recipes.value_out(
        simulate=lambda calls, tag, ov=None: simulate(calls, tag, _merge(ov, _funded_vault(address))),
        store=RecordingStore(),
        ctx=ctx,
        contract_address=address,
        principal=owner,
        calldata=spec.calldata,
        simulate_supported=True,
    )
    assert eff.verdict == VERDICT_PROVEN, eff.reason
    assert eff.details["value_moved"] is True
    assert eff.details["observation"] == "executed"
    assert eff.concrete["destination"] == owner.lower()


def _executor_probe(batch_vault, held_token, signature, *, holds_asset: bool):
    address, owner, simulate, fx, _vault_ctx = batch_vault
    token, ctx = held_token
    holdings = (token,) if holds_asset else ()
    selector = fx["selectors"][signature]
    names = ["targets", "data", "values"] if "[]" in signature else ["target", "data", "value"]
    fn = _fn_facts(signature, selector, names=names, flows=_EXECUTOR_FLOW)
    spec = cd.synthesize_value_out(_candidate_for(address, owner, selector, input_token_addresses=holdings), fn)
    assert spec is not None
    funded = _funded_holder(token, address)
    eff = recipes.value_out(
        simulate=lambda calls, tag, ov=None: simulate(calls, tag, _merge(ov, funded)),
        store=RecordingStore(),
        ctx=ctx,
        contract_address=address,
        principal=owner,
        calldata=spec.calldata,
        sentinel_address=spec.sentinel_address,
        sentinel_calldata=spec.sentinel_calldata,
        simulate_supported=True,
    )
    return spec, eff


@pytest.mark.parametrize("signature", ["forward(address,bytes,uint256)", "forward(address[],bytes[],uint256[])"])
def test_an_executor_probed_without_an_inner_call_witnesses_nothing(batch_vault, held_token, signature):
    """Forwarding empty calldata succeeds: "moved no value" about a function that can move everything."""
    _spec, eff = _executor_probe(batch_vault, held_token, signature, holds_asset=False)
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.details["observation"] == "executed"
    assert eff.details["value_moved"] is False


@pytest.mark.parametrize("signature", ["forward(address,bytes,uint256)", "forward(address[],bytes[],uint256[])"])
def test_an_executor_moves_a_held_asset_to_a_destination_the_caller_named(batch_vault, held_token, signature):
    """The sentinel variant makes caller-redirected funds an observation, not an inference."""
    spec, eff = _executor_probe(batch_vault, held_token, signature, holds_asset=True)
    assert held_token[0][2:].lower() in spec.calldata.lower()
    assert eff.verdict == VERDICT_PROVEN, eff.reason
    assert eff.details["value_moved"] is True
    assert eff.details["observation"] == "executed"
    assert eff.details["destination_shape"] == "caller_arbitrary"
    assert eff.details["shape_proved_by"] == "simulation"
    # The sentinel is fabricated and must never be published as the destination.
    assert eff.concrete.get("destination") != cd.SENTINEL_ADDRESS.lower()


def _merge(base: Any, extra: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {k: dict(v) for k, v in (base or {}).items()}
    for address, entry in extra.items():
        target = merged.setdefault(address, {})
        diff = dict(target.get("stateDiff") or {})
        diff.update(entry.get("stateDiff") or {})
        target["stateDiff"] = diff
    return merged
