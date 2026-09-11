"""End-to-end proof of the value-out and supply recipes on a real EVM.

Every other test of these two recipes scripts the simulate seam: a ``_Recorder``
replays hand-written ``SimResult``s, so the arithmetic and the log parsing are
exercised but the EVM's own behaviour is assumed. That assumption is exactly
where two published-wrong verdicts came from, and neither was reachable from a
scripted block:

  * a burn whose ``unchecked { totalSupply -= amount }`` WRAPPED past zero,
    because the caller had been seeded more shares than existed. The wrapped
    supply read as a near-``2^256`` increase, i.e. a mint — and the recipe
    published it as proven, witnessed dilution on a call that destroyed units.
  * a payout the callee provably guards out (``if (amount > 0)``), reported as
    an outflow that cannot execute.

Both need a real ``SUB`` opcode and a real revert, so this test deploys the
compiled fixture to a local NON-FORKING anvil and drives the production recipes
against it through ``eth_simulateV1`` — anvil's own, no scripting anywhere.

Gated behind ``anvil_available`` (the fixture ships pre-compiled bytecode, so no
solc is needed here). No live marker, no RPC, no forking anvil.

NOTE ON PORTS. Every anvil in the offline suite binds a fixed localhost port, so
a duplicate is a spurious failure in whichever test loses the race — and it only
shows up when the files run together, never in isolation. Currently taken:
8547-8548 (``test_effects_anvil.py``) and 8551-8556
(``test_effects_token_fixtures_e2e.py``). This file takes 8560; an ad-hoc anvil
should start above that.
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

# Clear of every other anvil in the suite — see the module docstring.
_PORT = 8560

CTX = SimContext(chain_id=31337, block=1, hardfork="prague")

pytestmark = [pytest.mark.skipif(not anvil_available(), reason="anvil not on PATH"), pytest.mark.anvil]

# Storage layout of the fixture, read straight off its source declaration order:
#   0 owner, 1 totalSupply, 2 balanceOf, 3 _allowances  (treasury is immutable).
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
    """Encode a call to one of the fixture's own functions, refusing to proceed on
    a signature it does not export — a silently-``None`` calldata would probe the
    zero selector and the assertions below would be about nothing."""
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
    """Deploy the vault once and hand back ``(address, owner, simulate)``."""
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
    """Give ``holder`` a share balance and set the vault's ``totalSupply``."""
    slot = _mapping_entry_slot(_BALANCE_BASE, [int(holder, 16)])
    assert slot is not None
    return _slot_overrides(address, {slot: _word(shares), _TOTAL_SUPPLY_SLOT: _word(supply)})


# ---------------------------------------------------------------------------
# Supply — the burn that wraps
# ---------------------------------------------------------------------------


def test_a_burn_whose_supply_wraps_is_published_as_a_burn(deployed):
    """The seed hands the caller MORE shares than exist, so the vault's
    ``unchecked`` decrement wraps past zero on a real EVM. Nothing here scripts
    the arithmetic: anvil computes it, and the recipe has to read the sign the
    EVM actually produced rather than the one Python's arbitrary-precision
    subtraction suggests."""
    address, _owner, simulate, fx = deployed
    holder = "0x" + "22" * 20
    burned = 10**18
    shares = 2**128  # what the seeder used to write, unconditionally
    supply = 26_078_429_092_482  # a real supply, far BELOW the amount burned

    overrides = _seeded_holder(address, holder, shares, supply)

    def seeded(calls, tag, ov=None):
        return simulate(calls, tag, _merge(ov, overrides))

    calldata = _cd(fx, "exit(uint256)", substitutions={0: burned})

    # Precondition, asserted rather than assumed: the EVM really did wrap. Without
    # this the test would keep passing while quietly exercising nothing — a burn
    # of less than the supply needs no guard to read correctly.
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
    # Backing/dilution belongs to mints alone; a burn must never carry it.
    assert "backing" not in eff.details


def test_a_real_mint_is_published_as_a_mint(deployed):
    """The control: same recipe, same chain, a call that genuinely prints units."""
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
    # No asset came in, and the mint emitted a real Transfer from 0x0: this is
    # the witnessed-dilution shape, earned rather than assumed.
    assert eff.details["backing"]["minted"] is True
    assert eff.details["backing"]["inflow_observed"] is False


# ---------------------------------------------------------------------------
# Value-out — a guarded payout that cannot execute
# ---------------------------------------------------------------------------


def test_a_zero_amount_payout_moves_nothing_and_is_not_proven(deployed):
    """``sweepToTreasury(0)`` runs to completion and transfers nothing, because
    the contract guards ``if (amount > 0)``. The call SUCCEEDS, so the row must
    separate "ran and moved nothing" from "never ran" — and must not be proven."""
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
    # It EXECUTED — the guard skipped the transfer. A reverted probe would be a
    # different row entirely, and a consumer must be able to tell them apart.
    assert eff.details["observation"] == "executed"
    assert eff.reason == "no_value_observed"


def test_a_funded_payout_to_the_immutable_treasury_is_proven_fixed(deployed):
    """The same function with a non-zero amount and a funded vault moves value —
    and the destination is an immutable the caller cannot name, which static
    proves and the recipe publishes as a shape the fork's own transfer confirms."""
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
    # Static named the SHAPE (a universal); the fork supplied the ADDRESS.
    assert eff.details["destination_shape"] == "immutable_fixed"
    assert eff.details["shape_proved_by"] == "static"
    assert eff.concrete["destination"] == TREASURY.lower()


# ---------------------------------------------------------------------------
# Value-out — a body that only runs for a non-empty array
# ---------------------------------------------------------------------------


def _batch_fixture() -> dict[str, Any]:
    return json.loads(_BATCH_FIXTURE.read_text())


# Storage layout of the batch fixture: slot 0 is ``balanceOf``.
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
    """Deploy the batch/executor vault and hand back
    ``(address, owner, simulate, fx, ctx)``.

    The context carries the block this deployment landed in, and that is not
    decoration: the recipes simulate at ``ctx.block``, and at any earlier block
    this address is CODELESS — a call to which succeeds and moves nothing. Every
    assertion below would then be about a contract that did not exist yet, which
    is the fabricated non-observation this whole file exists to catch."""
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
    """A SECOND deployment of the same fixture, standing in for an asset the vault
    under probe holds. Nothing about it is vault-specific — the executor only ever
    calls ``transfer`` on it, which is the ERC-20 standard.

    Carries its own context for the same reason the vault does: this deployment
    lands in a LATER block, and simulated before it the token is a codeless
    address — which a low-level call succeeds against while moving nothing, i.e.
    it would turn this test green against no token at all."""
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
    """The control, and the reason the fixture exists: with the encoder's own
    default in the array slots the call SUCCEEDS and moves nothing, so the row
    reads "executed, moved no value" — a negative published about a loop body the
    probe never entered."""
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
    """The non-empty-array probe end to end: PRODUCTION synthesis builds the calldata, and the same
    function that moved nothing above now moves value on a real EVM."""
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


# ---------------------------------------------------------------------------
# Value-out — an arbitrary-call executor
# ---------------------------------------------------------------------------


def _executor_probe(batch_vault, held_token, signature, *, holds_asset: bool):
    """Synthesize and run the value-out probe for one executor signature, with or
    without a measured holding to build an inner call from. Returns
    ``(spec, effect)``."""
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
    """The control. With no measured holding there is no honest inner call, so
    the payload slot keeps the encoder's empty bytes — and forwarding empty
    calldata to an account SUCCEEDS. The row then reads "executed, moved no
    value" about a function that can move everything the contract holds."""
    _spec, eff = _executor_probe(batch_vault, held_token, signature, holds_asset=False)
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.details["observation"] == "executed"
    assert eff.details["value_moved"] is False


@pytest.mark.parametrize("signature", ["forward(address,bytes,uint256)", "forward(address[],bytes[],uint256[])"])
def test_an_executor_moves_a_held_asset_to_a_destination_the_caller_named(batch_vault, held_token, signature):
    """The executor inner-call synthesis end to end, both arities. It forwards an ERC-20
    transfer of an asset the deployment provably holds, and the sentinel variant
    puts the attacker identity in the payload's recipient — so the caller
    redirecting the funds is an OBSERVATION, not an inference."""
    spec, eff = _executor_probe(batch_vault, held_token, signature, holds_asset=True)
    # The token came from measured holdings, and it is in the destination slot.
    assert held_token[0][2:].lower() in spec.calldata.lower()
    assert eff.verdict == VERDICT_PROVEN, eff.reason
    assert eff.details["value_moved"] is True
    assert eff.details["observation"] == "executed"
    assert eff.details["destination_shape"] == "caller_arbitrary"
    assert eff.details["shape_proved_by"] == "simulation"
    # The sentinel is a fabricated address and must never be published as the
    # place the money went; the BASE probe pays the principal.
    assert eff.concrete.get("destination") != cd.SENTINEL_ADDRESS.lower()


def _merge(base: Any, extra: dict[str, Any]) -> dict[str, Any]:
    """Union two state-override maps, with ``extra``'s stateDiff winning per slot."""
    merged: dict[str, Any] = {k: dict(v) for k, v in (base or {}).items()}
    for address, entry in extra.items():
        target = merged.setdefault(address, {})
        diff = dict(target.get("stateDiff") or {})
        diff.update(entry.get("stateDiff") or {})
        target["stateDiff"] = diff
    return merged
