"""What a probe is allowed to put in an argument, and which attempts it may fire.

Three failures the 2026-07-22 live run made visible, all of them the prober's own
fault rather than the contract's:

* the probe amount was written into EVERY integer argument, so a redemption's
  token id received one whole token unit and the call reverted on its own input
  (``ERC721: invalid token ID``);
* a ``msg.value`` retry was appended unconditionally, and a non-payable target
  rejects it with an EMPTY revert before its body runs — 9 of 13 seeded calls;
* a payout the contract could not fund (its own ETH balance was short) read as a
  non-observation, with nothing recorded to say which precondition failed.

The fixtures here are deliberately generic shapes — a plain ERC-721
``redeem(uint256 id)``, a ``withdraw(uint256 amount, uint256 deadline)`` — so a
pass cannot come from recognizing a protocol.
"""

from __future__ import annotations

from typing import Any

from eth_utils.crypto import keccak

from services.effects import calldata as cd
from services.effects import recipes
from services.effects.config import VERDICT_PROVEN, VERDICT_UNKNOWN
from services.effects.harness import SimContext
from services.effects.seeding import SEED_CONTRACT_ETH_BALANCE, SEED_ETH_VALUE, SeedBudget
from services.effects.selection import Candidate
from services.effects.simulate import SimCallResult, SimResult
from tests.test_effects_harness import RecordingStore, ok, transfer_log

CONTRACT = "0x" + "c0" * 20
PRINCIPAL = "0x" + "22" * 20
RECIPIENT = "0x" + "33" * 20
CTX = SimContext(chain_id=1, block=1000, hardfork="prague")

_ONE_UNIT = 10**18


def _sel(sig: str) -> str:
    return "0x" + keccak(text=sig).hex()[:8]


def _facts(sig: str, *, parameter_names: list[str], flows: list[dict[str, Any]] | None = None) -> cd.ContractFacts:
    """A one-function contract whose static facts say the function pays ETH out."""
    selector = _sel(sig)
    info = {
        "function": sig,
        "selector": selector,
        "abi_signature": sig,
        "sinks": [],
        "state_writes": [],
        "value_flows": flows
        if flows is not None
        else [{"kind": "native_transfer_send", "direction": "out", "origin": "body"}],
        "effect_labels": [],
        "effect_targets": [],
        "state_changing": True,
        "parameter_names": parameter_names,
        "payable": False,
    }
    return cd.ContractFacts(
        address=CONTRACT,
        job_id="job-1",
        effects={sig: info},
        trees={},
        canonical_signatures={sig: sig},
        legacy_value_flows={},
        by_selector={selector: sig},
    )


def _candidate(sig: str) -> Candidate:
    return Candidate(
        function_id=1,
        contract_id=1,
        contract_address=CONTRACT,
        selector=_sel(sig),
        function_name=sig.split("(")[0],
        authority_public=False,
        effect_targets=("x",),
        principal_addresses=(PRINCIPAL,),
    )


def _spec(facts: cd.ContractFacts, sig: str):
    fn = cd.resolve_function(facts, _sel(sig))
    assert fn is not None
    spec = cd.synthesize_value_out(_candidate(sig), fn)
    assert spec is not None
    return spec


def _word(data: str, index: int) -> int:
    start = 10 + index * 64
    return int(data[start : start + 64], 16)


# ---------------------------------------------------------------------------
# 1. argument roles
# ---------------------------------------------------------------------------


def test_id_shaped_param_never_receives_the_probe_amount():
    """A plain ERC-721 redemption: the only argument is a token id, and the
    seeded retry used to raise it to one whole token unit."""
    sig = "redeem(uint256)"
    spec = _spec(_facts(sig, parameter_names=["tokenId"]), sig)
    assert _word(spec.calldata, 0) == cd.ARG_IDENTIFIER
    # The seeded retry scales the QUANTITY; an id is not one, at any token scale.
    for decimals, encoded in spec.seeded_calldata.items():
        assert _word(encoded, 0) == cd.ARG_IDENTIFIER, decimals


def test_amount_goes_only_to_the_named_quantity():
    """``withdraw(uint256 amount, uint256 deadline)``: one argument is a quantity
    and one is a timestamp. Filling both with the amount is what a blunt
    substitution does; filling the deadline with 1 wei makes every call expire."""
    sig = "withdraw(uint256,uint256)"
    spec = _spec(_facts(sig, parameter_names=["amount", "deadline"]), sig)
    assert _word(spec.calldata, 0) == cd.ARG_AMOUNT
    assert _word(spec.calldata, 1) == 0
    assert _word(spec.seeded_calldata[18], 0) == _ONE_UNIT
    assert _word(spec.seeded_calldata[18], 1) == 0


def test_flow_lattice_names_the_quantity_when_the_source_did_not():
    """No parameter names (an older artifact), but the flow lattice resolved which
    entry parameter the outgoing amount came from — the dispositive fact."""
    sig = "pay(uint256,uint256)"
    flows = [
        {
            "kind": "native_transfer_send",
            "direction": "out",
            "origin": "body",
            "amount_kind": {"kind": "param", "tier": "dispositive_ast"},
            "amount_param_index": 1,
        }
    ]
    spec = _spec(_facts(sig, parameter_names=[], flows=flows), sig)
    assert _word(spec.calldata, 0) == 0
    assert _word(spec.calldata, 1) == cd.ARG_AMOUNT


def test_unproven_role_takes_no_substitution_at_all():
    """No names, no lattice index: the honest filler is the encoder's zero. A
    guessed quantity in an unknown slot is how a probe reverts on itself."""
    sig = "act(uint256,uint256)"
    spec = _spec(_facts(sig, parameter_names=[]), sig)
    assert _word(spec.calldata, 0) == 0
    assert _word(spec.calldata, 1) == 0


def test_lattice_index_ignored_unless_the_amount_kind_is_param():
    sig = "pay(uint256,uint256)"
    flows = [
        {
            "kind": "native_transfer_send",
            "direction": "out",
            "origin": "body",
            "amount_kind": {"kind": "whole_balance", "tier": "static_trace"},
            "amount_param_index": 1,
        }
    ]
    spec = _spec(_facts(sig, parameter_names=[], flows=flows), sig)
    assert _word(spec.calldata, 1) == 0


def test_payability_and_native_payout_reach_the_plan():
    sig = "redeem(uint256)"
    spec = _spec(_facts(sig, parameter_names=["tokenId"]), sig)
    assert spec.target_payable is False
    assert spec.native_payout is True


# ---------------------------------------------------------------------------
# 2. attempts that cannot witness anything are not issued
# ---------------------------------------------------------------------------


class _Chain:
    """A contract that reverts every call, recording what it was asked."""

    def __init__(self, *, revert_data: str | None = "0x") -> None:
        self.blocks: list[tuple[list, str, dict | None]] = []
        self.revert_data = revert_data

    def __call__(self, calls, block_tag, overrides):
        self.blocks.append((list(calls), block_tag, overrides))
        return SimResult(calls=tuple(SimCallResult(False, "0x", self.revert_data, ()) for _ in calls))

    @property
    def target_values(self) -> list[int]:
        return [c.value for block, _t, _o in self.blocks for c in block if c.to.lower() == CONTRACT.lower()]


def _seeder(budget: SeedBudget | None = None):
    """A seeder that resolves nothing — the shape of a target with no input asset."""

    def seeder(_request):
        return None

    seeder.budget = budget if budget is not None else SeedBudget()  # type: ignore[attr-defined]
    return seeder


def _value_out(chain, **kwargs):
    return recipes.value_out(
        simulate=chain,
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata=_sel("redeem(uint256)") + (1).to_bytes(32, "big").hex(),
        simulate_supported=True,
        gate_ref="gate:none",
        seeded_calldata={18: _sel("redeem(uint256)") + (1).to_bytes(32, "big").hex()},
        **kwargs,
    )


def test_non_payable_target_is_never_sent_msg_value():
    chain = _Chain()
    eff = _value_out(chain, seeder=_seeder(), target_payable=False, native_payout=False)
    assert eff.verdict == VERDICT_UNKNOWN
    # Only the unseeded probe ran: no attempt could have witnessed anything.
    assert chain.target_values == [0]


def test_unknown_payability_still_tries_msg_value():
    """Payability is tri-state: an artifact that predates the fact must not lose
    the ETH-deposit path."""
    chain = _Chain()
    _value_out(chain, seeder=_seeder(), target_payable=None, native_payout=False)
    assert SEED_ETH_VALUE in chain.target_values


def test_skipped_payable_attempt_records_why():
    store = RecordingStore()
    budget = SeedBudget()
    recipes.value_out(
        simulate=_Chain(),
        store=store,
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata=_sel("redeem(uint256)") + (1).to_bytes(32, "big").hex(),
        simulate_supported=True,
        gate_ref="gate:none",
        seeded_calldata={18: _sel("redeem(uint256)") + (1).to_bytes(32, "big").hex()},
        seeder=_seeder(budget),
        target_payable=False,
        native_payout=False,
    )
    outcomes = {entry["outcome"] for entry in store.stored[-1]["seed_attempts"]}
    assert "skipped_no_viable_attempt" in outcomes
    assert "skipped_no_token_resolved" in outcomes
    assert budget.metrics()["seed_outcome_skipped_no_viable_attempt"] >= 1


def test_every_failed_attempt_records_its_revert():
    """``executed=0`` must never be silent: each discarded attempt names the
    revert it died on."""
    store = RecordingStore()
    budget = SeedBudget()
    recipes.value_out(
        simulate=_Chain(revert_data="0x08c379a0"),
        store=store,
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata=_sel("redeem(uint256)") + (1).to_bytes(32, "big").hex(),
        simulate_supported=True,
        gate_ref="gate:none",
        seeded_calldata={18: _sel("redeem(uint256)") + (1).to_bytes(32, "big").hex()},
        seeder=_seeder(budget),
        target_payable=True,
        native_payout=False,
    )
    reverted = [e for e in store.stored[-1]["seed_attempts"] if e["outcome"] == "target_reverted"]
    assert reverted and all(e.get("detail") for e in reverted)
    assert budget.metrics()["seed_outcome_target_reverted"] == len(reverted)


# ---------------------------------------------------------------------------
# 3. contract-balance seeding — a capability claim, flagged as one
# ---------------------------------------------------------------------------


class _UnderfundedChain:
    """A payout that reverts until the CONTRACT itself holds ETH."""

    def __init__(self) -> None:
        self.blocks: list[tuple[list, str, dict | None]] = []

    def __call__(self, calls, block_tag, overrides):
        self.blocks.append((list(calls), block_tag, overrides))
        funded = int(((overrides or {}).get(CONTRACT.lower()) or {}).get("balance", "0x0"), 16)
        results = []
        for _call in calls:
            if funded >= SEED_CONTRACT_ETH_BALANCE:
                results.append(ok(logs=[transfer_log(CONTRACT, CONTRACT, RECIPIENT, 5)]))
            else:
                results.append(SimCallResult(False, "0x", "0xcd786059", ()))
        return SimResult(calls=tuple(results))

    @property
    def labels(self) -> list[str]:
        return []


def _payout(chain, **kwargs):
    return recipes.value_out(
        simulate=chain,
        store=kwargs.pop("store", RecordingStore()),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata=_sel("sweep(uint256)") + (1).to_bytes(32, "big").hex(),
        simulate_supported=True,
        gate_ref="gate:none",
        seeded_calldata={18: _sel("sweep(uint256)") + (1).to_bytes(32, "big").hex()},
        seeder=_seeder(),
        **kwargs,
    )


def test_contract_balance_seeding_proves_the_payout_and_flags_the_weaker_claim():
    chain = _UnderfundedChain()
    store = RecordingStore()
    eff = _payout(chain, store=store, target_payable=False, native_payout=True)
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["value_moved"] is True
    # The claim is "would move value if the contract were funded" and says so.
    assert eff.details["contract_balance_seeded"] is True
    assert store.stored[-1]["contract_balance_seeded"] is True


def test_contract_balance_attempt_runs_last_and_only_where_static_says_eth_leaves():
    chain = _UnderfundedChain()
    eff = _payout(chain, target_payable=True, native_payout=True)
    assert eff.verdict == VERDICT_PROVEN
    # Ordering: the funded block is the LAST one, so a less synthetic attempt
    # would always have won had it executed.
    funded = [i for i, (_c, _t, ov) in enumerate(chain.blocks) if (ov or {}).get(CONTRACT.lower(), {}).get("balance")]
    assert funded == [len(chain.blocks) - 1]

    # ...and a function static says never sends ETH out never pays for it.
    plain = _Chain()
    _value_out(plain, seeder=_seeder(), target_payable=False, native_payout=False)
    assert not any((ov or {}).get(CONTRACT.lower(), {}).get("balance") for _c, _t, ov in plain.blocks)


def test_unseeded_success_never_carries_the_capability_flag():
    """The flag exists to weaken a verdict; a probe that never needed the
    override must not carry it."""
    chain = _Chain()

    def sim(calls, tag, ov):
        chain.blocks.append((list(calls), tag, ov))
        return SimResult(calls=(ok(logs=[transfer_log(CONTRACT, CONTRACT, RECIPIENT, 5)]),))

    eff = _payout(sim, target_payable=True, native_payout=True)
    assert eff.verdict == VERDICT_PROVEN
    assert "contract_balance_seeded" not in eff.details
    assert "input_seeded" not in eff.details


def test_claims_bridge_publishes_both_synthesis_qualifiers():
    """A consumer reading the claim must see the caveat, not just the verdict."""
    from services.effects import claims_bridge

    class _Verdict:
        id = 7
        effect_class = "value_out"
        verdict = VERDICT_PROVEN
        tier = "tier1"
        behavior_hash = "h"
        current_check_passed = None
        witness = {"value_moved": True, "input_seeded": True, "contract_balance_seeded": True}
        observed_residue: dict[str, Any] | None = None

    claim = claims_bridge.verdict_to_claim(_Verdict())
    assert claim is not None
    assert claim["witness"]["observed"]["contract_balance_seeded"] is True
    assert claim["witness"]["observed"]["input_seeded"] is True
