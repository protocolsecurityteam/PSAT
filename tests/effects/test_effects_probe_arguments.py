"""Three prober faults from the 2026-07-22 live run: the amount went into every integer argument, a ``msg.value``
retry hit non-payable targets, and an unfundable payout recorded no reason. Fixtures are generic so a pass can't
come from recognizing a protocol.
"""

from __future__ import annotations

from typing import Any

from eth_utils.crypto import keccak

from services.effects import calldata as cd
from services.effects import recipes
from services.effects.config import VERDICT_PROVEN
from services.effects.harness import SimContext
from services.effects.seeding import SEED_CONTRACT_ETH_BALANCE, SeedBudget
from services.effects.selection import Candidate
from services.effects.simulate import SimCallResult, SimResult
from tests.support.effects_stubs import RecordingStore, ok, transfer_log

CONTRACT = "0x" + "c0" * 20
PRINCIPAL = "0x" + "22" * 20
RECIPIENT = "0x" + "33" * 20
CTX = SimContext(chain_id=1, block=1000, hardfork="prague")


def _sel(sig: str) -> str:
    return "0x" + keccak(text=sig).hex()[:8]


def _facts(sig: str, *, parameter_names: list[str], flows: list[dict[str, Any]] | None = None) -> cd.ContractFacts:
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


def test_id_shaped_param_never_receives_the_probe_amount():
    """The seeded retry used to raise a token id to one whole unit."""
    sig = "redeem(uint256)"
    spec = _spec(_facts(sig, parameter_names=["tokenId"]), sig)
    assert _word(spec.calldata, 0) == cd.ARG_IDENTIFIER
    for decimals, encoded in spec.seeded_calldata.items():
        assert _word(encoded, 0) == cd.ARG_IDENTIFIER, decimals


def test_payability_and_native_payout_reach_the_plan():
    sig = "redeem(uint256)"
    spec = _spec(_facts(sig, parameter_names=["tokenId"]), sig)
    assert spec.target_payable is False
    assert spec.native_payout is True


class _Chain:
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

    def seeder(_request):
        return None

    seeder.budget = budget if budget is not None else SeedBudget()  # pyright: ignore[reportFunctionMemberAccess]
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
    """``executed=0`` must never be silent."""
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


class _UnderfundedChain:
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
    assert eff.details["contract_balance_seeded"] is True
    assert store.stored[-1]["contract_balance_seeded"] is True
