"""What may occupy a caller-supplied token argument.

The 2026-07-25 run left all 8 supply verdicts unknown: the principal went into every address argument, so
deposits reverted. A token slot needs a real token, and until then no backing witness may be published, since
``address(0)`` makes ``safeTransfer`` a codeless no-op that mints against a pull that never happened.
"""

from __future__ import annotations

from typing import Any

from eth_utils.crypto import keccak

from services.effects import calldata as cd
from services.effects import recipes
from services.effects.config import VERDICT_PROVEN
from services.effects.harness import SimContext
from services.effects.seeding import Seeding
from services.effects.selection import Candidate
from services.effects.simulate import SimCallResult, SimResult
from tests.support.effects_stubs import RecordingStore, transfer_log

VAULT = "0x" + "c0" * 20
PRINCIPAL = "0x" + "22" * 20
TOKEN_A = "0x" + "a1" * 20
TOKEN_B = "0x" + "b2" * 20
CTX = SimContext(chain_id=1, block=1000, hardfork="prague")


def _sel(sig: str) -> str:
    return "0x" + keccak(text=sig).hex()[:8]


def _facts(
    sig: str,
    *,
    parameter_names: list[str],
    sinks: list[dict[str, Any]] | None = None,
    labels: list[str] | None = None,
) -> cd.ContractFacts:
    selector = _sel(sig)
    info = {
        "function": sig,
        "selector": selector,
        "abi_signature": sig,
        "sinks": sinks or [],
        "state_writes": [],
        "value_flows": [],
        "effect_labels": labels if labels is not None else ["mint"],
        "effect_targets": [],
        "state_changing": True,
        "parameter_names": parameter_names,
        "payable": False,
    }
    return cd.ContractFacts(
        address=VAULT,
        job_id="job-1",
        effects={sig: info},
        trees={},
        canonical_signatures={sig: sig},
        legacy_value_flows={},
        by_selector={selector: sig},
    )


def _pull_sink(sig: str, target: str) -> dict[str, Any]:
    """Its selector belongs to the library, so nothing keyed on ERC-20 selectors sees it."""
    return {
        "id": f"{sig}:sink0:external_call:{target}.safeTransferFrom",
        "function": sig,
        "kind": "external_call",
        "target": f"{target}.safeTransferFrom",
        "selector": "0x9729bb1e",
        "origin": "body",
    }


def _candidate(sig: str, *, holdings: tuple[str, ...] = ()) -> Candidate:
    return Candidate(
        function_id=1,
        contract_id=1,
        contract_address=VAULT,
        selector=_sel(sig),
        function_name=sig.split("(")[0],
        authority_public=False,
        principal_addresses=(PRINCIPAL,),
        input_token_addresses=holdings,
    )


def _spec(facts: cd.ContractFacts, sig: str, *, holdings: tuple[str, ...] = ()):
    fn = cd.resolve_function(facts, _sel(sig))
    assert fn is not None
    spec = cd.synthesize_supply(_candidate(sig, holdings=holdings), fn)
    assert spec is not None
    return spec


def _arg(data: str, index: int) -> str:
    start = 10 + index * 64
    return "0x" + data[start + 24 : start + 64]


def _roles(sig: str, names: list[str], sinks: list[dict[str, Any]] | None = None) -> dict[int, str]:
    facts = _facts(sig, parameter_names=names, sinks=sinks)
    fn = cd.resolve_function(facts, _sel(sig))
    assert fn is not None
    types = ["address" if t.strip() == "address" else t.strip() for t in sig[sig.index("(") + 1 : -1].split(",")]
    return cd.address_param_roles(fn, types)


def test_token_slot_reaches_the_plan_and_the_holdings_ride_with_it():
    sig = "deposit(address,uint256,address)"
    spec = _spec(
        _facts(sig, parameter_names=["depositAsset", "amount", "receiver"]),
        sig,
        holdings=(TOKEN_A, TOKEN_B),
    )
    assert spec.token_param_indexes == (0,)
    assert TOKEN_A in spec.input_token_hints
    assert spec.input_token_hints[-1] == cd.SELF_TOKEN_HINT


def test_a_state_var_called_through_becomes_a_getter_hint_but_a_parameter_never_does():
    sig = "deposit(address,uint256)"
    facts = _facts(
        sig,
        parameter_names=["depositAsset", "amount"],
        sinks=[_pull_sink(sig, "depositAsset"), _pull_sink(sig, "nativeWrapper")],
    )
    fn = cd.resolve_function(facts, _sel(sig))
    assert fn is not None
    hints = cd.input_token_hints(fn)
    assert "nativeWrapper()" in hints
    # There is no storage behind a parameter.
    assert "depositAsset()" not in hints


def _seeding(*tokens: str) -> Seeding:
    return Seeding(
        overrides={t: {"stateDiff": {}} for t in tokens},
        readback_calls=(),
        readback_expected=(),
        tokens=tokens,
        decimals=18,
    )


def _attempts(sig: str, names: list[str], seeding: Seeding | None, *, holdings: tuple[str, ...] = (TOKEN_A,)):
    spec = _spec(_facts(sig, parameter_names=names), sig, holdings=holdings)
    transcript: dict[str, Any] = {}
    return (
        recipes._seed_attempts(
            seeder=(lambda _req: seeding),
            transcript=transcript,
            contract_address=VAULT,
            principal=PRINCIPAL,
            token_hints=spec.input_token_hints,
            seeded_calldata=spec.seeded_calldata,
            seeded_sentinel_calldata={},
            block_tag="0x1",
            target_payable=False,
            token_param_indexes=spec.token_param_indexes,
        ),
        transcript,
    )


def test_seeded_retry_writes_the_resolved_token_into_the_token_slot():
    attempts, transcript = _attempts(
        "deposit(address,uint256,address)", ["depositAsset", "amount", "receiver"], _seeding(TOKEN_A)
    )
    assert attempts
    assert _arg(attempts[0].calldata, 0) == TOKEN_A
    assert _arg(attempts[0].calldata, 2) == PRINCIPAL
    assert transcript["seeding"]["token_args"] == {"0": TOKEN_A}


def test_two_token_slots_take_two_distinct_tokens():
    attempts, _ = _attempts(
        "swap(address,address,uint256,address)", ["tokenIn", "tokenOut", "amountIn", "to"], _seeding(TOKEN_A, TOKEN_B)
    )
    assert _arg(attempts[0].calldata, 0) == TOKEN_A
    assert _arg(attempts[0].calldata, 1) == TOKEN_B


def test_the_probe_target_is_never_written_into_a_token_slot():
    """A vault's own share token as the deposit asset gives a mint whose only inflow the backing rule discards."""
    attempts, transcript = _attempts(
        "deposit(address,uint256,address)", ["depositAsset", "amount", "receiver"], _seeding(VAULT)
    )
    assert _arg(attempts[0].calldata, 0) == PRINCIPAL
    assert {"label": "seed_path", "outcome": "skipped_no_token_for_param"} in transcript["seed_attempts"]


def _supply(sig: str, names: list[str], results, *, seeding: Seeding | None = None, holdings=(TOKEN_A,)):
    spec = _spec(_facts(sig, parameter_names=names), sig, holdings=holdings)
    store = RecordingStore()
    blocks = list(results)

    def simulate(calls, block_tag=None, overrides=None):
        return blocks.pop(0)

    return recipes.supply(
        simulate=simulate,
        store=store,
        ctx=CTX,
        token_address=VAULT,
        principal=PRINCIPAL,
        mint_calldata=spec.mint_calldata,
        simulate_supported=True,
        seeder=(lambda _req: seeding),
        input_token_hints=spec.input_token_hints,
        token_param_indexes=spec.token_param_indexes,
        seeded_calldata=spec.seeded_calldata,
        target_payable=False,
    )


def _reverted_block() -> SimResult:
    return SimResult(
        calls=(
            SimCallResult(True, "0x0", None, ()),
            SimCallResult(False, "0x", "0x", ()),
            SimCallResult(True, "0x0", None, ()),
        )
    )


def _supply_block(before: int, after: int, logs=()):
    return SimResult(
        calls=(
            SimCallResult(True, hex(before), None, ()),
            SimCallResult(True, "0x", None, tuple(logs)),
            SimCallResult(True, hex(after), None, ()),
        )
    )


def test_backing_is_published_once_every_token_slot_carried_a_proven_token():
    reverted = _reverted_block()
    seeded = _supply_block(
        0,
        100,
        [
            transfer_log(TOKEN_A, PRINCIPAL, VAULT, 5),
            transfer_log(VAULT, "0x" + "00" * 20, PRINCIPAL, 100),
        ],
    )
    eff = _supply(
        "deposit(address,uint256,address)",
        ["depositAsset", "amount", "receiver"],
        [reverted, seeded],
        seeding=_seeding(TOKEN_A),
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["backing"]["inflow_observed"] is True
    assert eff.concrete["backing_inflow_transfers"] == 1


def test_seeding_a_token_cannot_by_itself_produce_an_inflow():
    """Storage writes emit no logs."""
    reverted = _reverted_block()
    seeded = _supply_block(0, 100, [transfer_log(VAULT, "0x" + "00" * 20, PRINCIPAL, 100)])
    eff = _supply(
        "deposit(address,uint256,address)",
        ["depositAsset", "amount", "receiver"],
        # The recipient slot still holds the prober's identity, so the negative needs the inertness differential.
        [reverted, seeded, seeded],
        seeding=_seeding(TOKEN_A),
    )
    assert eff.details["backing"]["inflow_observed"] is False
    assert eff.details["backing"]["input_seeded"] is True
