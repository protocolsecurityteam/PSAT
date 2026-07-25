"""What may occupy a caller-supplied TOKEN argument, and what a probe may claim
about the call it produced.

The 2026-07-25 live run left all 8 supply verdicts ``unknown`` with no backing
payload: the encoder wrote the acting principal into every address argument, so
a deposit-shaped function received a non-token where it expected an ERC-20 and
reverted on its own first line (``TRANSFER_FROM_FAILED``). Two things follow.

* A token slot has to receive a REAL token before the pull can succeed, and the
  only honest source is the wire — a getter the code itself calls the asset
  through, or an asset the acting deployment provably holds.
* Until it does, no backing witness may be published. Measured on a mainnet fork
  (three independent vaults, 2026-07-25): with the encoder's default
  ``address(0)`` in the asset slot the call SUCCEEDS — a call to a codeless
  address is a no-op success inside every ``safeTransfer`` wrapper — and mints
  against a pull that never happened. Reporting that as
  ``backing.inflow_observed: false`` turns a deposit-backed conversion into
  witnessed dilution, on evidence the prober manufactured.

Fixtures are generic shapes — an ERC-4626 ``deposit(uint256,address)``, a
``swap(address,address,uint256,address)``, a name-free parameter identified only
by the sink that calls through it — so a pass cannot come from recognizing a
protocol.
"""

from __future__ import annotations

from typing import Any

from eth_utils.crypto import keccak

from services.effects import calldata as cd
from services.effects import recipes
from services.effects.config import VERDICT_PROVEN
from services.effects.harness import SimContext
from services.effects.seeding import Seeding
from services.effects.selection import Candidate, select_candidates
from services.effects.simulate import SimCallResult, SimResult
from tests.conftest import ADDR, requires_postgres
from tests.test_effects_harness import RecordingStore, transfer_log
from tests.test_effects_selection import _contract, _fn, _protocol

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
    """A body call THROUGH a name — the shape a library-wrapped pull leaves
    behind. Its selector belongs to the library, so nothing keyed on ERC-20
    selectors can see it."""
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
        effect_targets=("x",),
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


# ---------------------------------------------------------------------------
# 1. role classification
# ---------------------------------------------------------------------------


def test_asset_named_slot_is_a_token_and_the_receiver_is_not():
    roles = _roles("deposit(address,uint256,address)", ["depositAsset", "amount", "receiver"])
    assert roles[0] == cd.ROLE_TOKEN
    assert roles[2] == cd.ROLE_RECIPIENT


def test_a_swap_names_both_of_its_token_slots():
    roles = _roles("swap(address,address,uint256,address)", ["tokenIn", "tokenOut", "amountIn", "to"])
    assert roles[0] == cd.ROLE_TOKEN
    assert roles[1] == cd.ROLE_TOKEN
    assert roles[3] == cd.ROLE_RECIPIENT


def test_a_sink_calling_through_a_parameter_names_it_a_token_without_any_vocabulary():
    """No token word anywhere in the name: the evidence is that the body calls an
    ERC-20 method THROUGH that parameter."""
    sig = "pull(address,uint256)"
    roles = _roles(sig, ["x", "n"], [_pull_sink(sig, "x")])
    assert roles[0] == cd.ROLE_TOKEN


def test_a_name_carrying_both_vocabularies_is_no_evidence_at_all():
    """Demoting a payout destination to a token slot costs the observation the
    probe exists for, so an ambiguous name keeps the principal."""
    roles = _roles("send(address,uint256)", ["tokenRecipient", "amount"])
    assert roles[0] == cd.ROLE_RECIPIENT


def test_an_unnamed_address_slot_gets_no_role():
    roles = _roles("act(address,uint256)", ["", ""])
    assert 0 not in roles


# ---------------------------------------------------------------------------
# 2. what the plan carries
# ---------------------------------------------------------------------------


def test_token_slot_reaches_the_plan_and_the_holdings_ride_with_it():
    sig = "deposit(address,uint256,address)"
    spec = _spec(
        _facts(sig, parameter_names=["depositAsset", "amount", "receiver"]),
        sig,
        holdings=(TOKEN_A, TOKEN_B),
    )
    assert spec.token_param_indexes == (0,)
    # Offered to the seeder as already-resolved addresses, ahead of the self
    # fallback and behind the getters.
    assert TOKEN_A in spec.input_token_hints
    assert spec.input_token_hints[-1] == cd.SELF_TOKEN_HINT


def test_holdings_are_withheld_from_a_function_with_no_token_slot():
    """A function that takes no token cannot spend a layout discovery on one."""
    sig = "mint(address,uint256)"
    spec = _spec(_facts(sig, parameter_names=["to", "amount"]), sig, holdings=(TOKEN_A,))
    assert spec.token_param_indexes == ()
    assert TOKEN_A not in spec.input_token_hints


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
    # There is no storage behind a parameter; asking for ``depositAsset()``
    # spends a call to learn nothing.
    assert "depositAsset()" not in hints


def test_substitute_address_arg_fails_closed_on_a_slot_that_is_not_there():
    data = "0x" + "aa" * 4 + "00" * 32
    assert cd.substitute_address_arg(data, 1, TOKEN_A) is None
    assert cd.substitute_address_arg(data, 0, "0xnope") is None
    assert _arg(cd.substitute_address_arg(data, 0, TOKEN_A) or "", 0) == TOKEN_A


# ---------------------------------------------------------------------------
# 3. the seeded retry writes a proven token — and only a proven one
# ---------------------------------------------------------------------------


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
    # The recipient slot keeps the identity that makes the payout observable.
    assert _arg(attempts[0].calldata, 2) == PRINCIPAL
    assert transcript["seeding"]["token_args"] == {"0": TOKEN_A}


def test_two_token_slots_take_two_distinct_tokens():
    attempts, _ = _attempts(
        "swap(address,address,uint256,address)", ["tokenIn", "tokenOut", "amountIn", "to"], _seeding(TOKEN_A, TOKEN_B)
    )
    assert _arg(attempts[0].calldata, 0) == TOKEN_A
    assert _arg(attempts[0].calldata, 1) == TOKEN_B


def test_the_probe_target_is_never_written_into_a_token_slot():
    """Feeding a vault its own share token as the deposit asset produces a mint
    whose only inflow is the minted asset — which the backing rule discards, so
    the verdict would describe the prober's argument, not the function."""
    attempts, transcript = _attempts(
        "deposit(address,uint256,address)", ["depositAsset", "amount", "receiver"], _seeding(VAULT)
    )
    assert _arg(attempts[0].calldata, 0) == PRINCIPAL
    assert {"label": "seed_path", "outcome": "skipped_no_token_for_param"} in transcript["seed_attempts"]


# ---------------------------------------------------------------------------
# 4. the backing witness is gated on the argument that produced it
# ---------------------------------------------------------------------------


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
    """read -> mint reverts -> read: what an unseeded deposit-shaped probe does."""
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


def test_backing_is_withheld_when_a_token_slot_never_got_a_token():
    """The call went through with a non-token in the asset slot, so the pull was
    a no-op. ``inflow_observed: false`` would report that as dilution."""
    eff = _supply(
        "deposit(address,uint256,address)",
        ["depositAsset", "amount", "receiver"],
        [_supply_block(0, 100, [transfer_log(VAULT, "0x" + "00" * 20, PRINCIPAL, 100)])],
        seeding=None,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["supply_delta_sign"] == "mint"
    # ABSENT, not false: absence reads as unmeasured everywhere downstream.
    assert "backing" not in eff.details
    assert "backing_inflow_transfers" not in eff.concrete


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


def test_a_function_with_no_token_slot_keeps_its_backing_witness():
    """The gate must not silence the admin-mint case the witness exists for.

    ``mint(address,uint256)`` names no token, so the prober's identity sits in an
    address slot; the differential proves the mint did not depend on it (a stub
    that reverts on every call changes nothing) and the negative is published."""
    eff = _supply(
        "mint(address,uint256)",
        ["to", "amount"],
        [
            _supply_block(0, 100, [transfer_log(VAULT, "0x" + "00" * 20, PRINCIPAL, 100)]),
            _supply_block(0, 100, [transfer_log(VAULT, "0x" + "00" * 20, PRINCIPAL, 100)]),
        ],
        seeding=None,
    )
    assert eff.details["backing"]["inflow_observed"] is False
    assert eff.details["backing"]["minted"] is True


def test_seeding_a_token_cannot_by_itself_produce_an_inflow():
    """The seeded call pulls nothing: storage writes emit no logs, so the
    witnessed negative survives seeding."""
    reverted = _reverted_block()
    seeded = _supply_block(0, 100, [transfer_log(VAULT, "0x" + "00" * 20, PRINCIPAL, 100)])
    eff = _supply(
        "deposit(address,uint256,address)",
        ["depositAsset", "amount", "receiver"],
        # The third block is the inertness differential: the recipient slot still
        # holds the prober's identity, so the negative has to be earned.
        [reverted, seeded, seeded],
        seeding=_seeding(TOKEN_A),
    )
    assert eff.details["backing"]["inflow_observed"] is False
    assert eff.details["backing"]["input_seeded"] is True


def test_an_unresolved_token_slot_leaves_the_probe_exactly_as_it_was():
    """No seeder, no holdings: the calldata is byte-identical to the unseeded
    probe's, which is the fail-closed direction."""
    sig = "deposit(address,uint256,address)"
    spec = _spec(_facts(sig, parameter_names=["depositAsset", "amount", "receiver"]), sig)
    assert _arg(spec.mint_calldata, 0) == PRINCIPAL


@requires_postgres
def test_priced_holdings_only_and_richest_first(db_session):
    """An unpriced holding is usually an airdropped spam token; a mint witnessed
    against one would look byte-identical to a real deposit."""
    from db.models import ContractBalance

    p = _protocol(db_session, "reach-holdings")
    c = _contract(db_session, p.id, ADDR(0x2301))
    _fn(db_session, c.id, name="deposit", selector="0xbbbb0301", effect_targets=["S"])
    for token, usd in ((ADDR(0xAA01), 10.0), (ADDR(0xAA02), 900.0), (ADDR(0xAA03), None)):
        db_session.add(
            ContractBalance(contract_id=c.id, token_address=token, raw_balance="1", decimals=18, usd_value=usd)
        )
    db_session.flush()

    cand = next(c2 for c2 in select_candidates(db_session, p.id) if c2.selector == "0xbbbb0301")
    assert cand.input_token_addresses == (ADDR(0xAA02).lower(), ADDR(0xAA01).lower())
