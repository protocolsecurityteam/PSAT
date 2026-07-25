"""What a probe may PUBLISH about a call it could not fully control.

Three failures share one shape: the prober supplies part of the input, the call
then behaves in a way that is about the PROBER's choice rather than about the
function, and the resulting payload is published as though it described the
function.

* §5a backing — a call to a CODELESS address is a silent no-op success inside
  ``SafeTransferLib``, so a deposit-backed conversion handed the acting identity
  for its asset still mints while pulling nothing. ``inflow_observed: false`` on
  that execution is fabricated dilution. Parameter names cannot rule it out (an
  asset called ``want`` matches no vocabulary), so it is settled by observation.
* §4.2 value-out and §4.3 code-upgrade — a REVERTED probe has no logs and moved
  no slot, exactly like a probe that ran and did nothing. Collapsing the two put
  a precondition revert into the code-plane cache, where it transferred to every
  bytecode twin.
* every row — ``effect_verdicts.witness`` is written for ``unknown`` verdicts
  too, so the payload needs a self-contained discriminator.

Fixtures are generic ABI shapes; nothing here recognizes a protocol.
"""

from __future__ import annotations

from typing import Any

from eth_utils.crypto import keccak

from services.effects import recipes
from services.effects.config import VERDICT_PROVEN, VERDICT_UNKNOWN
from services.effects.harness import SimContext, unknown
from services.effects.simulate import SimCallResult, SimResult
from tests.test_effects_harness import RecordingStore, transfer_log
from workers.effects_worker import _CACHEABLE_UNKNOWN_REASONS, _is_cacheable

VAULT = "0x" + "c0" * 20
PRINCIPAL = "0x" + "22" * 20
TOKEN_A = "0x" + "a1" * 20
ZERO = "0x" + "00" * 20
SENTINEL = "0x" + "ee" * 20
CTX = SimContext(chain_id=1, block=1000, hardfork="prague")


def _sel(sig: str) -> str:
    return "0x" + keccak(text=sig).hex()[:8]


def _word(value: str | int) -> str:
    if isinstance(value, int):
        return value.to_bytes(32, "big").hex()
    return (value[2:] if value.startswith("0x") else value).rjust(64, "0").lower()


def _calldata(sig: str, *args: str | int) -> str:
    return _sel(sig) + "".join(_word(a) for a in args)


class _Recorder:
    """Replays scripted blocks and keeps every ``(calls, overrides)`` it was
    handed, so a test can assert on the OVERRIDES a differential issued rather
    than only on its verdict."""

    def __init__(self, *blocks: SimResult) -> None:
        self.blocks = list(blocks)
        self.seen: list[tuple[list[Any], Any]] = []

    def __call__(self, calls, block_tag=None, overrides=None) -> Any:
        self.seen.append((list(calls), overrides))
        return self.blocks.pop(0) if self.blocks else None


def _supply_block(before: int, after: int, logs=(), *, mint_ok: bool = True) -> SimResult:
    return SimResult(
        calls=(
            SimCallResult(True, hex(before), None, ()),
            SimCallResult(mint_ok, "0x", None if mint_ok else "0x", tuple(logs)),
            SimCallResult(True, hex(after), None, ()),
        )
    )


def _mint_only(minted_to: str = PRINCIPAL):
    return [transfer_log(VAULT, ZERO, minted_to, 100)]


def _supply(simulate, calldata: str, **kw):
    return recipes.supply(
        simulate=simulate,
        store=RecordingStore(),
        ctx=CTX,
        token_address=VAULT,
        principal=PRINCIPAL,
        mint_calldata=calldata,
        simulate_supported=True,
        **kw,
    )


# ---------------------------------------------------------------------------
# FIX 1 — the §5a NEGATIVE must be earned, whatever the asset parameter is called
# ---------------------------------------------------------------------------


def test_a_mint_whose_asset_slot_held_the_prober_identity_withholds_the_negative():
    """``enter(address want, uint256)``: ``want`` is in no token vocabulary, so
    ``token_param_indexes`` is empty and the old gate passed vacuously. The
    prober's own identity sits in the asset slot; with reverting code placed
    there the mint no longer executes, which proves the pull WAS on the executed
    path and that the observed "no inflow" was the prober's doing."""
    sig = "enter(address,uint256)"
    calldata = _calldata(sig, PRINCIPAL, 1)
    sim = _Recorder(
        # The unseeded call succeeds — the codeless no-op — and mints.
        _supply_block(0, 100, _mint_only()),
        # Differential: with a revert stub in the asset slot the pull is fatal.
        _supply_block(0, 0, (), mint_ok=False),
    )
    eff = _supply(sim, calldata, token_param_indexes=())

    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["supply_delta_sign"] == "mint"
    # ABSENT, not false: the claims bridge reads absence as unmeasured.
    assert "backing" not in eff.details
    assert "backing_inflow_transfers" not in eff.concrete
    # The differential was issued with plain reverting code at the address the
    # prober itself supplied — nothing name-derived took part in the decision.
    _calls, overrides = sim.seen[-1]
    assert overrides[PRINCIPAL.lower()]["code"] == recipes._REVERT_STUB_CODE


def test_a_mint_unaffected_by_the_stub_still_publishes_the_negative():
    """The counterpart, and the reason the fix is a differential rather than a
    codesize check: an admin mint's recipient is routinely a codeless EOA, and
    withholding on that alone would delete the unbacked-issuance witness."""
    sig = "mint(address,uint256)"
    calldata = _calldata(sig, PRINCIPAL, 1)
    sim = _Recorder(_supply_block(0, 100, _mint_only()), _supply_block(0, 100, _mint_only()))
    eff = _supply(sim, calldata, token_param_indexes=())

    assert eff.details["backing"]["inflow_observed"] is False
    assert eff.details["backing"]["minted"] is True
    assert eff.concrete["backing_inflow_transfers"] == 0


def test_a_differential_that_changes_the_delta_withholds():
    """The stub must be INERT, not merely survivable: a different supply delta
    means the prober's address participated in what was measured."""
    sig = "enter(address,uint256)"
    sim = _Recorder(_supply_block(0, 100, _mint_only()), _supply_block(0, 40, _mint_only()))
    eff = _supply(sim, _calldata(sig, PRINCIPAL, 1), token_param_indexes=())
    assert "backing" not in eff.details


def test_a_differential_that_cannot_be_run_withholds():
    """A malformed or absent second block is a non-observation, and a
    non-observation may not stand in for the proof."""
    sim = _Recorder(_supply_block(0, 100, _mint_only()))  # no differential block
    eff = _supply(sim, _calldata("enter(address,uint256)", PRINCIPAL, 1), token_param_indexes=())
    assert eff.verdict == VERDICT_PROVEN
    assert "backing" not in eff.details


def test_an_observed_inflow_needs_no_differential():
    """Asymmetric burden: ``inflow_observed: true`` is a Transfer log that exists.
    Only the negative is published as a claim about the function."""
    logs = [transfer_log(TOKEN_A, PRINCIPAL, VAULT, 5), *_mint_only()]
    sim = _Recorder(_supply_block(0, 100, logs))
    eff = _supply(sim, _calldata("enter(address,uint256)", PRINCIPAL, 1), token_param_indexes=())
    assert eff.details["backing"]["inflow_observed"] is True
    assert len(sim.seen) == 1


def test_a_mint_with_no_address_argument_at_all_needs_no_differential():
    """``wrap(uint256)`` gives the prober no address to get wrong."""
    sim = _Recorder(_supply_block(0, 100, _mint_only()))
    eff = _supply(sim, _calldata("wrap(uint256)", 1), token_param_indexes=())
    assert eff.details["backing"]["inflow_observed"] is False
    assert len(sim.seen) == 1


def test_prober_supplied_address_args_reads_the_bytes_not_the_types():
    principal = PRINCIPAL
    assert recipes._prober_supplied_address_args(_calldata("f(address)", principal), principal) == [principal.lower()]
    # A token written into the slot by the seeded retry is a proved contract and
    # is no longer the principal, so it drops out by construction.
    assert recipes._prober_supplied_address_args(_calldata("f(address)", TOKEN_A), principal) == []
    assert recipes._prober_supplied_address_args(_calldata("f(uint256)", 1), principal) == []
    # No identity to look for ⇒ nothing can be identified (the caller withholds).
    assert recipes._prober_supplied_address_args(_calldata("f(address)", ZERO), None) == []


def test_a_named_token_slot_that_never_got_a_token_still_withholds_first():
    """The cheap gate stays: a slot static PROVED carries a token and did not get
    one is disqualifying without spending a differential."""
    sim = _Recorder(_supply_block(0, 100, _mint_only()))
    eff = _supply(sim, _calldata("deposit(address,uint256)", PRINCIPAL, 1), token_param_indexes=(0,))
    assert "backing" not in eff.details
    assert len(sim.seen) == 1


# ---------------------------------------------------------------------------
# FIX 2 — a revert is not an observation of absence, and never code-plane
# ---------------------------------------------------------------------------


def test_a_reverted_value_probe_is_not_no_value_observed():
    sim = _Recorder(SimResult(calls=(SimCallResult(False, "0x", "0x", ()),)))
    eff = recipes.value_out(
        simulate=sim,
        store=RecordingStore(),
        ctx=CTX,
        contract_address=VAULT,
        principal=PRINCIPAL,
        calldata=_calldata("withdraw(uint256)", 1),
        simulate_supported=True,
    )
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "value_probe_reverted"
    assert eff.details["observation"] == "reverted"
    # ...and it must not travel to a bytecode twin on the behavioral hash.
    assert "value_probe_reverted" not in _CACHEABLE_UNKNOWN_REASONS
    assert _is_cacheable(unknown(recipes.EFFECT_CLASS_VALUE_OUT, reason="value_probe_reverted")) is False
    assert _is_cacheable(unknown(recipes.EFFECT_CLASS_VALUE_OUT, reason="no_value_observed")) is True


def test_an_executed_value_probe_that_moved_nothing_keeps_its_cacheable_reason():
    sim = _Recorder(SimResult(calls=(SimCallResult(True, "0x", None, ()),)))
    eff = recipes.value_out(
        simulate=sim,
        store=RecordingStore(),
        ctx=CTX,
        contract_address=VAULT,
        principal=PRINCIPAL,
        calldata=_calldata("withdraw(uint256)", 1),
        simulate_supported=True,
    )
    assert eff.reason == "no_value_observed"
    assert eff.details["observation"] == "executed"


def test_a_reverted_upgrade_probe_is_not_impl_slot_unchanged():
    """The same conflation in §4.3: the impl slot is unchanged after ANY revert,
    and ``impl_slot_unchanged`` IS code-plane cacheable."""
    slot = recipes.EIP1967_IMPL_SLOT
    old_impl = "0x" + _word("0x" + "01" * 20)
    sim = _Recorder(SimResult(calls=(SimCallResult(False, "0x", "0x", ()),), storage={VAULT.lower(): {slot: old_impl}}))
    eff = recipes.code_upgrade(
        simulate=sim,
        store=RecordingStore(),
        ctx=CTX,
        proxy_address=VAULT,
        principal=PRINCIPAL,
        upgrade_calldata=_calldata("upgradeTo(address)", SENTINEL),
        sentinel_address=SENTINEL,
        sentinel_override=recipes.transparent_sentinel_override(SENTINEL),
        impl_before=old_impl,
    )
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "upgrade_probe_reverted"
    assert eff.details["observation"] == "reverted"
    assert "upgrade_probe_reverted" not in _CACHEABLE_UNKNOWN_REASONS
    assert _is_cacheable(unknown(recipes.EFFECT_CLASS_CODE_UPGRADE, reason="upgrade_probe_reverted")) is False


def test_the_supply_recipe_already_split_revert_from_no_delta():
    """Guard on the shape the other two were made to match."""
    sim = _Recorder(_supply_block(0, 0, (), mint_ok=False))
    eff = _supply(sim, _calldata("mint(address,uint256)", PRINCIPAL, 1))
    assert eff.reason == "mint_call_reverted"
    assert eff.details["observation"] == "reverted"
    assert "mint_call_reverted" not in _CACHEABLE_UNKNOWN_REASONS


# ---------------------------------------------------------------------------
# FIX 3 — the witness carries its own discriminator
# ---------------------------------------------------------------------------


def test_every_row_carries_an_observation_discriminator():
    """``workers.effects_worker`` writes ``witness=details`` on unknown rows too,
    so a payload like ``{"value_moved": false}`` must not be readable as a proven
    absence without joining on ``verdict``."""
    rows: list[Any] = []

    # unsupported capability — nothing ran
    rows.append(
        recipes.value_out(
            simulate=_Recorder(),
            store=RecordingStore(),
            ctx=CTX,
            contract_address=VAULT,
            principal=PRINCIPAL,
            calldata="0x11111111",
            simulate_supported=False,
        )
    )
    # reverted
    rows.append(
        recipes.value_out(
            simulate=_Recorder(SimResult(calls=(SimCallResult(False, "0x", "0x", ()),))),
            store=RecordingStore(),
            ctx=CTX,
            contract_address=VAULT,
            principal=PRINCIPAL,
            calldata="0x11111111",
            simulate_supported=True,
        )
    )
    # executed, nothing moved
    rows.append(
        recipes.value_out(
            simulate=_Recorder(SimResult(calls=(SimCallResult(True, "0x", None, ()),))),
            store=RecordingStore(),
            ctx=CTX,
            contract_address=VAULT,
            principal=PRINCIPAL,
            calldata="0x11111111",
            simulate_supported=True,
        )
    )
    # executed, minted
    rows.append(_supply(_Recorder(_supply_block(0, 100, _mint_only())), _calldata("wrap(uint256)", 1)))
    # authority change whose mutation reverted
    rows.append(
        recipes.authority_change(
            simulate=_Recorder(
                SimResult(
                    calls=(
                        SimCallResult(False, "0x", "0x", ()),
                        SimCallResult(False, "0x", "0x", ()),
                        SimCallResult(False, "0x", "0x", ()),
                        SimCallResult(False, "0x", "0x", ()),
                        SimCallResult(False, "0x", "0x", ()),
                    )
                )
            ),
            store=RecordingStore(),
            ctx=CTX,
            contract_address=VAULT,
            principal=PRINCIPAL,
            mutate_calldata="0x11111111",
            probe_calldata="0x22222222",
            randoms=["0x" + "33" * 20, "0x" + "44" * 20],
        )
    )

    seen = {row.details["observation"] for row in rows}
    assert seen == {"not_run", "reverted", "executed"}
    for row in rows:
        # A ``false`` in the payload only describes F on an executed row.
        if row.verdict == VERDICT_UNKNOWN and row.details.get("value_moved") is False:
            assert row.details["observation"] in ("reverted", "executed")
