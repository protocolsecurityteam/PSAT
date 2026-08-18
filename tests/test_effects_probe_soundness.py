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
        sentinel_override={"code": "0x00"},
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


def test_authority_change_records_the_decoded_mutation_revert():
    """§9.3, seam ``recipes.authority_change``. The class is unrecoverable by
    construction (no seeder — it reverts on the gate, not a missing asset), but
    the decoded revert must be kept or the next census cannot name why the 31
    mutation_call_reverted rows reverted. Recorded the way ``value_out`` records a
    seeded attempt's revert (``_revert_detail``)."""
    err = _sel("Unauthorized()")  # a bare custom-error selector, no decodable payload
    sim = _Recorder(
        SimResult(
            calls=(
                SimCallResult(False, "0x", "0x", ()),  # before r1
                SimCallResult(False, "0x", "0x", ()),  # before r2
                SimCallResult(False, "0x", err, ()),  # mutate reverted with the selector
                SimCallResult(False, "0x", "0x", ()),  # after r1
                SimCallResult(False, "0x", "0x", ()),  # after r2
            )
        )
    )
    eff = recipes.authority_change(
        simulate=sim,
        store=RecordingStore(),
        ctx=CTX,
        contract_address=VAULT,
        principal=PRINCIPAL,
        mutate_calldata="0x11111111",
        probe_calldata="0x22222222",
        randoms=["0x" + "33" * 20, "0x" + "44" * 20],
    )
    assert eff.reason == "mutation_call_reverted"
    # The decoded reason names the selector (here an undecodable custom error),
    # and the same string reaches both the witness and the transcript.
    assert eff.transcript is not None
    assert err in eff.details["revert_reason"]
    assert eff.details["revert_reason"] == eff.transcript["mutate_revert"]


# ---------------------------------------------------------------------------
# A burn must never be published as a mint
# ---------------------------------------------------------------------------


def _burn_only(burned_from: str = PRINCIPAL, amount: int = 100):
    return [transfer_log(VAULT, burned_from, ZERO, amount)]


def test_a_burn_that_wrapped_past_zero_reads_as_a_burn():
    """``unchecked { totalSupply -= amount }`` is the universal ``_burn`` idiom.
    When the seeded holder balance exceeded the supply, the subtraction wrapped
    and ``totalSupply`` came back as a number just under ``2^256`` — which a plain
    Python subtraction reads as an enormous INCREASE, i.e. a mint. Reading the
    difference as the uint256 word it is restores the sign the EVM computed."""
    before = 26_078_429_092_482
    after = (before - 10**18) % (1 << 256)
    assert after > 1 << 250  # the wrap really happened

    eff = _supply(
        _Recorder(_supply_block(before, after, _burn_only())),
        _calldata("exit(uint256)", 1),
        token_param_indexes=(),
    )

    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["supply_delta_sign"] == "burn"
    # The §5a dilution witness belongs to mints alone and must not appear here.
    assert "backing" not in eff.details


def test_a_sign_contradicted_by_the_transfer_logs_publishes_nothing():
    """Two independent witnesses of one event: the ``totalSupply`` arithmetic and
    the zero-address ``Transfer`` logs. When they disagree the stage holds neither
    — least of all the proven "witnessed dilution" output."""
    eff = _supply(
        # Arithmetic says supply ROSE; the only zero-address transfer is a BURN.
        _Recorder(_supply_block(0, 100, _burn_only())),
        _calldata("exit(uint256)", 1),
        token_param_indexes=(),
    )

    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "supply_sign_contradicted_by_transfers"
    assert eff.details["observation"] == "executed"
    # And it must NOT transfer on the behavioral hash. The contradiction is a
    # property of this probe's state — which token emitted what, under whatever
    # was seeded — not a structural fact a bytecode twin inherits. Caching it
    # would republish "we could not read this call" as a fact about every twin.
    assert not _is_cacheable(eff)


def test_a_token_that_emits_no_zero_address_transfer_is_not_treated_as_a_contradiction():
    """Absence of evidence is not evidence of absence: a token that mints without
    emitting anything is unhelpful, not lying, and its verdict still stands."""
    eff = _supply(
        _Recorder(_supply_block(0, 100, ())),
        _calldata("mint(address,uint256)", PRINCIPAL, 1),
        token_param_indexes=(),
    )

    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["supply_delta_sign"] == "mint"


# ---------------------------------------------------------------------------
# The static destination-shape proof — a universal, adjudicated against the fork
# ---------------------------------------------------------------------------


def _facts_with_out_flows(*target_kinds, several_members=None):
    """FunctionFacts whose out-flows carry the given folded destination kinds."""
    from services.effects.calldata import FunctionFacts

    flows = []
    for kind in target_kinds:
        flow: dict[str, Any] = {
            "direction": "out",
            "kind": "native_transfer_send",
            "origin": "body",
            "target_kind": {"kind": kind, "tier": "dispositive_ast"},
        }
        if kind == "several":
            flow["target_kinds"] = [{"kind": m, "tier": "dispositive_ast"} for m in (several_members or [])]
        flows.append(flow)
    return FunctionFacts(
        full_name="pay(uint256)",
        selector="0xabcdef01",
        canonical_signature="pay(uint256)",
        effect_info={"value_flows": flows, "payable": False},
        tree=None,
        legacy_value_flows=(),
    )


def test_static_destination_shape_is_earned_across_every_out_flow():
    from services.effects.calldata import _OUT_DIRECTIONS, static_destination_shape

    out = frozenset(_OUT_DIRECTIONS)
    shape = static_destination_shape

    # Every site provably fixed.
    assert shape(_facts_with_out_flows("immutable"), out) == "immutable_fixed"
    assert shape(_facts_with_out_flows("constant", "storage_no_setter"), out) == "immutable_fixed"
    # An admin-settable site downgrades the whole function, never the reverse.
    assert shape(_facts_with_out_flows("immutable", "storage_setter"), out) == "storage_determined"
    # ONE caller-chosen site and there is no claim to make: the function is
    # caller-redirectable however fixed its other destinations are.
    assert shape(_facts_with_out_flows("immutable", "param"), out) is None
    assert shape(_facts_with_out_flows("msg_sender"), out) is None
    assert shape(_facts_with_out_flows("indeterminate"), out) is None
    assert shape(_facts_with_out_flows("self"), out) is None
    # A several is read through its members, worst member first.
    assert shape(_facts_with_out_flows("several", several_members=["immutable", "constant"]), out) == "immutable_fixed"
    assert shape(_facts_with_out_flows("several", several_members=["immutable", "param"]), out) is None
    # An unreadable several proves nothing.
    assert shape(_facts_with_out_flows("several", several_members=[]), out) is None
    # No out-flows at all is no claim, not a vacuous "fixed".
    assert shape(_facts_with_out_flows(), out) is None


def test_a_proven_fixed_shape_reaches_the_verdict():
    """The branch that publishes it was unreachable for the stage's whole life:
    it demanded a static ADDRESS, which the static plane classifies destinations
    by KIND and never resolves. The shape is a universal and stands on its own;
    the address comes from the observation when there is one."""
    moved = [transfer_log(VAULT, VAULT, TOKEN_A, 5)]
    eff = recipes.value_out(
        simulate=_Recorder(SimResult(calls=(SimCallResult(True, "0x", None, tuple(moved)),))),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=VAULT,
        principal=PRINCIPAL,
        calldata="0x11111111",
        simulate_supported=True,
        static_shape="immutable_fixed",
    )

    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["destination_shape"] == "immutable_fixed"
    assert eff.details["shape_proved_by"] == "static"
    # The address is the OBSERVED one — static named the shape, not the value.
    assert eff.concrete["destination"] == TOKEN_A.lower()


def test_a_landed_sentinel_still_outranks_the_static_shape():
    """An existential proof that the caller CAN redirect the funds beats a
    universal argued from the source. If they ever conflict, static is wrong."""
    eff = recipes.value_out(
        simulate=_Recorder(
            SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(VAULT, VAULT, TOKEN_A, 5),)),)),
            SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(VAULT, VAULT, SENTINEL, 5),)),)),
        ),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=VAULT,
        principal=PRINCIPAL,
        calldata="0x11111111",
        simulate_supported=True,
        sentinel_address=SENTINEL,
        sentinel_calldata="0x22222222",
        static_shape="immutable_fixed",
    )

    assert eff.details["destination_shape"] == "caller_arbitrary"
    assert eff.details["shape_proved_by"] == "simulation"


# ---------------------------------------------------------------------------
# The subject of a caller_arbitrary proof
# ---------------------------------------------------------------------------


def test_a_landed_sentinel_publishes_the_parameter_it_landed_in():
    """A ``caller_arbitrary`` verdict is a proof about ONE parameter, and the
    prober is the only thing that can say which. Without the subject the scorer's
    exec join cannot tell a sentinel that rode the call target from one that rode
    an executor payload, so it refuses every such verdict."""
    eff = recipes.value_out(
        simulate=_Recorder(
            SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(VAULT, VAULT, TOKEN_A, 5),)),)),
            SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(VAULT, VAULT, SENTINEL, 5),)),)),
        ),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=VAULT,
        principal=PRINCIPAL,
        calldata="0x11111111",
        simulate_supported=True,
        sentinel_address=SENTINEL,
        sentinel_calldata="0x22222222",
        sentinel_param="payload",
    )

    assert eff.details["destination_shape"] == "caller_arbitrary"
    assert eff.details["sentinel_param"] == "payload"


def test_a_sentinel_that_moved_nothing_still_names_its_subject():
    """The subject is a fact about the calldata that was ISSUED, not about the
    outcome. Publishing it only on a landing would leave a reader unable to tell
    "we probed that slot and it held" from "we never probed that slot"."""
    eff = recipes.value_out(
        simulate=_Recorder(
            SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(VAULT, VAULT, TOKEN_A, 5),)),)),
            SimResult(calls=(SimCallResult(True, "0x", None, ()),)),
        ),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=VAULT,
        principal=PRINCIPAL,
        calldata="0x11111111",
        simulate_supported=True,
        sentinel_address=SENTINEL,
        sentinel_calldata="0x22222222",
        sentinel_param="to",
    )

    assert eff.details["destination_shape"] == "unknown"
    assert eff.details["sentinel_param"] == "to"


def test_no_sentinel_probe_names_no_subject():
    """Absence is the third state: no sentinel was issued, so there is no
    parameter this verdict is a proof about — and a consumer must read that as
    "unnamed", never as "the destination"."""
    eff = recipes.value_out(
        simulate=_Recorder(
            SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(VAULT, VAULT, TOKEN_A, 5),)),))
        ),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=VAULT,
        principal=PRINCIPAL,
        calldata="0x11111111",
        simulate_supported=True,
        sentinel_param="to",
    )

    assert "sentinel_param" not in eff.details
