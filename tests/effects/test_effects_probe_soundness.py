"""What a probe may PUBLISH about a call it could not fully control.

The prober supplies part of the input, the call then behaves per the PROBER's choice, and the
payload is published as if it described the function:
* backing: a call to a CODELESS address is a silent no-op success inside ``SafeTransferLib``,
  so ``inflow_observed: false`` there is fabricated dilution. Names can't rule it out, so it is settled by observation.
* value-out / code-upgrade: a REVERTED probe looks like one that ran and did nothing;
  collapsing them put a precondition revert into the code-plane cache, transferring to every bytecode twin.
* every row: ``effect_verdicts.witness`` is written for ``unknown`` too, so it needs a self-contained discriminator.
Fixtures are generic ABI shapes; nothing here recognizes a protocol.
"""

from __future__ import annotations

from typing import Any

from eth_utils.crypto import keccak

from services.effects import recipes
from services.effects.config import VERDICT_PROVEN, VERDICT_UNKNOWN
from services.effects.harness import SimContext, unknown
from services.effects.simulate import SimCallResult, SimResult
from tests.support.effects_stubs import RecordingStore, transfer_log
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
    """Keeps every ``(calls, overrides)`` so a test can assert on the differential's overrides."""

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
# FIX 1 — the NEGATIVE must be earned, whatever the asset parameter is called
# ---------------------------------------------------------------------------


def test_a_mint_whose_asset_slot_held_the_prober_identity_withholds_the_negative():
    """``want`` is in no token vocabulary, so the old gate passed vacuously; the revert-stub differential proves the
    pull was on the executed path.
    """
    sig = "enter(address,uint256)"
    calldata = _calldata(sig, PRINCIPAL, 1)
    sim = _Recorder(
        _supply_block(0, 100, _mint_only()),
        _supply_block(0, 0, (), mint_ok=False),
    )
    eff = _supply(sim, calldata, token_param_indexes=())

    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["supply_delta_sign"] == "mint"
    # Absent, not false: the claims bridge reads absence as unmeasured.
    assert "backing" not in eff.details
    assert "backing_inflow_transfers" not in eff.concrete
    _calls, overrides = sim.seen[-1]
    assert overrides[PRINCIPAL.lower()]["code"] == recipes._REVERT_STUB_CODE


def test_a_differential_that_cannot_be_run_withholds():
    """A non-observation may not stand in for the proof."""
    sim = _Recorder(_supply_block(0, 100, _mint_only()))  # no differential block
    eff = _supply(sim, _calldata("enter(address,uint256)", PRINCIPAL, 1), token_param_indexes=())
    assert eff.verdict == VERDICT_PROVEN
    assert "backing" not in eff.details


def test_prober_supplied_address_args_reads_the_bytes_not_the_types():
    principal = PRINCIPAL
    assert recipes._prober_supplied_address_args(_calldata("f(address)", principal), principal) == [principal.lower()]
    assert recipes._prober_supplied_address_args(_calldata("f(address)", TOKEN_A), principal) == []
    assert recipes._prober_supplied_address_args(_calldata("f(uint256)", 1), principal) == []
    assert recipes._prober_supplied_address_args(_calldata("f(address)", ZERO), None) == []


def test_a_named_token_slot_that_never_got_a_token_still_withholds_first():
    sim = _Recorder(_supply_block(0, 100, _mint_only()))
    eff = _supply(sim, _calldata("deposit(address,uint256)", PRINCIPAL, 1), token_param_indexes=(0,))
    assert "backing" not in eff.details
    assert len(sim.seen) == 1


def test_a_reverted_upgrade_probe_is_not_impl_slot_unchanged():
    """The same conflation in code-upgrade probes: the impl slot is unchanged after ANY revert,
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


def test_every_row_carries_an_observation_discriminator():
    """A payload like ``{"value_moved": false}`` must not read as proven absence without joining on ``verdict``."""
    rows: list[Any] = []

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
    rows.append(_supply(_Recorder(_supply_block(0, 100, _mint_only())), _calldata("wrap(uint256)", 1)))
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
        if row.verdict == VERDICT_UNKNOWN and row.details.get("value_moved") is False:
            assert row.details["observation"] in ("reverted", "executed")


def test_authority_change_records_the_decoded_mutation_revert():
    """Probe seam ``recipes.authority_change``. The class is unrecoverable by
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
    assert eff.transcript is not None
    assert err in eff.details["revert_reason"]
    assert eff.details["revert_reason"] == eff.transcript["mutate_revert"]


def _burn_only(burned_from: str = PRINCIPAL, amount: int = 100):
    return [transfer_log(VAULT, burned_from, ZERO, amount)]


def test_a_sign_contradicted_by_the_transfer_logs_publishes_nothing():
    """When the supply arithmetic and the zero-address Transfer logs disagree, neither is held."""
    eff = _supply(
        _Recorder(_supply_block(0, 100, _burn_only())),
        _calldata("exit(uint256)", 1),
        token_param_indexes=(),
    )

    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "supply_sign_contradicted_by_transfers"
    assert eff.details["observation"] == "executed"
    # The contradiction is a property of this probe's state, not every twin.
    assert not _is_cacheable(eff)


def test_a_token_that_emits_no_zero_address_transfer_is_not_treated_as_a_contradiction():
    """A token that mints without emitting anything is unhelpful, not lying."""
    eff = _supply(
        _Recorder(_supply_block(0, 100, ())),
        _calldata("mint(address,uint256)", PRINCIPAL, 1),
        token_param_indexes=(),
    )

    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["supply_delta_sign"] == "mint"


def _facts_with_out_flows(*target_kinds, several_members=None):
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

    assert shape(_facts_with_out_flows("immutable"), out) == "immutable_fixed"
    assert shape(_facts_with_out_flows("constant", "storage_no_setter"), out) == "immutable_fixed"
    assert shape(_facts_with_out_flows("immutable", "storage_setter"), out) == "storage_determined"
    # One caller-chosen site makes the function caller-redirectable.
    assert shape(_facts_with_out_flows("immutable", "param"), out) is None
    assert shape(_facts_with_out_flows("msg_sender"), out) is None
    assert shape(_facts_with_out_flows("indeterminate"), out) is None
    assert shape(_facts_with_out_flows("self"), out) is None
    assert shape(_facts_with_out_flows("several", several_members=["immutable", "constant"]), out) == "immutable_fixed"
    assert shape(_facts_with_out_flows("several", several_members=["immutable", "param"]), out) is None
    assert shape(_facts_with_out_flows("several", several_members=[]), out) is None
    assert shape(_facts_with_out_flows(), out) is None
