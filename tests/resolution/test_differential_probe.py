"""Unit tests for the differential probe (DIFFERENTIAL_PROBE_PLAN §3, gated by
Phase 1). Every attribution-table row is exercised against recorded outcomes via
a stubbed ``call_batch`` — no live RPC. Soundness invariants asserted:

  * a public verdict requires ≥2 random SUCCESSES + block-independence;
  * indeterminate / inconclusive / synthesis-miss NEVER upgrade (fail closed);
  * the §3.5 block-independence cross-check withholds on state-dependent admission.
"""

from __future__ import annotations

from eth_abi.abi import encode as abi_encode
from eth_utils.crypto import keccak

from services.clients.rpc import EthCallResult, encode_address_word
from services.resolution import differential_probe as dp

# --- recorded outcome constructors -----------------------------------------

TRUE = "0x" + "0" * 63 + "1"


def ok(ret: str = "0x") -> EthCallResult:
    return EthCallResult(True, ret, None, None)


def revert(data: str) -> EthCallResult:
    return EthCallResult(False, "0x", data, "execution reverted")


def node_error(msg: str = "out of gas") -> EthCallResult:
    return EthCallResult(False, "0x", None, msg)


def err_string(msg: str) -> str:
    return "0x08c379a0" + abi_encode(["string"], [msg]).hex()


def custom_err(sig: str) -> str:
    return "0x" + keccak(text=sig).hex()[:8]


OWNABLE = err_string("Ownable: caller is not the owner")
ZERO_ADDR = err_string("ERC20: transfer to the zero address")
UNAUTHORIZED = custom_err("Unauthorized()")


# --- a stubbed wire keyed on (block_tag, call) ------------------------------


class StubWire:
    """Records every batch; returns outcomes from a ``(block_tag, from_addr) ->
    EthCallResult`` responder so tests can vary behavior by caller and by block."""

    def __init__(self, responder):
        self.responder = responder
        self.batches: list[tuple[str, list[dict]]] = []

    def __call__(self, calls, block_tag):
        self.batches.append((block_tag, list(calls)))
        return [self.responder(block_tag, c.get("from")) for c in calls]


# ---------------------------------------------------------------------------
# §3.3 / §3.4 attribution table
# ---------------------------------------------------------------------------


def test_attr_two_sided_random_revert_principal_success_is_discriminating():
    # row 1: revert(A) / success → caller-discriminating (confirmed gated)
    assert dp.attribute([revert(OWNABLE), revert(OWNABLE)], ok()) == "caller_discriminating"


def test_attr_two_sided_different_gates_is_discriminating():
    # row 2: random revert(A), principal revert(B), A≠B → caller-discriminating
    assert dp.attribute([revert(OWNABLE), revert(OWNABLE)], revert(ZERO_ADDR)) == "caller_discriminating"


def test_attr_two_sided_all_success_is_candidate_public():
    # row 3: success / success → not caller-discriminating (candidate public)
    assert dp.attribute([ok(), ok()], ok()) == "not_caller_discriminating"


def test_attr_two_sided_same_gate_everywhere_is_inconclusive():
    # row 4: revert(A) / revert(A) same error → inconclusive (shared earlier gate)
    assert dp.attribute([revert(OWNABLE), revert(OWNABLE)], revert(OWNABLE)) == "inconclusive"


def test_attr_node_error_is_indeterminate():
    # row 5: a node error (no revert data) anywhere among randoms → indeterminate
    assert dp.attribute([revert(OWNABLE), node_error()], ok()) == "indeterminate"
    assert dp.attribute([node_error()], None) == "indeterminate"


def test_attr_one_sided_all_success_is_candidate_public():
    assert dp.attribute([ok(), ok()], None) == "not_caller_discriminating"


def test_attr_one_sided_all_revert_same_is_consistent_rejection():
    assert dp.attribute([revert(OWNABLE), revert(OWNABLE)], None) == "caller_rejected_consistent"
    assert dp.attribute([revert(UNAUTHORIZED), revert(UNAUTHORIZED)], None) == "caller_rejected_consistent"


def test_attr_randoms_disagree_is_indeterminate():
    # a random/random split (one success, one revert) is state/arg-specific, not
    # curated-set caller discrimination → withhold.
    assert dp.attribute([ok(), revert(OWNABLE)], None) == "indeterminate"


def test_attr_one_sided_randoms_revert_different_data_is_indeterminate():
    assert dp.attribute([revert(OWNABLE), revert(UNAUTHORIZED)], None) == "indeterminate"


def test_attr_principal_node_error_falls_back_to_one_sided():
    # principal unusable → reason on randoms alone (both succeed → candidate public)
    assert dp.attribute([ok(), ok()], node_error()) == "not_caller_discriminating"


# ---------------------------------------------------------------------------
# §3.2 calldata synthesis
# ---------------------------------------------------------------------------


def test_synth_single_uint_zero_encodes():
    assert dp.synthesize_calldata("0x9a1e97d1", "setClaimingOpen(uint256)") == "0x9a1e97d1" + "00" * 32


def test_synth_no_args_is_bare_selector():
    assert dp.synthesize_calldata("0x715018a6", "renounceOwnership()") == "0x715018a6"


def test_synth_address_and_uint():
    data = dp.synthesize_calldata("0xa9059cbb", "transfer(address,uint256)")
    assert data == "0xa9059cbb" + "00" * 32 + "00" * 32


def test_synth_dynamic_types_do_not_crash():
    data = dp.synthesize_calldata("0x12345678", "foo(bytes,uint256[],string)")
    assert data is not None and data.startswith("0x12345678")


def test_synth_tuple_and_fixed_array():
    data = dp.synthesize_calldata("0x12345678", "bar((uint256,address),bool,uint8[2])")
    assert data is not None and data.startswith("0x12345678")


def test_synth_caller_correlated_substitution_sets_identity():
    identity = "0x" + "ab" * 20
    data = dp.synthesize_calldata("0x12345678", "f(address,uint256)", identity=identity, caller_correlated_indices={0})
    assert data is not None
    # First 32-byte word after the selector is the identity address.
    first_word = data[10 : 10 + 64]
    assert first_word == encode_address_word(identity)


def test_synth_miss_on_user_defined_type_returns_none():
    # A residual user-defined type (ERC20) is not ABI-encodable → synthesis MISS.
    assert dp.synthesize_calldata("0x18457e61", "exit(address,ERC20,uint256,address,uint256)") is None


def test_synth_miss_on_malformed_signature():
    assert dp.synthesize_calldata("0x12345678", "notasignature") is None
    assert dp.synthesize_calldata("0x12345678", None) is None


def test_synth_miss_on_bad_selector():
    assert dp.synthesize_calldata("0xZZ", "f()") is None
    assert dp.synthesize_calldata("deadbeef", "f()") is None


# ---------------------------------------------------------------------------
# §6.6 deterministic random identities + decode_error
# ---------------------------------------------------------------------------


def test_derive_random_identities_deterministic_and_distinct():
    a = dp.derive_random_identities("0x9a1e97d1", "0x" + "12" * 20, 2)
    b = dp.derive_random_identities("0x9a1e97d1", "0x" + "12" * 20, 2)
    assert a == b  # replayable
    assert len(set(a)) == 2  # distinct
    assert all(x.startswith("0x") and len(x) == 42 for x in a)
    # Different contract → different identities.
    c = dp.derive_random_identities("0x9a1e97d1", "0x" + "34" * 20, 2)
    assert set(a).isdisjoint(c)


def test_decode_error_shapes():
    assert dp.decode_error(OWNABLE) == "Error('Ownable: caller is not the owner')"
    assert dp.decode_error(UNAUTHORIZED) == f"custom_error {UNAUTHORIZED}"
    assert dp.decode_error("0x") == "(empty revert)"
    assert dp.decode_error(None) is None


# ---------------------------------------------------------------------------
# orchestration: run_differential_probe (§3.5 cross-check + §3.6 verdict)
# ---------------------------------------------------------------------------

ADDR = "0x" + "77" * 20


def _run(responder, *, principal=None, block=1_000_000, block_delta=1000):
    wire = StubWire(responder)
    result = dp.run_differential_probe(
        call_batch=wire,
        chain_id=1,
        contract_address=ADDR,
        selector="0x9a1e97d1",
        canonical_signature="setClaimingOpen(uint256)",
        block=block,
        principal=principal,
        block_delta=block_delta,
    )
    return result, wire


def test_run_candidate_public_with_block_independence_pass_upgrades():
    # Everyone succeeds at both blocks → confirmed public.
    result, wire = _run(lambda _tag, _frm: ok())
    assert result.verdict == "public"
    assert result.attribution == "not_caller_discriminating"
    assert result.transcript["cross_checks"]["block_independence"] == "pass"
    assert result.transcript["block_independence_block"] == 1_000_000 - 1000
    # Two batches: primary block + older block.
    assert len(wire.batches) == 2
    assert wire.batches[0][0] == hex(1_000_000)
    assert wire.batches[1][0] == hex(1_000_000 - 1000)
    # Transcript is replayable: identities + per-address outcomes recorded.
    assert len(result.transcript["identities"]["random"]) == 2
    assert all("success" in o for o in result.transcript["outcomes"].values())


def test_run_candidate_public_but_state_dependent_withholds():
    # Succeeds at the latest block, reverts at the older block → state-dependent → keep static.
    def responder(tag, _frm):
        return ok() if tag == hex(1_000_000) else revert(OWNABLE)

    result, wire = _run(responder)
    assert result.verdict == "keep_static"
    assert result.reason == "open_now_but_state_dependent"
    assert result.transcript["cross_checks"]["block_independence"] == "fail"
    assert len(wire.batches) == 2


def test_run_two_sided_confirmed_gated_does_not_reprobe():
    # random revert, principal success → confirmed gated; NO block-independence re-probe.
    def responder(_tag, frm):
        return ok() if frm == "0xPRINCIPAL".lower() else revert(OWNABLE)

    wire = StubWire(responder)
    result = dp.run_differential_probe(
        call_batch=wire,
        chain_id=1,
        contract_address=ADDR,
        selector="0x9a1e97d1",
        canonical_signature="setClaimingOpen(uint256)",
        block=1_000_000,
        principal="0xprincipal",
    )
    assert result.verdict == "gated_confirmed"
    assert result.attribution == "caller_discriminating"
    assert len(wire.batches) == 1  # never re-probes for a gated confirmation


def test_run_one_sided_consistent_rejection_is_gated_observed():
    result, wire = _run(lambda _tag, _frm: revert(OWNABLE))
    assert result.verdict == "gated_observed"
    assert result.attribution == "caller_rejected_consistent"
    assert len(wire.batches) == 1


def test_run_indeterminate_keeps_static():
    result, wire = _run(lambda _tag, _frm: node_error())
    assert result.verdict == "keep_static"
    assert result.attribution == "indeterminate"
    assert len(wire.batches) == 1


# ---------------------------------------------------------------------------
# recorded REAL transcript (§6.1) — captured once from the eRPC mainnet archive
# at block 25289222, replayed through a stubbed wire (the materializer test
# pattern). Grounds the attribution in genuine node responses, not hand-encoded
# bytes. See scripts/authority_audit/PHASE0_HANDPROBE.md.
# ---------------------------------------------------------------------------

_REAL_OWNABLE_REVERT = (
    "0x08c379a000000000000000000000000000000000000000000000000000000000"
    "00000020000000000000000000000000000000000000000000000000000000000"
    "00000204f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e6572"
).replace(" ", "")


def test_recorded_real_gated_transcript_replays_to_confirmed_gated():
    # EarlyAdopterPool.setClaimingOpen(uint256) @ 25289222: two random callers
    # revert "Ownable: caller is not the owner"; the real owner succeeds.
    gated = "0x7623e9dc0da6ff821ddb9ebaba794054e078f8c4"
    owner = "0xf155a2632ef263a6a382028b3b33feb29175b8a5"

    def responder(_tag, frm):
        return ok() if frm == owner else revert(_REAL_OWNABLE_REVERT)

    wire = StubWire(responder)
    result = dp.run_differential_probe(
        call_batch=wire,
        chain_id=1,
        contract_address=gated,
        selector="0x9a1e97d1",
        canonical_signature="setClaimingOpen(uint256)",
        block=25289222,
        principal=owner,
    )
    assert result.verdict == "gated_confirmed"
    assert result.transcript["outcomes"][owner]["success"] is True
    # The recorded revert decodes for the transcript (richness only).
    rand0 = result.transcript["identities"]["random"][0]
    assert result.transcript["outcomes"][rand0]["decoded_error"] == "Error('Ownable: caller is not the owner')"


def test_recorded_real_public_transcript_replays_to_public():
    # WETH transfer(0x0, 0) @ 25289222: both random callers succeed at both blocks.
    weth = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
    wire = StubWire(lambda _tag, _frm: ok(TRUE))
    result = dp.run_differential_probe(
        call_batch=wire,
        chain_id=1,
        contract_address=weth,
        selector="0xa9059cbb",
        canonical_signature="transfer(address,uint256)",
        block=25289222,
        block_delta=50000,
    )
    assert result.verdict == "public"
    assert result.transcript["cross_checks"]["block_independence"] == "pass"


def test_run_synthesis_miss_never_probes_and_keeps_static():
    wire = StubWire(lambda _tag, _frm: ok())
    result = dp.run_differential_probe(
        call_batch=wire,
        chain_id=1,
        contract_address=ADDR,
        selector="0x18457e61",
        canonical_signature="exit(address,ERC20,uint256,address,uint256)",  # user type → miss
        block=1_000_000,
    )
    assert result.verdict == "keep_static"
    assert result.calldata is None
    assert result.reason == "calldata_synthesis_miss"
    assert wire.batches == []  # a miss must NEVER hit the wire / manufacture an upgrade
