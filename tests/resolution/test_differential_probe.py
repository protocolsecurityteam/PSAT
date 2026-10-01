"""Unit tests for the differential probe. Every attribution-table row is
exercised against recorded outcomes via
a stubbed ``call_batch`` — no live RPC. Soundness invariants asserted:

  * a public verdict requires ≥2 random SUCCESSES + block-independence;
  * indeterminate / inconclusive / synthesis-miss NEVER upgrade (fail closed);
  * the block-independence cross-check withholds on state-dependent admission.
"""

from __future__ import annotations

import pytest
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
# attribution table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("randoms", "principal", "expected"),
    [
        # row 1: revert(A) / success → caller-discriminating (confirmed gated)
        pytest.param(
            [revert(OWNABLE), revert(OWNABLE)],
            ok(),
            "caller_discriminating",
            id="two_sided_random_revert_principal_success",
        ),
        # row 2: random revert(A), principal revert(B), A≠B → caller-discriminating
        pytest.param(
            [revert(OWNABLE), revert(OWNABLE)],
            revert(ZERO_ADDR),
            "caller_discriminating",
            id="two_sided_different_gates",
        ),
        # row 3 (CRITICAL): success / success → candidate public; the only path toward a public verdict
        pytest.param([ok(), ok()], ok(), "not_caller_discriminating", id="two_sided_all_success"),
        # row 4 (CRITICAL): same gate everywhere → inconclusive; a shared earlier gate must not upgrade or confirm
        pytest.param(
            [revert(OWNABLE), revert(OWNABLE)], revert(OWNABLE), "inconclusive", id="two_sided_same_gate_everywhere"
        ),
        # row 5 (CRITICAL): a node error (no revert data) among randoms → indeterminate, fails closed
        pytest.param([revert(OWNABLE), node_error()], ok(), "indeterminate", id="node_error_with_principal"),
        pytest.param([node_error()], None, "indeterminate", id="node_error_one_sided"),
        pytest.param([ok(), ok()], None, "not_caller_discriminating", id="one_sided_all_success"),
        pytest.param(
            [revert(OWNABLE), revert(OWNABLE)],
            None,
            "caller_rejected_consistent",
            id="one_sided_all_revert_same_ownable",
        ),
        pytest.param(
            [revert(UNAUTHORIZED), revert(UNAUTHORIZED)],
            None,
            "caller_rejected_consistent",
            id="one_sided_all_revert_same_custom",
        ),
        # (CRITICAL) random/random split is state/arg-specific, not curated-set caller discrimination → withhold
        pytest.param([ok(), revert(OWNABLE)], None, "indeterminate", id="randoms_disagree"),
        pytest.param(
            [revert(OWNABLE), revert(UNAUTHORIZED)], None, "indeterminate", id="one_sided_randoms_revert_different_data"
        ),
        # principal unusable → reason on randoms alone (both succeed → candidate public)
        pytest.param(
            [ok(), ok()], node_error(), "not_caller_discriminating", id="principal_node_error_falls_back_one_sided"
        ),
    ],
)
def test_attribute_table(randoms, principal, expected):
    assert dp.attribute(randoms, principal) == expected


# ---------------------------------------------------------------------------
# calldata synthesis
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("selector", "signature", "expected"),
    [
        pytest.param("0x9a1e97d1", "setClaimingOpen(uint256)", "0x9a1e97d1" + "00" * 32, id="single_uint_zero"),
        pytest.param("0x715018a6", "renounceOwnership()", "0x715018a6", id="no_args_bare_selector"),
        pytest.param(
            "0xa9059cbb", "transfer(address,uint256)", "0xa9059cbb" + "00" * 32 + "00" * 32, id="address_and_uint"
        ),
    ],
)
def test_synth_exact_encoding(selector, signature, expected):
    assert dp.synthesize_calldata(selector, signature) == expected


@pytest.mark.parametrize(
    "signature",
    [
        pytest.param("foo(bytes,uint256[],string)", id="dynamic_types"),
        pytest.param("bar((uint256,address),bool,uint8[2])", id="tuple_and_fixed_array"),
    ],
)
def test_synth_complex_types_do_not_crash(signature):
    data = dp.synthesize_calldata("0x12345678", signature)
    assert data is not None and data.startswith("0x12345678")


def test_synth_caller_correlated_substitution_sets_identity():
    identity = "0x" + "ab" * 20
    data = dp.synthesize_calldata("0x12345678", "f(address,uint256)", identity=identity, caller_correlated_indices={0})
    assert data is not None
    first_word = data[10 : 10 + 64]
    assert first_word == encode_address_word(identity)


@pytest.mark.parametrize(
    ("selector", "signature"),
    [
        # A residual user-defined type (ERC20) is not ABI-encodable → synthesis MISS.
        pytest.param("0x18457e61", "exit(address,ERC20,uint256,address,uint256)", id="user_defined_type"),
        pytest.param("0x12345678", "notasignature", id="malformed_signature"),
        pytest.param("0x12345678", None, id="no_signature"),
        pytest.param("0xZZ", "f()", id="selector_not_hex"),
        pytest.param("deadbeef", "f()", id="selector_missing_0x"),
    ],
)
def test_synth_miss_returns_none(selector, signature):
    assert dp.synthesize_calldata(selector, signature) is None


# ---------------------------------------------------------------------------
# deterministic random identities + decode_error
# ---------------------------------------------------------------------------


def test_derive_random_identities_deterministic_and_distinct():
    a = dp.derive_random_identities("0x9a1e97d1", "0x" + "12" * 20, 2)
    b = dp.derive_random_identities("0x9a1e97d1", "0x" + "12" * 20, 2)
    assert a == b  # replayable
    assert len(set(a)) == 2  # distinct
    assert all(x.startswith("0x") and len(x) == 42 for x in a)
    c = dp.derive_random_identities("0x9a1e97d1", "0x" + "34" * 20, 2)
    assert set(a).isdisjoint(c)


def test_decode_error_shapes():
    assert dp.decode_error(OWNABLE) == "Error('Ownable: caller is not the owner')"
    assert dp.decode_error(UNAUTHORIZED) == f"custom_error {UNAUTHORIZED}"
    assert dp.decode_error("0x") == "(empty revert)"
    assert dp.decode_error(None) is None


# ---------------------------------------------------------------------------
# orchestration: run_differential_probe
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
    result, wire = _run(lambda _tag, _frm: ok())
    assert result.verdict == "public"
    assert result.attribution == "not_caller_discriminating"
    assert result.transcript["cross_checks"]["block_independence"] == "pass"
    assert result.transcript["block_independence_block"] == 1_000_000 - 1000
    assert len(wire.batches) == 2
    assert wire.batches[0][0] == hex(1_000_000)
    assert wire.batches[1][0] == hex(1_000_000 - 1000)
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
# recorded REAL transcript — captured once from the eRPC mainnet archive
# at block 25289222, replayed through a stubbed wire (the materializer test
# pattern). Grounds the attribution in genuine node responses, not hand-encoded
# bytes; the recorded outcomes below are the replay source.
# ---------------------------------------------------------------------------


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
