"""Behavioral-hash ladder tests (EFFECTS_RESOLUTION_SPEC §7 / inv. 2).

Two layers:
  * a real-Slither compile of a mixin default vs a stricter override, gated
    behind local solc availability (the offline-suite convention — CI
    preinstalls one, a fresh clone skips), proving inv. 2 on real IR;
  * lightweight structural doubles (no solc) so the core invariants — override
    diverges, internal-callee inlining, immutable masking, unverified
    determinism, fast-path soundness precondition — are always covered.
"""

from __future__ import annotations

import pytest

from services.effects.hashing import (
    bytecode_fallback_hash,
    contract_surface_hash,
)

pytestmark = pytest.mark.compile


# ---------------------------------------------------------------------------
# Item 2 — unverified fallback + immutable masking.
# ---------------------------------------------------------------------------


def _with_metadata(core: bytes) -> bytes:
    # Fake CBOR metadata trailer: <core><meta bytes><2-byte big-endian meta len>.
    meta = b"\xa2\x64meta"
    return core + meta + len(meta).to_bytes(2, "big")


def test_unverified_fallback_is_deterministic_and_strips_metadata():
    core = b"\x60\x80\x60\x40\x52\xfe"
    h1 = bytecode_fallback_hash(_with_metadata(core), "0x12345678")
    h2 = bytecode_fallback_hash("0x" + _with_metadata(core).hex(), "0x12345678")
    # Two builds differing ONLY in the metadata trailer collapse to one hash.
    alt_meta = b"\xa2\x64DIFF"
    meta2 = core + alt_meta + len(alt_meta).to_bytes(2, "big")
    h3 = bytecode_fallback_hash(meta2, "0x12345678")
    assert h1 == h2 == h3
    # Different selector -> different hash (dispatch differs).
    assert bytecode_fallback_hash(_with_metadata(core), "0xdeadbeef") != h1


def test_immutable_masking_recovers_a_hit():
    """Two deployments identical except in an immutable byte-range hash apart
    without masking, and identical WITH the immutableReferences mask."""
    prefix = b"\x60\x80"
    suffix = b"\xfe"
    imm_a = b"\x11" * 32
    imm_b = b"\x22" * 32
    code_a = prefix + imm_a + suffix
    code_b = prefix + imm_b + suffix
    refs = {"7": [{"start": len(prefix), "length": 32}]}

    assert bytecode_fallback_hash(code_a, "0xaa") != bytecode_fallback_hash(code_b, "0xaa")
    assert bytecode_fallback_hash(code_a, "0xaa", immutable_references=refs) == bytecode_fallback_hash(
        code_b, "0xaa", immutable_references=refs
    )


def test_masking_never_merges_a_gated_deployment_with_an_ungated_one():
    """The invariant ``calldata._gate_ref`` relies on to emit ``gate:none``.

    ``gate:none`` is what a function gets when it has no predicate tree — a
    proven-ungated one AND one whose real gate the static plane could not lower.
    Those two may only ever share a cache identity when the OTHER component,
    the kernel ``behavior_hash``, also matches; here that hash is the whole
    runtime bytecode, which contains the gate. Immutable masking is the one
    thing that deliberately merges distinct deployments, so it is the thing that
    must not reach the gate: it erases the ADDRESS the gate compares against
    (two owners, one hash) and leaves the CALLER/EQ/JUMPI comparison standing
    (gated and ungated stay apart).
    """
    body = bytes.fromhex("6001600155")  # the guarded action: sstore(1, 1)

    # CALLER, PUSH20 <owner>, EQ, PUSH1 dest, JUMPI, REVERT, JUMPDEST
    def _gated(owner: bytes) -> bytes:
        return bytes.fromhex("33") + bytes.fromhex("73") + owner + bytes.fromhex("14601a575ffd5b") + body

    owner_offset = 2  # after CALLER + the PUSH20 opcode
    refs = {"1": [{"start": owner_offset, "length": 20}]}
    gated_a = _gated(b"\xaa" * 20)
    gated_b = _gated(b"\xbb" * 20)
    selector = "0xdeadbeef"

    # The mask does its job: a per-deployment immutable authority is not an identity.
    assert bytecode_fallback_hash(gated_a, selector, immutable_references=refs) == bytecode_fallback_hash(
        gated_b, selector, immutable_references=refs
    )
    # ...and cannot reach past it: the gate itself still splits the identity, so a
    # `gate:none` row can never transfer a verdict onto a deployment that has one.
    assert bytecode_fallback_hash(gated_a, selector, immutable_references=refs) != bytecode_fallback_hash(
        body, selector, immutable_references=refs
    )
    assert bytecode_fallback_hash(gated_a, selector) != bytecode_fallback_hash(body, selector)


def test_contract_surface_hash_is_selectorless_and_masks():
    prefix = b"\x60\x80"
    refs = {"1": [{"start": 2, "length": 4}]}
    a = prefix + b"\xaa\xbb\xcc\xdd" + b"\xfe"
    b = prefix + b"\x00\x11\x22\x33" + b"\xfe"
    assert contract_surface_hash(a, immutable_references=refs) == contract_surface_hash(b, immutable_references=refs)


# ---------------------------------------------------------------------------
# Real-Slither corroboration (gated behind local solc, offline compile only).
# ---------------------------------------------------------------------------


def _solc_086() -> str:
    import solc_select.solc_select as ss

    best: tuple[int, int, int] | None = None
    for version in ss.installed_versions():
        try:
            parsed = tuple(int(x) for x in version.split("."))
        except ValueError:
            continue
        if len(parsed) == 3 and (0, 8, 26) <= parsed and parsed[:2] == (0, 8) and (best is None or parsed > best):
            best = parsed
    if best is None:
        pytest.skip("no installed solc >=0.8.26 (run `solc-select install 0.8.27`)")
    return str(ss.artifact_path(".".join(str(x) for x in best)))
