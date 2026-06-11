"""Differential on-chain probe — upgrade a "gated, principals unknown" verdict
from a static heuristic to an observed fact (DIFFERENTIAL_PROBE_PLAN §3).

The earned-public default leaves a caller-dependent gate we can't resolve as
``external_check_only`` → "gated, principals unknown". For each such verdict we
ask the deployed contract directly whether the gate actually discriminates on
the caller, using only ``eth_call`` with a varying ``from`` (no transaction, no
state mutation):

  * ``from = RANDOM``    — a fresh address in no allowlist, holding no role;
  * ``from = PRINCIPAL`` — the resolved owner/role-holder, when known.

A gate that discriminates on the caller yields DIFFERENT outcomes; a non-caller
gate (business precondition, value movement, pure view) yields the SAME outcome.
That difference — or its absence — is the one bit this module observes.

Soundness is the whole risk (§3.3). The dangerous direction is upgrading a
genuinely-gated function to public because both identities reverted for the same
unrelated reason. Two rules make it sound:

  1. A public upgrade is EARNED only by ≥2 distinct random identities all
     SUCCEEDING, cross-checked for block-independence (§3.5). A single ambiguous
     probe never opens anything; indeterminate ≠ public; fail closed.
  2. Revert attribution compares RAW revert data, not decoded semantics. Two
     identical revert payloads are treated as the same gate (conservative —
     withholds upgrades, the safe direction). Decoding is for the transcript
     only and never drives a verdict (the earned-public refactor deliberately
     moved away from positive recognition of authority patterns).

This module is PURE given an injected ``call_batch`` callable (a thin wrapper
over :func:`utils.rpc.eth_call_batch`), so it is testable against a stubbed wire
with recorded transcripts. The wiring (predicate resolution) supplies the
callable, the pinned block, and applies the verdict to the capability (§3.6).
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from eth_utils.crypto import keccak

from utils.rpc import EthCallResult

# A call batch issues N eth_calls (each ``{from?, to, data}``) at one block tag and
# returns per-call results PRESERVING revert data. Injected so the probe is hermetic.
CallBatch = Callable[[list[dict[str, str]], str], Sequence[EthCallResult]]

Attribution = Literal[
    "caller_discriminating",  # random rejected where principal proceeds → confirmed gated
    "not_caller_discriminating",  # every identity proceeds → candidate public
    "caller_rejected_consistent",  # one-sided: all randoms rejected identically → gated, observed
    "inconclusive",  # both sides hit the SAME gate → shared precondition
    "indeterminate",  # undecodable / node error / synthesis miss → keep static
]

# The only verdict that CHANGES a static gated-unknown verdict is ``public`` (and only
# after the cross-checks pass). Everything else keeps the conservative static verdict;
# ``gated_confirmed`` / ``gated_observed`` merely attach observed evidence to it.
Verdict = Literal["public", "gated_confirmed", "gated_observed", "keep_static"]

_RANDOM_IDENTITY_COUNT = 2


def differential_probe_enabled() -> bool:
    """The differential-probe feature flag. Default ON — the Phase 3 corpus
    confusion matrix is green (0 label-disagreeing public upgrades over 711 rows),
    the bar the plan set for enabling. ``PSAT_DIFFERENTIAL_PROBE=0`` is the release
    kill-switch (the earned-public / #130 precedent). The offline suite forces it
    OFF via tests/conftest.py for hermeticity (it issues live eth_call probes)."""
    return os.getenv("PSAT_DIFFERENTIAL_PROBE", "1").lower() in ("1", "true", "yes")


def _block_independence_delta() -> int:
    """Blocks to step back for the §3.5.1 state-independence re-probe. ~50k blocks
    (≈7 days at 12s) is a different state epoch while staying inside an archive
    node's range. Override with ``PSAT_PROBE_BLOCK_DELTA``."""
    try:
        return max(1, int(os.getenv("PSAT_PROBE_BLOCK_DELTA", "50000")))
    except ValueError:
        return 50000


@dataclass
class ProbeResult:
    attribution: Attribution
    verdict: Verdict
    transcript: dict[str, Any]
    reason: str
    # The synthesized calldata, or None on a synthesis miss (then verdict is always
    # keep_static — a miss can only withhold an upgrade, never manufacture one).
    calldata: str | None = field(default=None)


# ---------------------------------------------------------------------------
# §3.2 — calldata synthesis
# ---------------------------------------------------------------------------


def synthesize_calldata(
    selector: str,
    canonical_signature: str | None,
    *,
    identity: str | None = None,
    caller_correlated_indices: Iterable[int] = (),
) -> str | None:
    """Build full calldata ``selector ++ abi.encode(default_args)`` for a function.

    Zero/default-encodes every argument from the canonical ABI types (0 for
    uint/address, empty for bytes/array/string, false for bool) — most authority
    gates fire before argument validation, so a zero-arg call still exercises the
    gate (§3.2.1). When ``caller_correlated_indices`` is given and ``identity`` is
    set, those address-typed positional arguments are set to ``identity`` instead
    of zero, so a self-service / appointed path keyed on a parameter is reachable
    (§3.2.2).

    Returns None — a synthesis MISS — when the argument types can't be parsed or
    ABI-encoded (a residual user-defined type, an exotic shape). A miss fails safe:
    the caller keeps the static verdict (§3.2.3). Never raises.
    """
    if not isinstance(selector, str) or not selector.startswith("0x") or len(selector) != 10:
        return None
    types = _parse_arg_types(canonical_signature)
    if types is None:
        return None
    correlated = {int(i) for i in caller_correlated_indices}
    try:
        from eth_abi.abi import encode as abi_encode

        values = []
        for idx, type_str in enumerate(types):
            if idx in correlated and identity is not None and _is_address_type(type_str):
                values.append(_checksum_optional(identity))
            else:
                values.append(_default_value_for_type(type_str))
        encoded = abi_encode(types, values).hex() if types else ""
    except Exception:
        return None
    return selector + encoded


def _parse_arg_types(canonical_signature: str | None) -> list[str] | None:
    """Extract the top-level argument type list from ``name(t1,t2,...)``. Returns
    ``[]`` for a no-arg function, a list of type strings otherwise, or None when the
    signature is malformed."""
    if not isinstance(canonical_signature, str):
        return None
    open_paren = canonical_signature.find("(")
    if open_paren < 0 or not canonical_signature.endswith(")"):
        return None
    inner = canonical_signature[open_paren + 1 : -1].strip()
    if not inner:
        return []
    return _split_top_level(inner)


def _split_top_level(inner: str) -> list[str]:
    """Split a comma-separated type list at depth 0, so nested tuples
    ``(uint256,address)`` and arrays ``uint256[2]`` aren't split inside their
    brackets."""
    parts: list[str] = []
    depth = 0
    current = ""
    for ch in inner:
        if ch in "([":
            depth += 1
            current += ch
        elif ch in ")]":
            depth -= 1
            current += ch
        elif ch == "," and depth == 0:
            parts.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        parts.append(current.strip())
    return parts


def _is_address_type(type_str: str) -> bool:
    return type_str.strip() == "address"


def _checksum_optional(addr: str) -> str:
    # eth_abi accepts lowercase hex addresses; keep it lowercase + 0x-prefixed.
    a = addr.lower()
    return a if a.startswith("0x") else "0x" + a


def _default_value_for_type(type_str: str) -> Any:
    """A canonical zero/empty Python value for an ABI type, for ``eth_abi.encode``.
    Handles arrays (fixed + dynamic), tuples (recursive), and the scalar types.
    Raises on an unrecognized type so :func:`synthesize_calldata` records a miss."""
    t = type_str.strip()
    # Dynamic / fixed arrays: strip the trailing [..]
    if t.endswith("]"):
        open_bracket = t.rfind("[")
        base = t[:open_bracket]
        size = t[open_bracket + 1 : -1]
        if size == "":  # dynamic array → empty
            return []
        return [_default_value_for_type(base) for _ in range(int(size))]
    if t.startswith("(") and t.endswith(")"):
        components = _split_top_level(t[1:-1])
        return tuple(_default_value_for_type(c) for c in components)
    if t == "address":
        return "0x" + "00" * 20
    if t == "bool":
        return False
    if t == "string":
        return ""
    if t == "bytes":
        return b""
    if t.startswith("bytes"):  # bytesN fixed
        n = int(t[5:])
        return b"\x00" * n
    if t.startswith("uint") or t.startswith("int"):
        return 0
    if t in ("ufixed", "fixed") or t.startswith("ufixed") or t.startswith("fixed"):
        return 0
    raise ValueError(f"unsupported abi type for default-encode: {t!r}")


# ---------------------------------------------------------------------------
# §6.6 — deterministic random identities
# ---------------------------------------------------------------------------


def derive_random_identities(selector: str, contract_address: str, n: int = _RANDOM_IDENTITY_COUNT) -> list[str]:
    """Derive ``n`` random caller addresses deterministically from
    ``keccak(selector ++ address ++ salt)`` so a replay uses the SAME addresses
    (no ``Math.random``-style nondeterminism — §6.6). Astronomically unlikely to
    collide with any curated allowlist member by construction."""
    sel = bytes.fromhex(selector[2:]) if selector.startswith("0x") else bytes.fromhex(selector)
    addr = bytes.fromhex(contract_address[2:]) if contract_address.startswith("0x") else bytes.fromhex(contract_address)
    out: list[str] = []
    for salt in range(n):
        digest = keccak(sel + addr + salt.to_bytes(2, "big"))
        out.append("0x" + digest.hex()[-40:])
    return out


# ---------------------------------------------------------------------------
# §3.3 — revert attribution (raw-data comparison; decode is transcript-only)
# ---------------------------------------------------------------------------


def _is_success(o: EthCallResult) -> bool:
    return o.success


def _is_node_error(o: EthCallResult) -> bool:
    """A revert with NO decodable data: OOG, transport, a node that omits
    ``error.data``. Not attributable → drives indeterminate."""
    return (not o.success) and o.revert_data is None


def decode_error(revert_data: str | None) -> str | None:
    """Best-effort human label for a revert, for the transcript ONLY (never a
    verdict input). Decodes ``Error(string)`` and ``Panic(uint256)``; otherwise
    records the 4-byte custom-error selector."""
    if revert_data is None:
        return None
    if revert_data == "0x":
        return "(empty revert)"
    body = revert_data[2:] if revert_data.startswith("0x") else revert_data
    if len(body) < 8:
        return f"(short revert {revert_data})"
    sel = body[:8]
    if sel == "08c379a0":  # Error(string)
        try:
            from eth_abi.abi import decode as abi_decode

            return "Error(%r)" % abi_decode(["string"], bytes.fromhex(body[8:]))[0]
        except Exception:
            return f"Error(string) <undecodable {revert_data[:18]}…>"
    if sel == "4e487b71":  # Panic(uint256)
        try:
            from eth_abi.abi import decode as abi_decode

            return "Panic(0x%x)" % abi_decode(["uint256"], bytes.fromhex(body[8:]))[0]
        except Exception:
            return "Panic(uint256)"
    return f"custom_error 0x{sel}"


def attribute(randoms: Sequence[EthCallResult], principal: EthCallResult | None) -> Attribution:
    """Map a probe outcome set to an attribution (§3.3 table + §3.4 one-sided).

    Soundness rules baked in:
      * any node error among the randoms → indeterminate (can't attribute);
      * randoms that DISAGREE among themselves → indeterminate (a random/random
        split is state/arg-specific, not curated-set caller discrimination);
      * a public verdict requires EVERY random to SUCCEED;
      * identical revert data is treated as the same gate (conservative).
    """
    if not randoms:
        return "indeterminate"
    if any(_is_node_error(o) for o in randoms):
        return "indeterminate"

    all_success = all(o.success for o in randoms)
    all_revert = all(not o.success for o in randoms)
    if not (all_success or all_revert):
        return "indeterminate"  # randoms split — unclear, withhold

    random_revert_datas = {o.revert_data for o in randoms if not o.success}
    randoms_same_gate = len(random_revert_datas) <= 1

    # A principal that itself errored at the node is unusable — fall back to one-sided.
    if principal is not None and _is_node_error(principal):
        principal = None

    if principal is not None:
        if all_revert and principal.success:
            return "caller_discriminating"  # confirmed gated (random blocked, principal proceeds)
        if all_revert and not principal.success:
            if randoms_same_gate and principal.revert_data == next(iter(random_revert_datas)):
                return "inconclusive"  # everyone hits the SAME gate → shared precondition
            if randoms_same_gate:
                return "caller_discriminating"  # principal reached a DIFFERENT (later) gate
            return "indeterminate"
        if all_success and principal.success:
            return "not_caller_discriminating"  # candidate public
        if all_success and not principal.success:
            # Random callers succeeding is the openness signal (§3.3: a random success is
            # strong evidence of openness); the principal reverting is arg/state-specific.
            return "not_caller_discriminating"
        return "indeterminate"

    # One-sided (§3.4) — no principal.
    if all_success:
        return "not_caller_discriminating"  # candidate public
    if all_revert and randoms_same_gate:
        return "caller_rejected_consistent"  # gated, observed (verdict unchanged)
    return "indeterminate"


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def _outcome_dict(role: str, addr: str, o: EthCallResult) -> dict[str, Any]:
    return {
        "address": addr.lower(),
        "role": role,
        "success": o.success,
        "return_or_revert_hex": o.return_data if o.success else (o.revert_data if o.revert_data is not None else None),
        "decoded_error": None if o.success else decode_error(o.revert_data),
        "error_message": o.error_message,
    }


def run_differential_probe(
    *,
    call_batch: CallBatch,
    chain_id: int,
    contract_address: str,
    selector: str,
    canonical_signature: str | None,
    block: int,
    principal: str | None = None,
    random_count: int = _RANDOM_IDENTITY_COUNT,
    block_delta: int | None = None,
    caller_correlated_indices: Iterable[int] = (),
) -> ProbeResult:
    """Probe one gated-unknown function and return an attributed verdict with a
    replayable transcript (§6.1). ``block`` MUST be a pinned height — never probe
    at ``latest``, or mutable allowlist state makes the answer drift (§6.2).

    Verdict mapping for the caller (§3.6):
      * ``public``         → mint ``conditional_universal`` (caller-independent, observed)
      * ``gated_confirmed``→ keep gated; attach two-sided discriminating evidence
      * ``gated_observed`` → keep gated; attach one-sided rejection evidence
      * ``keep_static``    → leave the static verdict untouched (inconclusive/indeterminate/miss)
    """
    calldata = synthesize_calldata(
        selector,
        canonical_signature,
        identity=principal,
        caller_correlated_indices=caller_correlated_indices,
    )
    base_transcript: dict[str, Any] = {
        "feature": "differential_probe",
        "version": 1,
        "chain_id": chain_id,
        "contract_address": contract_address.lower(),
        "selector": selector,
        "canonical_signature": canonical_signature,
        "calldata": calldata,
        "block_number": block,
    }
    if calldata is None:
        return ProbeResult(
            attribution="indeterminate",
            verdict="keep_static",
            transcript={**base_transcript, "attribution": "indeterminate", "reason": "calldata_synthesis_miss"},
            reason="calldata_synthesis_miss",
            calldata=None,
        )

    randoms = derive_random_identities(selector, contract_address, random_count)
    identities = list(randoms) + ([principal] if principal else [])
    roles = ["random"] * len(randoms) + (["principal"] if principal else [])
    calls = [{"from": ident, "to": contract_address, "data": calldata} for ident in identities]

    block_tag = hex(block)
    results = list(call_batch(calls, block_tag))
    if len(results) != len(calls):
        return ProbeResult(
            attribution="indeterminate",
            verdict="keep_static",
            transcript={**base_transcript, "attribution": "indeterminate", "reason": "batch_length_mismatch"},
            reason="batch_length_mismatch",
            calldata=calldata,
        )

    random_results = results[: len(randoms)]
    principal_result = results[len(randoms)] if principal else None

    attribution = attribute(random_results, principal_result)
    outcomes = {ident.lower(): _outcome_dict(role, ident, res) for ident, role, res in zip(identities, roles, results)}
    transcript: dict[str, Any] = {
        **base_transcript,
        "identities": {"random": [r.lower() for r in randoms], "principal": principal.lower() if principal else None},
        "outcomes": outcomes,
        "attribution": attribution,
        "cross_checks": {},
    }

    if attribution == "caller_discriminating":
        transcript["verdict"] = "gated_confirmed"
        return ProbeResult("caller_discriminating", "gated_confirmed", transcript, "two_sided_discrimination", calldata)

    if attribution == "caller_rejected_consistent":
        transcript["verdict"] = "gated_observed"
        return ProbeResult(
            "caller_rejected_consistent", "gated_observed", transcript, "one_sided_consistent_rejection", calldata
        )

    if attribution != "not_caller_discriminating":
        # inconclusive / indeterminate → keep the static verdict, untouched.
        transcript["verdict"] = "keep_static"
        return ProbeResult(attribution, "keep_static", transcript, attribution, calldata)

    # candidate public → §3.5 block-independence cross-check before any upgrade.
    delta = block_delta if block_delta is not None else _block_independence_delta()
    older_block = block - delta
    if older_block < 1:
        transcript["cross_checks"]["block_independence"] = "skipped_low_block"
        transcript["verdict"] = "keep_static"
        return ProbeResult("not_caller_discriminating", "keep_static", transcript, "no_older_block", calldata)

    older_tag = hex(older_block)
    older_calls = [{"from": r, "to": contract_address, "data": calldata} for r in randoms]
    older_results = list(call_batch(older_calls, older_tag))
    transcript["block_independence_block"] = older_block
    transcript["outcomes_older_block"] = {
        r.lower(): _outcome_dict("random", r, res) for r, res in zip(randoms, older_results)
    }

    older_attribution = attribute(older_results, None)
    if older_attribution == "not_caller_discriminating":
        transcript["cross_checks"]["block_independence"] = "pass"
        transcript["verdict"] = "public"
        return ProbeResult("not_caller_discriminating", "public", transcript, "open_and_block_independent", calldata)

    # Admission was state-dependent (or unverifiable at the older block) — fail closed.
    transcript["cross_checks"]["block_independence"] = "fail"
    transcript["verdict"] = "keep_static"
    return ProbeResult("not_caller_discriminating", "keep_static", transcript, "open_now_but_state_dependent", calldata)
