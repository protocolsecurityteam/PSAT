"""Differential on-chain probe: turns "gated, principals unknown" into an observed fact (DIFFERENTIAL_PROBE_PLAN §3).

For an unresolved caller-dependent gate, ``eth_call`` it with ``from = RANDOM`` (in no allowlist) and, when known,
``from = PRINCIPAL``. A caller-discriminating gate gives different outcomes; a non-caller gate gives the same.

The risk is upgrading a gated function to public when both reverted for an unrelated reason (§3.3). So a public upgrade
needs at least two distinct random identities all succeeding plus a block-independence cross-check (§3.5), and revert
attribution compares raw revert data (decoding is transcript-only).

Pure given an injected ``call_batch`` (wrapping :func:`services.clients.rpc.eth_call_batch`); the caller supplies the
pinned block and applies the verdict (§3.6).
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from eth_utils.crypto import keccak

from services.clients.rpc import EthCallResult

# N eth_calls at one block, preserving revert data. Injected for hermetic tests.
CallBatch = Callable[[list[dict[str, str]], str], Sequence[EthCallResult]]

Attribution = Literal[
    "caller_discriminating",  # random rejected where principal proceeds → confirmed gated
    "not_caller_discriminating",  # every identity proceeds → candidate public
    "caller_rejected_consistent",  # one-sided: all randoms rejected identically → gated, observed
    "inconclusive",  # both sides hit the SAME gate → shared precondition
    "indeterminate",  # undecodable / node error / synthesis miss → keep static
]

# Only ``public`` changes the static verdict; the others just attach evidence.
Verdict = Literal["public", "gated_confirmed", "gated_observed", "keep_static"]

_RANDOM_IDENTITY_COUNT = 2


def differential_probe_enabled() -> bool:
    """Feature flag, default on (0 label-disagreeing upgrades over 711 corpus rows).

    ``PSAT_DIFFERENTIAL_PROBE=0`` disables; tests/conftest.py forces it off.
    """
    return os.getenv("PSAT_DIFFERENTIAL_PROBE", "1").lower() in ("1", "true", "yes")


def _block_independence_delta() -> int:
    """Blocks to step back for the §3.5.1 re-probe (~7 days); override with ``PSAT_PROBE_BLOCK_DELTA``."""
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
    # None on a synthesis miss, which can only withhold an upgrade.
    calldata: str | None = field(default=None)


def synthesize_calldata(
    selector: str,
    canonical_signature: str | None,
    *,
    identity: str | None = None,
    caller_correlated_indices: Iterable[int] = (),
) -> str | None:
    """Build ``selector ++ abi.encode(default_args)``.

    Arguments are zero/empty (most gates fire before argument validation, §3.2.1). Address args at
    ``caller_correlated_indices`` are set to ``identity`` so self-service paths are reachable (§3.2.2). Returns None on
    unparseable or unencodable types, which keeps the static verdict (§3.2.3). Never raises.
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
    """Top-level arg types from ``name(t1,t2,...)``: ``[]`` for no args, None if malformed."""
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
    """Split a type list at depth 0 so tuples and fixed arrays stay intact."""
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
    a = addr.lower()
    return a if a.startswith("0x") else "0x" + a


def _default_value_for_type(type_str: str) -> Any:
    """A zero/empty value for an ABI type (arrays, tuples, scalars).

    Raises on unknown types so synthesis records a miss.
    """
    t = type_str.strip()
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


def derive_random_identities(selector: str, contract_address: str, n: int = _RANDOM_IDENTITY_COUNT) -> list[str]:
    """``n`` deterministic random callers from ``keccak(selector ++ address ++ salt)``, so replays use the same
    addresses (§6.6).
    """
    sel = bytes.fromhex(selector[2:]) if selector.startswith("0x") else bytes.fromhex(selector)
    addr = bytes.fromhex(contract_address[2:]) if contract_address.startswith("0x") else bytes.fromhex(contract_address)
    out: list[str] = []
    for salt in range(n):
        digest = keccak(sel + addr + salt.to_bytes(2, "big"))
        out.append("0x" + digest.hex()[-40:])
    return out


def _is_node_error(o: EthCallResult) -> bool:
    """A revert with no data (OOG, transport, node omits ``error.data``): unattributable."""
    return (not o.success) and o.revert_data is None


def decode_error(revert_data: str | None) -> str | None:
    """Human label for a revert, for the transcript only: ``Error(string)``, ``Panic(uint256)``, else the
    custom-error selector.
    """
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
    """Map probe outcomes to an attribution (§3.3, §3.4).

    * Any node error among randoms → indeterminate.
    * Randoms disagreeing → indeterminate (state- or arg-specific).
    * Public requires every random to succeed.
    * Identical revert data counts as the same gate (conservative).
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

    # An errored principal is unusable; fall back to one-sided.
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
            # Randoms succeeding signals openness; the principal's revert is arg/state-specific.
            return "not_caller_discriminating"
        return "indeterminate"

    # One-sided (§3.4).
    if all_success:
        return "not_caller_discriminating"  # candidate public
    if all_revert and randoms_same_gate:
        return "caller_rejected_consistent"  # gated, observed (verdict unchanged)
    return "indeterminate"


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
    """Probe one gated-unknown function; returns a verdict with a replayable transcript (§6.1).

    ``block`` must be pinned, never ``latest`` (§6.2).

      * ``public``          → ``conditional_universal``
      * ``gated_confirmed`` → keep gated, attach two-sided evidence
      * ``gated_observed``  → keep gated, attach one-sided evidence
      * ``keep_static``     → unchanged
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
        transcript["verdict"] = "keep_static"
        return ProbeResult(attribution, "keep_static", transcript, attribution, calldata)

    # Candidate public: run the §3.5 block-independence check first.
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

    # State-dependent or unverifiable at the older block: fail closed.
    transcript["cross_checks"]["block_independence"] = "fail"
    transcript["verdict"] = "keep_static"
    return ProbeResult("not_caller_discriminating", "keep_static", transcript, "open_now_but_state_dependent", calldata)
