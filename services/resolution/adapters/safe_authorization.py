from __future__ import annotations

from dataclasses import replace

from eth_abi.abi import decode, encode
from eth_utils.crypto import keccak

from services.clients.rpc import rpc_request

from ..capabilities import CapabilityExpr, ExternalCheck
from . import EvaluationContext

_HINTS = {"safe_v1_4_1_signatures", "safe_v1_4_1_modules"}


class SafeAuthorizationAdapter:
    @classmethod
    def matches(cls, descriptor: dict, ctx: EvaluationContext) -> int:
        del ctx
        authority = descriptor.get("authority_contract") or {}
        return (
            100
            if (
                descriptor.get("kind") == "external_set"
                and authority.get("abi_hint") in _HINTS
                and (authority.get("address_source") or {}).get("source") == "self_address"
                and descriptor.get("source_identity")
            )
            else 0
        )

    @classmethod
    def supports_external_check_only(cls) -> bool:
        return True

    def enumerate(self, descriptor: dict, ctx: EvaluationContext) -> CapabilityExpr:
        hint = (descriptor.get("authority_contract") or {})["abi_hint"]
        key = (hint, ctx.contract_address, ctx.block)
        cache = ctx.meta.setdefault("live_read_memo", {})
        if key in cache:
            return cache[key]
        fallback = CapabilityExpr.external_check_only(
            ExternalCheck(
                target_address=ctx.contract_address,
                target_call_selector=None,
                extra={"basis": ["caller_tainted_authority_unresolved", "safe_authorization_read_unavailable"]},
            )
        )
        rpc_url, address, block = ctx.rpc_url, ctx.contract_address, ctx.block
        if not rpc_url or not address or not isinstance(block, int):
            return fallback

        def read(signature, return_types, args=b""):
            calldata = "0x" + (keccak(text=signature)[:4] + args).hex()
            raw = rpc_request(
                rpc_url,
                "eth_call",
                [{"to": address, "data": calldata}, hex(block)],
                retries=1,
                chain_id=ctx.chain_id,
            )
            return decode(return_types, bytes.fromhex(raw.removeprefix("0x")))

        try:
            if hint == "safe_v1_4_1_signatures":
                owners = list(read("getOwners()", ["address[]"])[0])
                threshold = read("getThreshold()", ["uint256"])[0]
                if not 0 < threshold <= len(set(owners)) == len(owners) or any(int(owner, 16) <= 1 for owner in owners):
                    return fallback
                cap = CapabilityExpr.threshold_group(threshold, owners)
            else:
                modules, next_module = read(
                    "getModulesPaginated(address,uint256)",
                    ["address[]", "address"],
                    encode(["address", "uint256"], ["0x" + "0" * 39 + "1", 100]),
                )
                if int(next_module, 16) != 1:
                    return fallback  # A truncated list cannot prove all callers, or absence.
                cap = CapabilityExpr.finite_set(list(modules))
        except Exception:
            return fallback
        cap = replace(
            cap,
            last_indexed_block=ctx.block,
            trace=[
                {
                    "step": "safe_signature_threshold" if hint.endswith("signatures") else "safe_modules",
                    "contract": ctx.contract_address,
                    "observed_at_block": ctx.block,
                    "source_identity": descriptor["source_identity"],
                }
            ],
        )
        cache[key] = cap
        return cap
