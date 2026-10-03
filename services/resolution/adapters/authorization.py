"""Resolve source-derived signer registries and thresholds from storage at one pinned block."""

from __future__ import annotations

from dataclasses import replace

from eth_abi.abi import encode
from eth_utils.crypto import keccak

from services.clients.rpc import rpc_request

from ..capabilities import CapabilityExpr, ExternalCheck
from . import EvaluationContext

_MAX_LINKED_MEMBERS = 256


class AuthorizationAdapter:
    @classmethod
    def matches(cls, descriptor: dict, ctx: EvaluationContext) -> int:
        del ctx
        if descriptor.get("kind") == "signature_threshold" and descriptor.get("registry"):
            return 100
        if descriptor.get("kind") == "mapping_membership" and descriptor.get("membership_inventory"):
            return 95
        return 0

    @classmethod
    def supports_external_check_only(cls) -> bool:
        return True

    def enumerate(self, descriptor: dict, ctx: EvaluationContext) -> CapabilityExpr:
        address, block, rpc_url = ctx.contract_address, ctx.block, ctx.rpc_url
        fallback = CapabilityExpr.external_check_only(
            ExternalCheck(
                target_address=address,
                target_call_selector=None,
                extra={"basis": ["caller_tainted_authority_unresolved", "authorization_storage_unavailable"]},
            )
        )
        if not address or not isinstance(block, int) or not rpc_url:
            return fallback
        cache = ctx.meta.setdefault("live_read_memo", {})
        key = ("authorization", address.lower(), block, repr(descriptor))
        if key in cache:
            return cache[key]
        try:
            if descriptor.get("kind") == "signature_threshold":
                registry = descriptor["registry"]
                members = _read_inventory(rpc_url, address, block, registry, ctx.chain_id)
                threshold = _read_scalar(rpc_url, address, block, descriptor["threshold"], ctx.chain_id)
                if not members or threshold <= 0 or threshold > len(members):
                    return fallback
                cap = CapabilityExpr.threshold_group(threshold, members)
                step = "source_signature_threshold"
            else:
                members = _read_inventory(rpc_url, address, block, descriptor["membership_inventory"], ctx.chain_id)
                cap = CapabilityExpr.finite_set(members)
                step = "source_membership_inventory"
        except (KeyError, TypeError, ValueError, RuntimeError):
            return fallback
        cap = replace(
            cap,
            last_indexed_block=block,
            trace=[
                {
                    "step": step,
                    "contract": address.lower(),
                    "observed_at_block": block,
                    "basis": "source-derived storage inventory",
                }
            ],
        )
        cache[key] = cap
        return cap


def _storage(rpc_url: str, address: str, block: int, slot: int, chain_id: int | None) -> int:
    raw = rpc_request(
        rpc_url,
        "eth_getStorageAt",
        [address.lower(), hex(slot), hex(block)],
        retries=1,
        chain_id=chain_id,
    )
    if not isinstance(raw, str) or not raw.startswith("0x"):
        raise RuntimeError("malformed storage result")
    return int(raw, 16)


def _read_scalar(rpc_url: str, address: str, block: int, descriptor: dict, chain_id: int | None) -> int:
    if descriptor.get("kind") == "constant":
        return int(descriptor["value"])
    if descriptor.get("kind") != "storage":
        raise ValueError("unsupported threshold source")
    word = _storage(rpc_url, address, block, int(descriptor["slot"], 0), chain_id)
    offset = int(descriptor.get("byte_offset") or 0)
    size = int(descriptor.get("size_bytes") or 32)
    if offset < 0 or size <= 0 or offset + size > 32:
        raise ValueError("invalid packed storage range")
    return (word >> (offset * 8)) & ((1 << (size * 8)) - 1)


def _read_inventory(rpc_url: str, address: str, block: int, descriptor: dict, chain_id: int | None) -> list[str]:
    if descriptor.get("kind") != "linked_list":
        raise ValueError("unsupported membership inventory")
    mapping_slot = int(descriptor["slot"], 0)
    sentinel = int(descriptor["sentinel"], 0)
    if sentinel <= 0 or sentinel >= 1 << 160:
        raise ValueError("invalid linked-list sentinel")
    members: list[str] = []
    seen = {sentinel}
    current = sentinel
    for _ in range(_MAX_LINKED_MEMBERS + 1):
        location = int.from_bytes(keccak(encode(["address", "uint256"], [_address(current), mapping_slot])), "big")
        current = _storage(rpc_url, address, block, location, chain_id) & ((1 << 160) - 1)
        if current == sentinel:
            return members
        if current == 0 or current in seen:
            raise RuntimeError("malformed linked membership list")
        seen.add(current)
        members.append(_address(current))
    raise RuntimeError("linked membership list exceeds bound")


def _address(value: int) -> str:
    return "0x" + value.to_bytes(20, "big").hex()
