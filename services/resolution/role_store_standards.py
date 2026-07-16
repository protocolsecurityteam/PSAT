"""Recognized enumerable role-store standards — the single place a new one is added.

A delegated role gate (``roleRegistry.onlyOperatingMultisig(msg.sender)`` and its
siblings) resolves to its real controllers only if the pipeline knows (a) which
events carry the grant/revoke history to fold and (b) which runtime-bytecode
selectors confirm the store speaks a standard this pipeline models. This table is
consumed by BOTH the indexer's enrollment branch (``all_topic0s`` /
``detect_standards`` → which cursors to seed) and the Stage-2
``EnumerableRoleStoreAdapter`` (``matches`` / ``enumerate`` fold), so a future
protocol upgrade to a *recognized* standard lands enumerated automatically and an
upgrade to a *novel* one lands fail-closed-and-loud — the durability invariant in
CONTROLLER_RESOLUTION_SPEC.md §5.

Adding a standard = one ``RoleStoreStandard`` entry in ``STANDARDS``; everything
downstream (enrollment, fold, probe) is data-driven off it.

Selectors and topic0s are derived from their signatures (keccak) rather than
pinned as hex, and cross-checked against ``rolegate-fix-evidence/
roles_ground_truth.json`` (Solady ``RoleSet`` topic0
0xaddc47d7…758201b8, ``hasRole(address,uint256)`` 0x5c97f4a2, OZ
AccessControlEnumerable EIP-165 id 0x5a05180f).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeGuard

from eth_utils.crypto import keccak
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import Contract
from utils.rpc import default_rpc_url, get_code, parse_address_result, rpc_request

_ZERO_ADDRESS = "0x" + "0" * 40

# EIP-1967 implementation slot: keccak("eip1967.proxy.implementation") - 1.
EIP1967_IMPL_SLOT = "0x" + format(int.from_bytes(keccak(text="eip1967.proxy.implementation"), "big") - 1, "064x")


def _selector(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


def _topic0(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()


@dataclass(frozen=True)
class RoleEventSpec:
    """One grant/revoke event of a role-store standard, described so a generic
    fold can turn its log topics into a (holder, role, active) tuple.

    ``active_topic_index`` names the topic holding a bool active flag (Solady's
    ``RoleSet`` carries one at topic3); when it is ``None`` the event's own
    identity decides activation (``active_when``: OZ ``RoleGranted`` → True,
    ``RoleRevoked`` → False).
    """

    signature: str
    holder_topic_index: int
    role_topic_index: int
    active_topic_index: int | None
    active_when: bool | None

    @property
    def topic0(self) -> str:
        return _topic0(self.signature)


@dataclass(frozen=True)
class GetterSpec:
    """The standard's enumerable-getter walk — an optional consistency alarm for
    the adapter (fold is the source of truth; a getter mismatch declines loud).
    ``count_selector(role) -> uint256`` then ``at_selector(role, i) -> address``.
    """

    count_signature: str
    at_signature: str
    role_id_type: str  # "uint256" | "bytes32"

    @property
    def count_selector(self) -> str:
        return _selector(self.count_signature)

    @property
    def at_selector(self) -> str:
        return _selector(self.at_signature)


@dataclass(frozen=True)
class RoleStoreStandard:
    name: str
    marker_selectors: tuple[str, ...]  # ALL must appear in the impl's runtime bytecode
    grant_events: tuple[RoleEventSpec, ...]
    enumerable_getter: GetterSpec | None
    eip165_interface_id: str | None = None  # bonus adapter signal; not used for bytecode detection

    def topic0s(self) -> tuple[str, ...]:
        return tuple(ev.topic0 for ev in self.grant_events)


SOLADY_ENUMERABLE_ROLES = RoleStoreStandard(
    name="solady_enumerable_roles",
    marker_selectors=(
        _selector("roleHolderCount(uint256)"),
        _selector("roleHolders(uint256)"),
        _selector("roleHolderAt(uint256,uint256)"),
        _selector("hasRole(address,uint256)"),
    ),
    grant_events=(
        # RoleSet(address indexed holder, uint256 indexed role, bool indexed active)
        RoleEventSpec(
            signature="RoleSet(address,uint256,bool)",
            holder_topic_index=1,
            role_topic_index=2,
            active_topic_index=3,
            active_when=None,
        ),
    ),
    enumerable_getter=GetterSpec(
        count_signature="roleHolderCount(uint256)",
        at_signature="roleHolderAt(uint256,uint256)",
        role_id_type="uint256",
    ),
)

OZ_ACCESS_CONTROL_ENUMERABLE = RoleStoreStandard(
    name="oz_access_control_enumerable",
    marker_selectors=(
        _selector("getRoleMemberCount(bytes32)"),
        _selector("getRoleMember(bytes32,uint256)"),
        _selector("hasRole(bytes32,address)"),
    ),
    grant_events=(
        # RoleGranted/RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)
        RoleEventSpec(
            signature="RoleGranted(bytes32,address,address)",
            holder_topic_index=2,
            role_topic_index=1,
            active_topic_index=None,
            active_when=True,
        ),
        RoleEventSpec(
            signature="RoleRevoked(bytes32,address,address)",
            holder_topic_index=2,
            role_topic_index=1,
            active_topic_index=None,
            active_when=False,
        ),
    ),
    enumerable_getter=GetterSpec(
        count_signature="getRoleMemberCount(bytes32)",
        at_signature="getRoleMember(bytes32,uint256)",
        role_id_type="bytes32",
    ),
    eip165_interface_id="0x5a05180f",
)

STANDARDS: tuple[RoleStoreStandard, ...] = (SOLADY_ENUMERABLE_ROLES, OZ_ACCESS_CONTROL_ENUMERABLE)


def all_topic0s() -> list[str]:
    """The union of every standard's grant/revoke topic0s — the over-enroll set
    the indexer seeds when bytecode detection is inconclusive (a never-emitted
    cursor costs one empty scan window; a missed cursor kills the recall path)."""
    topics: set[str] = set()
    for standard in STANDARDS:
        topics.update(standard.topic0s())
    return sorted(topics)


def _selector_in_code(selector: str, body: str) -> bool:
    sel = selector.lower().removeprefix("0x")
    if len(sel) != 8:
        return False
    # solc emits each external function in the dispatcher as PUSH4 <selector>
    # (0x63); the bare-substring fallback covers unusual dispatchers. Mirrors
    # BytecodeSelectorRepo.has_selector so detection agrees with the adapter's probe.
    return ("63" + sel) in body or sel in body


def detect_standards(code_hex: str | None) -> list[RoleStoreStandard]:
    """Every standard whose full marker-selector set is present in ``code_hex``
    (a contract's runtime bytecode). ALL markers required — a partial match is
    inconclusive and falls to the caller's union-enroll fallback rather than
    risking a cross-standard false positive."""
    if not code_hex:
        return []
    body = code_hex.lower()
    return [s for s in STANDARDS if all(_selector_in_code(sel, body) for sel in s.marker_selectors)]


def _looks_like_address(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and value.startswith("0x") and len(value) == 42 and value.lower() != _ZERO_ADDRESS


def _code_at(address: str, chain_id: int, rpc_url: str | None) -> str | None:
    if not rpc_url:
        return None
    try:
        return get_code(rpc_url, address, chain_id=chain_id) or None
    except Exception:
        return None


def _impl_via_db(session: Session | None, address: str) -> str | None:
    if session is None:
        return None
    try:
        row = session.execute(
            select(Contract.implementation)
            .where(func.lower(Contract.address) == address.lower())
            .where(Contract.implementation.isnot(None))
            .limit(1)
        ).first()
    except Exception:
        return None
    impl = row[0] if row else None
    return impl.lower() if _looks_like_address(impl) else None


def _impl_via_slot(address: str, chain_id: int, rpc_url: str | None) -> str | None:
    if not rpc_url:
        return None
    try:
        raw = rpc_request(rpc_url, "eth_getStorageAt", [address, EIP1967_IMPL_SLOT, "latest"])
    except Exception:
        return None
    resolved = parse_address_result(raw)
    return resolved.lower() if _looks_like_address(resolved) else None


def resolve_probe_code(
    session: Session | None,
    authority: str,
    chain_id: int,
    *,
    rpc_url: str | None = None,
    max_hops: int = 2,
) -> str | None:
    """Runtime bytecode to run ``detect_standards`` against, following the proxy
    hop the registry needs: the PROXY stub carries no getter selectors, so DB-
    first via ``contracts.implementation`` (linkage proven on preview) → EIP-1967
    slot read → the terminal code. Bounded to ``max_hops`` implementation links
    (deeper → return whatever code we reached → no detection → guard, loud)."""
    if not _looks_like_address(authority):
        return None
    if rpc_url is None:
        rpc_url = default_rpc_url(chain_id=chain_id)
    addr = authority.lower()
    seen = {addr}
    code = _code_at(addr, chain_id, rpc_url)
    for _ in range(max_hops):
        impl = _impl_via_db(session, addr) or _impl_via_slot(addr, chain_id, rpc_url)
        if impl is None or impl in seen:
            break
        seen.add(impl)
        addr = impl
        code = _code_at(addr, chain_id, rpc_url) or code
    return code
