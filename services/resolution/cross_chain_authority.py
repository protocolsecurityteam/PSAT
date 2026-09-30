"""Cross-chain authority recognition (invariant 15: label early, model late).

L2 deployments often hand ownership to an aliased L1 address or an OP-stack bridge predeploy, which would otherwise
classify as anonymous EOAs or contracts. Recognition uses the chain registry (``ChainInfo.bridge_executors`` /
``cross_domain_messengers``) and the run's known addresses, with no RPC. It attaches a label (``resolved_type ==
"cross_chain_authority"``) and, for aliased owners, the implied L1 address as a hint, never a control edge.

A no-op on chains without bridge constants (all but Base today), so mainnet is untouched.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from utils.chains import ChainInfo, UnknownChainError, chain_by_id

CROSS_CHAIN_AUTHORITY_TYPE = "cross_chain_authority"

# OP-stack and Arbitrum alias L1 senders as ``(L1_address + OFFSET) mod 2**160``.
L1_TO_L2_ALIAS_OFFSET = 0x1111000000000000000000000000000000001111
_ADDRESS_SPACE = 1 << 160


def _normalize(address: str | None) -> str | None:
    if not isinstance(address, str):
        return None
    norm = address.strip().lower()
    if not (norm.startswith("0x") and len(norm) == 42):
        return None
    try:
        int(norm, 16)
    except ValueError:
        return None
    return norm


def undo_l1_to_l2_alias(l2_address: str | None) -> str | None:
    """The L1 address implied by an aliased L2 address, or ``None`` if malformed.

    Only meaningful when the result is a known address (see :func:`classify_cross_chain_authority`).
    """
    norm = _normalize(l2_address)
    if norm is None:
        return None
    implied = (int(norm, 16) - L1_TO_L2_ALIAS_OFFSET) % _ADDRESS_SPACE
    return f"0x{implied:040x}"


def classify_cross_chain_authority(
    address: str,
    *,
    chain_info: ChainInfo,
    known_addresses: Iterable[str] = (),
) -> tuple[str, dict[str, object]] | None:
    """Recognise *address* as a cross-chain authority on *chain_info*'s chain.

    Returns ``(CROSS_CHAIN_AUTHORITY_TYPE, details)`` with ``details.role`` one of ``"cross_domain_messenger"``,
    ``"bridge_executor"``, ``"aliased_l1_owner"``, or ``None``. The aliased case fires only when the implied L1 address
    is in ``known_addresses``.
    """
    if not (chain_info.bridge_executors or chain_info.cross_domain_messengers):
        return None
    norm = _normalize(address)
    if norm is None:
        return None

    if norm in {a.lower() for a in chain_info.cross_domain_messengers}:
        return CROSS_CHAIN_AUTHORITY_TYPE, {"address": norm, "role": "cross_domain_messenger"}
    if norm in {a.lower() for a in chain_info.bridge_executors}:
        return CROSS_CHAIN_AUTHORITY_TYPE, {"address": norm, "role": "bridge_executor"}

    known = {a.lower() for a in known_addresses if isinstance(a, str)}
    if known:
        implied = undo_l1_to_l2_alias(norm)
        if implied is not None and implied in known:
            return CROSS_CHAIN_AUTHORITY_TYPE, {
                "address": norm,
                "role": "aliased_l1_owner",
                # Hint only (inv. 15), not a control edge.
                "implied_l1_address": implied,
            }
    return None


def make_cross_chain_recognizer(
    chain_id: int | None,
    known_addresses: Iterable[str] = (),
) -> Callable[[str], tuple[str, dict[str, object]] | None] | None:
    """A recognizer bound to a chain and run scope, or ``None`` when the chain has no bridge constants, so callers
    keep the mainnet path unchanged.
    """
    try:
        info = chain_by_id(int(chain_id))  # pyright: ignore[reportArgumentType]
    except (UnknownChainError, TypeError, ValueError):
        return None
    if not (info.bridge_executors or info.cross_domain_messengers):
        return None
    known = frozenset(a.lower() for a in known_addresses if isinstance(a, str) and a)

    def _recognize(address: str) -> tuple[str, dict[str, object]] | None:
        return classify_cross_chain_authority(address, chain_info=info, known_addresses=known)

    return _recognize
