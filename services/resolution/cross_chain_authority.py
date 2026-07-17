"""Cross-chain authority recognition (invariant 15: label early, model late).

L2 deployments overwhelmingly hand ownership to an *aliased* L1 address or to an
OP-stack bridge predeploy. Left alone those principals classify as anonymous
EOAs / generic contracts — exactly the silent under-labeling invariant 15
forbids. This module recognises them from data that is already on hand: the
chain's registry constants (``ChainInfo.bridge_executors`` /
``cross_domain_messengers``) and the run's own set of known addresses. No
cross-chain RPC, no probing, no control edge — the recognition attaches a
*label* (``resolved_type == "cross_chain_authority"``) and, for an aliased
owner, the implied L1 address as a non-authoritative hint.

v1 is chain-as-island (inv. 15): the implied L1 address is a hint only, never a
control edge. Modeling real cross-chain edges is a later phase.

Chain scoping: recognition is a no-op on any chain whose registry entry carries
no bridge constants (today every chain except Base). Mainnet is therefore
provably untouched — the recognizer factory returns ``None`` for it and no
per-address work runs.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from utils.chains import ChainInfo, UnknownChainError, chain_by_id

# The principal classification value this module mints, sitting beside the
# existing kinds ("eoa", "safe", "timelock", "proxy_admin", "contract", ...).
CROSS_CHAIN_AUTHORITY_TYPE = "cross_chain_authority"

# Both OP-stack (Base) and Arbitrum apply this offset to an L1-contract sender
# when it appears on the L2: ``L2_alias = (L1_address + OFFSET) mod 2**160``.
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


def apply_l1_to_l2_alias(l1_address: str | None) -> str | None:
    """The L2 alias of an L1 address (``L1 + OFFSET mod 2**160``), or ``None`` if
    *l1_address* is not a well-formed hex address."""
    norm = _normalize(l1_address)
    if norm is None:
        return None
    aliased = (int(norm, 16) + L1_TO_L2_ALIAS_OFFSET) % _ADDRESS_SPACE
    return f"0x{aliased:040x}"


def undo_l1_to_l2_alias(l2_address: str | None) -> str | None:
    """The L1 address implied by an aliased L2 address (``L2 - OFFSET mod
    2**160``), or ``None`` if *l2_address* is not a well-formed hex address.

    The transform is not on its own evidence that *l2_address* is an alias — any
    address minus the offset is *some* address. It is only meaningful when the
    result is a member of the run's known-address set (see
    :func:`classify_cross_chain_authority`)."""
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

    Returns ``(CROSS_CHAIN_AUTHORITY_TYPE, details)`` where ``details.role`` is
    one of ``"cross_domain_messenger"``, ``"bridge_executor"``,
    ``"aliased_l1_owner"`` — or ``None`` when *address* is not a recognised
    cross-chain authority. Recognition is skipped entirely on a chain with no
    bridge constants, so a mainnet caller always gets ``None``.

    ``known_addresses`` is this run's resolution scope: the aliased-owner case
    fires only when the implied L1 address (``address - OFFSET``) is a member of
    it, which is what keeps the arithmetic from labelling arbitrary addresses.
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
                # Hint only (inv. 15): the L1 principal this alias stands in for.
                # NOT a control edge — v1 is chain-as-island.
                "implied_l1_address": implied,
            }
    return None


def make_cross_chain_recognizer(
    chain_id: int | None,
    known_addresses: Iterable[str] = (),
) -> Callable[[str], tuple[str, dict[str, object]] | None] | None:
    """Bind a single-argument ``address -> (resolved_type, details) | None``
    recognizer to a chain and its run scope, or return ``None`` when the chain
    has no bridge constants (mainnet and every not-yet-enabled chain).

    Returning ``None`` — rather than a recognizer that always misses — is the
    signal callers use to keep their mainnet path byte-identical: they only wire
    a recognizer in when one exists.
    """
    try:
        info = chain_by_id(int(chain_id))  # type: ignore[arg-type]
    except (UnknownChainError, TypeError, ValueError):
        return None
    if not (info.bridge_executors or info.cross_domain_messengers):
        return None
    known = frozenset(a.lower() for a in known_addresses if isinstance(a, str) and a)

    def _recognize(address: str) -> tuple[str, dict[str, object]] | None:
        return classify_cross_chain_authority(address, chain_info=info, known_addresses=known)

    return _recognize
