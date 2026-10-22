"""Every implementation an address has run, read from its upgrade events: what a claim that every write to a lookup
is logged has to hold for, since entries an earlier implementation set stay in storage after an upgrade.

Read for the proxy standards whose upgrades log the new implementation: EIP-1967 ``Upgraded`` (and a beacon's, after
``BeaconUpgraded``), Gnosis Safe ``ChangedMasterCopy``, Compound ``NewImplementation``, and an Aragon app's base in
its kernel's ``SetApp``. The history counts only when it was read whole and ends at the code running now; otherwise
it is unknown, and nothing about the address's lookups is complete.
"""

from __future__ import annotations

from typing import Any

from eth_utils.crypto import keccak

_UPGRADED = int.from_bytes(keccak(text="Upgraded(address)"), "big")
_BEACON_UPGRADED = int.from_bytes(keccak(text="BeaconUpgraded(address)"), "big")
_MASTER_COPY = int.from_bytes(keccak(text="ChangedMasterCopy(address)"), "big")
_NEW_IMPLEMENTATION = int.from_bytes(keccak(text="NewImplementation(address,address)"), "big")
_SET_APP = int.from_bytes(keccak(text="SetApp(bytes32,bytes32,address)"), "big")
_ARAGON_KERNEL = int.from_bytes(keccak(text="aragonOS.appStorage.kernel"), "big")
_ARAGON_APP_ID = int.from_bytes(keccak(text="aragonOS.appStorage.appId"), "big")
_ARAGON_BASES = int.from_bytes(keccak(text="base"), "big")


def _topic(value: int) -> str:
    return "0x" + format(value, "064x")


def implementations(chain: Any, address: int, running: int) -> list[int] | None:
    """The implementations ``address`` has run, oldest first, ending with ``running``; ``[address]`` for code that
    runs at its own address; ``None`` when the history can't be read whole or doesn't end at ``running``."""
    address %= 2**160
    running %= 2**160
    if running == address:
        return [address]
    subjects: list[int] = []
    found = _logged_implementations(chain, address, subjects=subjects)
    if found is None:
        return None
    if found:
        # The first one logged must be the one the proxy was made with: an implementation set without an event
        # before it (a constructor writing the slot itself) would have written entries no history shows.
        if not _anchored(chain, address, subjects[0]):
            return None
    else:
        # An Aragon app proxy keeps no implementation of its own: each call reads its kernel, whose apps are set
        # only by ``SetApp``.
        found = _aragon_bases(chain, address)
    if not found or found[-1] != running:
        return None
    return list(dict.fromkeys(found))


def _logged_implementations(
    chain: Any, address: int, depth: int = 0, subjects: list[int] | None = None
) -> list[int] | None:
    """The implementations the address's upgrade events name, in order (a beacon's behind it); ``subjects``
    receives what each event named directly (an implementation, or a beacon)."""
    kinds = (_UPGRADED, _BEACON_UPGRADED, _MASTER_COPY, _NEW_IMPLEMENTATION)
    topics = frozenset(_topic(t) for t in kinds)
    logs = chain.logs(address, topics)
    if chain.cut(address, topics):
        return None
    out: list[int] = []
    for log_topics, data in logs:
        if not log_topics:
            continue
        kind = log_topics[0]
        if kind in (_UPGRADED, _MASTER_COPY):
            # Indexed in EIP-1967; in the data for OpenZeppelin's legacy proxies and Gnosis Safe.
            word = log_topics[1] if len(log_topics) > 1 else data[0] if data else None
        elif kind == _NEW_IMPLEMENTATION:
            word = data[1] if len(data) > 1 else None
        elif kind == _BEACON_UPGRADED:
            beacon = log_topics[1] if len(log_topics) > 1 else data[0] if data else None
            if beacon is None or depth > 1:
                return None
            behind = _logged_implementations(chain, beacon % 2**160, depth + 1)
            if behind is None or not behind or not _anchored(chain, beacon % 2**160, behind[0]):
                return None
            out.extend(behind)
            if subjects is not None:
                subjects.append(beacon % 2**160)
            continue
        else:
            continue  # another event: not asked for
        if word is None:
            return None
        out.append(word % 2**160)
        if subjects is not None:
            subjects.append(word % 2**160)
    return out


# Where proxies keep what runs: EIP-1967's implementation and beacon, OpenZeppelin's legacy implementation, and
# slot 0 (Gnosis Safe's master copy, many hand-written proxies).
_IMPLEMENTATION_SLOTS = (
    int.from_bytes(keccak(text="eip1967.proxy.implementation"), "big") - 1,
    int.from_bytes(keccak(text="eip1967.proxy.beacon"), "big") - 1,
    int.from_bytes(keccak(text="org.zeppelinos.proxy.implementation"), "big"),
    0,
)


def _anchored(chain: Any, address: int, first: int) -> bool:
    """Whether ``first`` is what ``address`` was created running: named by the creating transaction (its calls'
    words, or the storage it left), or held in a proxy slot at the block the address was created in."""
    trace = chain.creation_trace(address)
    if trace is not None:
        words, storage = trace
        if first in {w % 2**160 for w in words} or first in {v % 2**160 for v in storage.values()}:
            return True
    block = chain.creation_block(address)
    if block is None:
        return False
    from .decide import _hex20

    for slot in _IMPLEMENTATION_SLOTS:
        raw = chain._get(("s_at", address, slot, block), "eth_getStorageAt", [_hex20(address), hex(slot), hex(block)])
        if isinstance(raw, str) and int(raw, 16) % 2**160 == first:
            return True
    return False


def _aragon_bases(chain: Any, address: int) -> list[int] | None:
    """An Aragon app proxy's bases: its kernel's ``SetApp`` for the base namespace and the app's id."""
    from .decide import UNK

    kernel, app_id = chain.storage(address, _ARAGON_KERNEL), chain.storage(address, _ARAGON_APP_ID)
    if kernel is UNK or app_id is UNK or not isinstance(kernel, int) or not kernel or not app_id:
        return None
    kernel %= 2**160
    topics = frozenset({_topic(_SET_APP)})
    logs = chain.logs(kernel, topics)
    if chain.cut(kernel, topics):
        return None
    out = [
        data[0] % 2**160
        for log_topics, data in logs
        if len(log_topics) > 2 and log_topics[1] == _ARAGON_BASES and log_topics[2] == app_id and data
    ]
    return out or None
