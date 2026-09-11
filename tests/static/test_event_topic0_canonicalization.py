"""Regression: event ``topic0`` must keccak the canonical ABI signature.

An event's ``topic0`` is ``keccak(canonical-ABI-signature)``, where every
non-elementary parameter collapses to its ABI head: contract/interface ->
``address``, enum -> ``uint8``, user-defined value type -> its underlying
elementary type, array ``T[]`` -> ``canonical(T)[]``, struct -> the
parenthesized member tuple. Both topic0 producers used to derive the signature
from Slither's *declared* type names (``Event.full_name`` /
``str(type)`` -> ``IGem``, ``Vat.Status``, ``IGem[]``, ``PoolId``), so the
keccak'd topic0 matched ZERO on-chain logs and the privileged-mapping allowlist
enumerated EMPTY (status=complete) -> the tool UNDER-reported privilege holders.

These tests compile the events with real Slither and assert the canonicalizer
produces the signature whose keccak equals the REAL on-chain ``topic0`` of
production events (Seaport ``OrderFulfilled``, Uniswap-v4 ``Initialize``,
ERC-1155 ``TransferBatch``, Maker-style ``Rely``). The on-chain topic0 constants
are independently sourced; the canonicalizer derives them generically from the
compiled types (no expected string is hardcoded in the producer).
"""

from __future__ import annotations

import textwrap

import pytest
from eth_utils.crypto import keccak

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.static_analysis import tracking  # noqa: E402
from services.static.static_analysis.mapping_events import (  # noqa: E402
    _abi_type,
    _event_metadata,
)

# Real on-chain ``topic0`` values (keccak of the canonical signature solc/the
# chain assign), sourced independently of this pipeline. A wrong topic0 returns
# zero logs for these events — the exact bug.
RELY = "0xdd0e34038ac38b2a1ce960229778ac48a8719bc900b6c4f8d0475c6e8b385a60"
ORDER_FULFILLED = "0x9d9af8e38d66c62e2c12f0225249fd9d721c54b83f48d9352c97c6cacdcb6f31"
INITIALIZE = "0xdd466e674ea557f56295e2d0218a125ea4b4f0f6f3307b95f85e6110838d6438"
TRANSFER_BATCH = "0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb"

# Canonical signatures whose keccak equal the constants above.
CANONICAL = {
    "Rely": "Rely(address)",
    "OrderFulfilled": (
        "OrderFulfilled(bytes32,address,address,address,"
        "(uint8,address,uint256,uint256)[],"
        "(uint8,address,uint256,uint256,address)[])"
    ),
    "Initialize": "Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)",
    "TransferBatch": "TransferBatch(address,address,address,uint256[],uint256[])",
    # Fixed and nested fixed arrays of an interface — exact-match anchor.
    "Fixed": "Fixed(address[2],address[][2])",
}

ON_CHAIN = {
    "Rely": RELY,
    "OrderFulfilled": ORDER_FULFILLED,
    "Initialize": INITIALIZE,
    "TransferBatch": TRANSFER_BATCH,
}

# Faithful re-declaration of the production events with their real parameter
# types: Maker ``Rely(IGem)``, Seaport ``OrderFulfilled`` (enum + struct + array
# + ``address payable`` member), Uniswap-v4 ``Initialize`` (``PoolId``/``Currency``
# UDVTs + ``IHooks`` interface), ERC-1155 ``TransferBatch`` (elementary-only,
# proves the no-op path), and fixed/nested arrays of an interface.
SOURCE = """
pragma solidity ^0.8.19;

interface IGem {}
interface IHooks {}
type PoolId is bytes32;
type Currency is address;

enum ItemType { NATIVE, ERC20, ERC721, ERC1155, ERC721_WITH_CRITERIA, ERC1155_WITH_CRITERIA }
struct SpentItem { ItemType itemType; address token; uint256 identifier; uint256 amount; }
struct ReceivedItem { ItemType itemType; address token; uint256 identifier; uint256 amount; address payable recipient; }

contract Probe {
    event Rely(IGem indexed usr);
    event OrderFulfilled(
        bytes32 orderHash,
        address indexed offerer,
        address indexed zone,
        address recipient,
        SpentItem[] offer,
        ReceivedItem[] consideration
    );
    event Initialize(
        PoolId indexed id,
        Currency indexed currency0,
        Currency indexed currency1,
        uint24 fee,
        int24 tickSpacing,
        IHooks hooks,
        uint160 sqrtPriceX96,
        int24 tick
    );
    event TransferBatch(
        address indexed operator, address indexed from, address indexed to, uint256[] ids, uint256[] values
    );
    event Fixed(IGem[2] pair, IGem[][2] nested);

    function touch() external { emit Rely(IGem(address(0))); }
}
"""


def _topic0(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()


@pytest.fixture(scope="module")
def events(tmp_path_factory) -> dict[str, object]:
    tmp = tmp_path_factory.mktemp("event_topic0")
    f = tmp / "Probe.sol"
    f.write_text(textwrap.dedent(SOURCE).strip() + "\n")
    contract = next(c for c in Slither(str(f)).contracts if c.name == "Probe")
    return {ev.name: ev for ev in contract.events}


@pytest.mark.parametrize("event_name", sorted(CANONICAL))
def test_mapping_events_topic0_is_canonical(events, event_name):
    """``mapping_events._event_metadata`` (writer-event allowlist producer)."""
    md = _event_metadata(events[event_name])
    assert md is not None
    assert md["signature"] == CANONICAL[event_name]
    if event_name in ON_CHAIN:
        assert _topic0(md["signature"]) == ON_CHAIN[event_name]


@pytest.mark.parametrize("event_name", sorted(CANONICAL))
def test_tracking_topic0_is_canonical(events, event_name):
    """``tracking._event_reference`` (runtime wss_logs watch-plan producer)."""
    ref = tracking._event_reference(events[event_name])
    assert ref["signature"] == CANONICAL[event_name]
    assert ref["topic0"] == _topic0(CANONICAL[event_name])
    if event_name in ON_CHAIN:
        assert ref["topic0"] == ON_CHAIN[event_name]


def test_declared_name_signatures_would_miss_onchain_logs(events):
    """Revert-proof: the OLD ``full_name`` (declared-name) signatures keccak to a
    topic0 that does NOT match the real on-chain one for every non-elementary
    event — re-introducing them would re-create the under-report bug."""
    for name in ("Rely", "OrderFulfilled", "Initialize"):
        full_name = events[name].full_name
        assert _topic0(full_name) != ON_CHAIN[name]


def test_elementary_only_event_is_byte_identical(events):
    """No behavior change for elementary-only events: the canonical signature
    equals Slither's ``full_name`` (the legacy producer output)."""
    ev = events["TransferBatch"]
    md = _event_metadata(ev)
    assert md is not None
    assert md["signature"] == ev.full_name
    assert tracking._event_signature(ev) == ev.full_name


def test_abi_type_collapses_each_non_elementary_shape(events):
    """Unit-level: each producer's ``_abi_type`` lowers interface/enum/UDVT/array/
    struct to its canonical ABI head."""
    of = events["OrderFulfilled"]
    spent = next(e for e in of.elems if e.name == "offer").type  # SpentItem[]
    assert _abi_type(spent) == "(uint8,address,uint256,uint256)[]"
    assert tracking._abi_type(spent) == "(uint8,address,uint256,uint256)[]"

    init = events["Initialize"]
    pool_id = next(e for e in init.elems if e.name == "id").type  # PoolId (UDVT bytes32)
    hooks = next(e for e in init.elems if e.name == "hooks").type  # IHooks interface
    assert _abi_type(pool_id) == "bytes32"
    assert _abi_type(hooks) == "address"
