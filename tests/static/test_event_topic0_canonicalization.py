"""Regression: event ``topic0`` must keccak the canonical ABI signature.

Non-elementary params collapse to their ABI head (contract -> ``address``, enum ->
``uint8``, UDVT -> underlying, ``T[]`` -> ``canonical(T)[]``, struct -> member
tuple). Both topic0 producers used to keccak Slither's *declared* type names, which
matched ZERO on-chain logs, so the privileged-mapping allowlist enumerated EMPTY
(status=complete) and the tool UNDER-reported privilege holders.

Tests assert the canonicalizer's keccak equals the REAL on-chain ``topic0`` of
production events (Seaport, Uniswap-v4, ERC-1155, Maker-style); the constants are
independently sourced, nothing is hardcoded in the producer.
"""

from __future__ import annotations

import textwrap

import pytest
from eth_utils.crypto import keccak

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline import tracking  # noqa: E402
from services.static.contract_analysis_pipeline.mapping_events import (  # noqa: E402
    _event_metadata,
)

# Real on-chain ``topic0`` values, sourced independently of this pipeline. A wrong
# topic0 returns zero logs for these events, the exact bug.
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
# types (ERC-1155 ``TransferBatch`` is elementary-only and proves the no-op path).
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
    md = _event_metadata(events[event_name])
    assert md is not None
    assert md["signature"] == CANONICAL[event_name]
    if event_name in ON_CHAIN:
        assert _topic0(md["signature"]) == ON_CHAIN[event_name]


@pytest.mark.parametrize("event_name", sorted(CANONICAL))
def test_tracking_topic0_is_canonical(events, event_name):
    ref = tracking._event_reference(events[event_name])
    assert ref["signature"] == CANONICAL[event_name]
    assert ref["topic0"] == _topic0(CANONICAL[event_name])
    if event_name in ON_CHAIN:
        assert ref["topic0"] == ON_CHAIN[event_name]
