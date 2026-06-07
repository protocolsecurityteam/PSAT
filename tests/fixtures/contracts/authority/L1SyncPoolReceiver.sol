// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// PSAT regression fixture — faithful to ether.fi L1BaseSyncPoolUpgradeable
//   (the base of L1SyncPoolETH 0x39272ee125ebd9214404f735baae50acb9d334c0 and the
//    other four L1/SyncPool receivers, Etherscan-verified, mainnet, solc 0.8.24).
// Why it's here: `onMessageReceived` gates on `msg.sender == $.receivers[originEid]`
//   — a `mapping(uint32 => address)` keyed by a FUNCTION PARAMETER, inside ERC-7201
//   namespaced storage (claim #3 group C). There is no single getter to read: the
//   authorized caller is whichever receiver the (param) eid maps to. Resolution
//   recovers the principal set by ENUMERATING the mapping's value set from its
//   `ReceiverSet` setter events (mapping value enumeration). See
//   tests/test_param_keyed_mapping_enumeration.py.
//
// The namespaced storage struct (assembly `$.slot := <constant>`), the verbatim
// gate, the `setReceiver`→`_setReceiver` writer, and the
// `ReceiverSet(uint32 indexed, address)` event (key indexed in topic1, value in
// data) are reproduced exactly so the discovered WriterEventSpec
// (key_position=0, value_position=1, indexed_positions=[0], direction="set") and
// the equality operand shape match the on-chain contract. The LayerZero / OZ
// upgradeable bases are replaced by a minimal `_Ownable` so the fixture is
// self-contained; the `onlyOwner` setter gate is incidental to group C.

contract _Ownable {
    address private _owner;

    constructor() {
        _owner = msg.sender;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    modifier onlyOwner() {
        require(msg.sender == _owner, "not owner");
        _;
    }
}

contract L1SyncPoolReceiver is _Ownable {
    struct L1BaseSyncPoolStorage {
        address tokenOut;
        address lockBox;
        uint256 totalUnbackedTokens;
        mapping(uint32 => address) receivers;
    }

    // keccak256(abi.encode(uint256(keccak256("syncpools.storage.l1basesyncpool")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant L1BaseSyncPoolStorageLocation =
        0xd96cd964f71a052084af61290ff53294a8f76de4d8f66ba7682fe6598635ef00;

    function _getL1BaseSyncPoolStorage() internal pure returns (L1BaseSyncPoolStorage storage $) {
        assembly {
            $.slot := L1BaseSyncPoolStorageLocation
        }
    }

    error L1BaseSyncPool__UnauthorizedCaller();

    event ReceiverSet(uint32 indexed originEid, address receiver);

    // Public getter exists on-chain but takes the eid as an argument, so it can't
    // be read with empty calldata — the principal set still requires enumeration.
    function getReceiver(uint32 originEid) public view virtual returns (address) {
        L1BaseSyncPoolStorage storage $ = _getL1BaseSyncPoolStorage();
        return $.receivers[originEid];
    }

    // Group C: the authorized caller is `receivers[originEid]`, a mapping keyed by
    // the `originEid` parameter. Verbatim from the on-chain source.
    function onMessageReceived(uint32 originEid, bytes32 guid, address tokenIn, uint256 amountIn, uint256 amountOut)
        public
        payable
        virtual
    {
        L1BaseSyncPoolStorage storage $ = _getL1BaseSyncPoolStorage();

        if (msg.sender != $.receivers[originEid]) revert L1BaseSyncPool__UnauthorizedCaller();

        guid;
        tokenIn;
        amountIn;
        amountOut;
    }

    function setReceiver(uint32 originEid, address receiver) public virtual onlyOwner {
        _setReceiver(originEid, receiver);
    }

    // Precision boundary (NOT in the real contract): a caller gate on the same
    // mapping read by a CONSTANT key — not a caller-chosen parameter — has no
    // value set to enumerate per caller, so it must NOT be stamped as a
    // param-keyed authority mapping. Guards the static pass against over-matching.
    function defaultReceiverGate() public view {
        L1BaseSyncPoolStorage storage $ = _getL1BaseSyncPoolStorage();
        if (msg.sender != $.receivers[0]) revert L1BaseSyncPool__UnauthorizedCaller();
    }

    function _setReceiver(uint32 originEid, address receiver) internal virtual {
        L1BaseSyncPoolStorage storage $ = _getL1BaseSyncPoolStorage();
        $.receivers[originEid] = receiver;

        emit ReceiverSet(originEid, receiver);
    }
}
