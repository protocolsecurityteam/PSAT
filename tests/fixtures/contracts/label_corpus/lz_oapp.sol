// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// Synthetic LayerZero OApp with OZ-v5 (ERC-7201) namespaced storage. The OApp
// gate (setPeer(uint32,bytes32) + peers(uint32)) drives the lz_oapp.* config
// claims; setLockBox writes a namespaced pseudo-slot member (hygiene
// storage_location_pseudo), the callee_pointer near-miss that must NOT fire even
// though `lockBox` is an address-typed pointer.
contract LzOApp {
    /// @custom:storage-location erc7201:synthetic.storage.OApp
    struct OAppStorage {
        address lockBox;
        address delegate;
        mapping(uint32 => bytes32) peers;
    }

    // keccak256(abi.encode(uint256(keccak256("synthetic.storage.OApp")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant OAppStorageLocation =
        0x8f7a9d1e00000000000000000000000000000000000000000000000000000000;

    address public owner;

    event PeerSet(uint32 eid, bytes32 peer);
    event DelegateSet(address delegate);
    event LockBoxSet(address lockBox);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function _getOAppStorage() private pure returns (OAppStorage storage $) {
        assembly {
            $.slot := OAppStorageLocation
        }
    }

    function peers(uint32 eid) public view returns (bytes32) {
        return _getOAppStorage().peers[eid];
    }

    function setPeer(uint32 eid, bytes32 peer) public onlyOwner {
        _getOAppStorage().peers[eid] = peer;
        emit PeerSet(eid, peer);
    }

    function setDelegate(address delegate) public onlyOwner {
        _getOAppStorage().delegate = delegate;
        emit DelegateSet(delegate);
    }

    function setLockBox(address lockBox) public onlyOwner {
        _getOAppStorage().lockBox = lockBox;
        emit LockBoxSet(lockBox);
    }
}
