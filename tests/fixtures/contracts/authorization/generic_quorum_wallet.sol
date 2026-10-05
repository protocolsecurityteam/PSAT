// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract GenericQuorumWallet {
    error InvalidAuthorization();

    address internal constant HEAD = address(1);
    mapping(address => address) internal signerLinks;
    uint256 internal signerCount;
    uint256 internal minimumApprovals;

    constructor(address[] memory initialSigners, uint256 minimum) {
        signerLinks[HEAD] = HEAD;
        address cursor = HEAD;
        for (uint256 i; i < initialSigners.length; i++) {
            signerLinks[cursor] = initialSigners[i];
            cursor = initialSigners[i];
        }
        signerLinks[cursor] = HEAD;
        signerCount = initialSigners.length;
        minimumApprovals = minimum;
    }

    function execute(address target, bytes calldata payload, uint256 actionNonce, bytes calldata signatures)
        external
    {
        bytes32 digest = actionDigest(target, payload, actionNonce);
        validateBundle(msg.sender, digest, signatures, minimumApprovals);
        (bool ok,) = target.call(payload);
        require(ok);
    }

    function actionDigest(address target, bytes calldata payload, uint256 actionNonce)
        public
        pure
        returns (bytes32 digest)
    {
        bytes32 payloadHash = keccak256(payload);
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, target)
            mstore(add(ptr, 32), payloadHash)
            mstore(add(ptr, 64), actionNonce)
            digest := keccak256(ptr, 96)
        }
    }

    function validateBundle(address, bytes32 digest, bytes calldata signatures, uint256 needed) public view {
        if (needed == 0 || signatures.length < needed * 65) revert InvalidAuthorization();
        address previous = address(0);
        for (uint256 i = 0; i < needed; i++) {
            (uint8 v, bytes32 r, bytes32 s) = split(signatures, i);
            address candidate = ecrecover(digest, v, r, s);
            if (candidate <= previous || signerLinks[candidate] == address(0) || candidate == HEAD) {
                revert InvalidAuthorization();
            }
            previous = candidate;
        }
    }

    function split(bytes calldata signatures, uint256 pos) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        uint256 offset = pos * 65;
        assembly {
            r := calldataload(add(signatures.offset, offset))
            s := calldataload(add(add(signatures.offset, offset), 32))
            v := byte(0, calldataload(add(add(signatures.offset, offset), 64)))
        }
    }

    function signerInventory() external view returns (address[] memory result) {
        result = new address[](signerCount);
        address cursor = signerLinks[HEAD];
        uint256 index;
        while (cursor != HEAD) {
            result[index] = cursor;
            cursor = signerLinks[cursor];
            index++;
        }
    }
}
