// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// UUPS positive (EETH-class): OpenZeppelin UUPSUpgradeable exposes
// proxiableUUID() plus upgradeTo/upgradeToAndCall gated by _authorizeUpgrade,
// which EETH overrides onlyOwner. The proxiableUUID sibling is the UUPS gate.

abstract contract UUPSUpgradeable {
    event Upgraded(address indexed implementation);

    address private immutable __self = address(this);

    function proxiableUUID() external view virtual returns (bytes32) {
        return 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    }

    function upgradeTo(address newImplementation) external {
        _authorizeUpgrade(newImplementation);
        _upgradeToAndCallUUPS(newImplementation, new bytes(0));
    }

    function upgradeToAndCall(address newImplementation, bytes memory data) external payable {
        _authorizeUpgrade(newImplementation);
        _upgradeToAndCallUUPS(newImplementation, data);
    }

    function _upgradeToAndCallUUPS(address newImplementation, bytes memory data) private {
        _implementation = newImplementation;
        emit Upgraded(newImplementation);
        if (data.length > 0) {
            (bool ok,) = newImplementation.delegatecall(data);
            require(ok, "call failed");
        }
    }

    address internal _implementation;

    function _authorizeUpgrade(address newImplementation) internal virtual;
}

contract EETH is UUPSUpgradeable {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    uint256 public totalShares;

    function mintShares(address user, uint256 share) external {
        totalShares += share;
        shares[user] += share;
    }

    mapping(address => uint256) public shares;

    function _authorizeUpgrade(address) internal override onlyOwner {}
}
