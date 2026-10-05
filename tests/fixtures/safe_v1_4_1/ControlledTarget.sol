// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.9.0;

contract ControlledTarget {
    address public immutable safe;
    uint256 public value;

    constructor(address controller) {
        safe = controller;
    }

    function setValue(uint256 next) external {
        require(msg.sender == safe, "only Safe");
        value = next;
    }
}
