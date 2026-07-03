// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Adversarial near-miss NEGATIVE for exec.arbitrary: a body-origin external
// call whose destination is a parameter (address to) but whose calldata is not
// caller-supplied — the value send carries empty calldata. Address-tainted
// destination alone is not arbitrary execution, so no exec.arbitrary claim.

contract PayableToken {
    mapping(address => uint256) public balanceOf;

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        (bool ok,) = to.call{value: amount}("");
        require(ok, "send failed");
        return true;
    }

    function withdraw(address payable to, uint256 amount) external {
        (bool ok,) = to.call{value: amount}("");
        require(ok, "send failed");
    }
}
