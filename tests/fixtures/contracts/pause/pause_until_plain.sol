// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// A timed pause in plain storage: the owner arms a uint64 timestamp to now + a caller-chosen window and every
// state-changing entry point requires the clock to have passed it. `delete` lifts it early; `setPause` does either.
contract PlainPauseUntil {
    address public owner;
    uint64 public pausedUntil;
    mapping(address => uint256) public balanceOf;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier whenNotPaused() {
        require(block.timestamp > pausedUntil, "paused");
        _;
    }

    function pauseFor(uint64 duration) external onlyOwner {
        pausedUntil = uint64(block.timestamp) + duration;
    }

    function unpause() external onlyOwner {
        delete pausedUntil;
    }

    function setPause(bool on, uint64 duration) external onlyOwner {
        if (on) {
            pausedUntil = uint64(block.timestamp) + duration;
        } else {
            pausedUntil = 0;
        }
    }

    function deposit() external payable whenNotPaused {
        balanceOf[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external whenNotPaused {
        balanceOf[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}

// The OZ Pausable ABI over a timestamp latch: the standard describes a bool flag, so the claim stays idiom-tier.
contract OzAbiPauseUntil {
    address public owner;
    uint256 public pausedUntil;
    mapping(address => uint256) public balanceOf;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function paused() public view returns (bool) {
        return pausedUntil >= block.timestamp;
    }

    function pause() external onlyOwner {
        pausedUntil = block.timestamp + 1 days;
    }

    function unpause() external onlyOwner {
        pausedUntil = 0;
    }

    function transfer(address to, uint256 amount) external {
        require(pausedUntil < block.timestamp, "paused");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}
