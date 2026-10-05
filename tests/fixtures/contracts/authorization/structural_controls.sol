// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract StructuralControls {
    address public owner;
    mapping(address => bool) public operators;
    mapping(address => uint256) public credits;
    mapping(bytes32 => uint256) public scheduled;
    uint256 public supply;
    uint256 public limit;
    bool public paused;

    constructor() { owner = msg.sender; }
    function authorize() internal view { require(msg.sender == owner); }
    function grant(address who) external { authorize(); operators[who] = true; }
    function revoke(address who) external { authorize(); operators[who] = false; }
    function setLimit(uint256 next) external { authorize(); limit = next; }
    function deposit() external payable { credits[msg.sender] += msg.value; }
    function mint(uint256 amount) external { require(operators[msg.sender]); supply += amount; }
    function schedule(bytes32 action, uint256 when) external { authorize(); scheduled[action] = when; }
    function run(address target, bytes calldata payload) external {
        bytes32 action = keccak256(abi.encode(target, payload));
        require(scheduled[action] != 0 && block.timestamp >= scheduled[action]);
        delete scheduled[action];
        (bool ok,) = target.call(payload); require(ok);
    }
    function mixed(bool withdraw, address target, bytes calldata payload, uint256 amount) external {
        if (withdraw) {
            require(amount <= credits[msg.sender]);
            credits[msg.sender] -= amount;
            (bool ok,) = msg.sender.call{value: amount}(""); require(ok);
        } else {
            authorize();
            (bool ok,) = target.call(payload); require(ok);
        }
    }
    function pause(bool value) external { authorize(); paused = value; }
    function publicWhenReady() external view { require(!paused); }
}
