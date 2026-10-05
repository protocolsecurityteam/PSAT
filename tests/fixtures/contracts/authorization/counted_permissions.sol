// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
contract CountedPermissions {
    address internal constant HEAD = address(1);
    mapping(address => address) internal participants;
    mapping(bytes32 => mapping(address => uint256)) internal approvals;
    uint256 internal minimum;
    uint256 internal size;
    constructor(address[] memory people, uint256 required) {
        address cursor = HEAD;
        for (uint256 i; i < people.length; ++i) { participants[cursor] = people[i]; cursor = people[i]; }
        participants[cursor] = HEAD; minimum = required; size = people.length;
    }
    function approve(bytes32 action) external {
        require(participants[msg.sender] != address(0));
        approvals[action][msg.sender] = 1;
    }
    function revoke(bytes32 action, address who) external { delete approvals[action][who]; }
    function execute(address target, bytes calldata payload) external {
        bytes32 action = keccak256(abi.encode(target, payload));
        checkApprovals(action);
        (bool ok,) = target.call(payload); require(ok);
    }
    function checkApprovals(bytes32 action) internal {
        uint256 count = 0;
        address person = participants[HEAD];
        while (person != HEAD) {
            if (person == msg.sender || approvals[action][person] != 0) {
                approvals[action][person] = 0;
                count++;
            }
            person = participants[person];
        }
        require(count >= minimum);
    }
    function list() external view returns (address[] memory result) {
        result = new address[](size);
        address cursor = participants[HEAD]; uint256 i;
        while (cursor != HEAD) { result[i++] = cursor; cursor = participants[cursor]; }
    }
}
