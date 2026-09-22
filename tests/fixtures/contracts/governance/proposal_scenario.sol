// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

contract ScenarioTarget {
    uint256 private delay = 172800;
    address public governor;

    constructor(address governor_) { governor = governor_; }
    function getMinDelay() external view returns (uint256) { return delay; }
    function updateDelay(uint256 value) external payable {
        require(msg.sender == governor, "not governor");
        delay = value;
    }
}

contract ScenarioGovernor {
    struct ProposalData {
        uint256 id;
        address proposer;
        address[] targets;
        uint256[] values;
        string[] signatures;
        bytes[] calldatas;
        uint256 start;
        uint256 end;
        string description;
    }
    event ProposalCreated(
        uint256 proposalId,
        address proposer,
        address[] targets,
        uint256[] values,
        string[] signatures,
        bytes[] calldatas,
        uint256 voteStart,
        uint256 voteEnd,
        string description
    );

    mapping(uint256 => uint256) private snapshots;
    mapping(uint256 => uint256) private deadlines;
    mapping(uint256 => bool) private created;

    function CLOCK_MODE() external pure returns (string memory) { return "mode=blocknumber&from=default"; }
    function votingPeriod() external pure returns (uint256) { return 100; }
    function proposalSnapshot(uint256 id) external view returns (uint256) { return snapshots[id]; }
    function proposalDeadline(uint256 id) external view returns (uint256) { return deadlines[id]; }
    function votingDelay() external pure returns (uint256) { return 5; }
    function proposalThreshold() external pure returns (uint256) { return 0; }

    function propose(address target, bytes calldata data, string calldata description) external returns (uint256) {
        address[] memory targets = new address[](1);
        targets[0] = target;
        uint256[] memory values = new uint256[](1);
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = data;
        bytes32 descriptionHash = keccak256(bytes(description));
        uint256 id = uint256(keccak256(abi.encode(targets, values, calldatas, descriptionHash)));
        uint256 start = block.number + 5;
        uint256 end = start + 100;
        snapshots[id] = start;
        deadlines[id] = end;
        created[id] = true;
        _announce(id, target, data, description, start, end, 0);
        return id;
    }

    function proposeValue(address target, bytes calldata data, string calldata description, uint256 amount)
        external returns (uint256)
    {
        address[] memory targets = new address[](1);
        targets[0] = target;
        uint256[] memory values = new uint256[](1);
        values[0] = amount;
        bytes[] memory calldatas = new bytes[](1);
        calldatas[0] = data;
        uint256 id = uint256(keccak256(abi.encode(targets, values, calldatas, keccak256(bytes(description)))));
        uint256 start = block.number + 5;
        snapshots[id] = start;
        deadlines[id] = start + 100;
        created[id] = true;
        _announce(id, target, data, description, start, start + 100, amount);
        return id;
    }

    function _announce(
        uint256 id, address target, bytes calldata data, string calldata description,
        uint256 start, uint256 end, uint256 amount
    ) internal {
        ProposalData memory proposal;
        proposal.id = id;
        proposal.proposer = msg.sender;
        proposal.targets = new address[](1);
        proposal.targets[0] = target;
        proposal.values = new uint256[](1);
        proposal.values[0] = amount;
        proposal.signatures = new string[](1);
        proposal.calldatas = new bytes[](1);
        proposal.calldatas[0] = data;
        proposal.start = start;
        proposal.end = end;
        proposal.description = description;
        bytes memory payload = abi.encode(proposal);
        bytes32 topic = keccak256(
            "ProposalCreated(uint256,address,address[],uint256[],string[],bytes[],uint256,uint256,string)"
        );
        // abi.encode(struct) adds a leading tuple offset; event data is the tuple body.
        assembly { log1(add(payload, 64), sub(mload(payload), 32), topic) }
    }

    function execute(
        address[] calldata targets, uint256[] calldata values, bytes[] calldata calldatas, bytes32 descriptionHash
    ) external payable {
        require(created[uint256(keccak256(abi.encode(targets, values, calldatas, descriptionHash)))], "no proposal");
        for (uint256 i = 0; i < targets.length; i++) {
            (bool success,) = targets[i].call{value: values[i]}(calldatas[i]);
            require(success, "action reverted");
        }
    }
}
