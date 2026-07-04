// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Timelock positive (OZ TimelockController-class): the gate is the
// getMinDelay + schedule + execute sibling triple plus the hashOperation
// marker. schedule/execute/cancel/updateDelay map to per-selector timelock.*
// claims; execute/executeBatch additionally forward caller-supplied target +
// calldata, so they also carry exec.arbitrary.

contract TimelockController {
    mapping(bytes32 => uint256) private _timestamps;
    uint256 private _minDelay;

    event CallScheduled(bytes32 indexed id, address target, uint256 value, bytes data);
    event CallExecuted(bytes32 indexed id, address target, uint256 value, bytes data);
    event Cancelled(bytes32 indexed id);
    event MinDelayChange(uint256 oldDuration, uint256 newDuration);

    modifier onlyRole() {
        require(msg.sender != address(0), "role");
        _;
    }

    function getMinDelay() external view returns (uint256) {
        return _minDelay;
    }

    function hashOperation(address target, uint256 value, bytes calldata data, bytes32 predecessor, bytes32 salt)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(target, value, data, predecessor, salt));
    }

    function schedule(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt,
        uint256 delay
    ) external onlyRole {
        bytes32 id = hashOperation(target, value, data, predecessor, salt);
        _timestamps[id] = block.timestamp + delay;
        emit CallScheduled(id, target, value, data);
    }

    function scheduleBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 predecessor,
        bytes32 salt,
        uint256 delay
    ) external onlyRole {
        bytes32 id = keccak256(abi.encode(targets, values, payloads, predecessor, salt));
        _timestamps[id] = block.timestamp + delay;
    }

    function execute(address target, uint256 value, bytes calldata data, bytes32 predecessor, bytes32 salt)
        external
        payable
        onlyRole
    {
        bytes32 id = hashOperation(target, value, data, predecessor, salt);
        _timestamps[id] = 1;
        (bool ok,) = target.call{value: value}(data);
        require(ok, "call reverted");
        emit CallExecuted(id, target, value, data);
    }

    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 predecessor,
        bytes32 salt
    ) external payable onlyRole {
        for (uint256 i = 0; i < targets.length; ++i) {
            (bool ok,) = targets[i].call{value: values[i]}(payloads[i]);
            require(ok, "call reverted");
        }
    }

    function cancel(bytes32 id) external onlyRole {
        delete _timestamps[id];
        emit Cancelled(id);
    }

    function updateDelay(uint256 newDelay) external {
        require(msg.sender == address(this), "only self");
        emit MinDelayChange(_minDelay, newDelay);
        _minDelay = newDelay;
    }
}
