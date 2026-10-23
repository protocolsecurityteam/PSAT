pragma solidity 0.8.27;
// QuantumPFP's shape: transfers only by the owner, so no check reads the approvals; a view hands them out.
contract Approvals {
    address owner;
    mapping(uint256 => address) owners;
    mapping(uint256 => address) tokenApprovals;
    mapping(address => uint256) balances;

    function approve(address to, uint256 id) external {
        require(owners[id] == msg.sender);
        tokenApprovals[id] = to;
    }

    function getApproved(uint256 id) external view returns (address) {
        require(owners[id] != address(0));
        return tokenApprovals[id];
    }

    function transferFrom(address from, address to, uint256 id) external {
        require(msg.sender == owner && owners[id] == from);
        owners[id] = to;
    }

    function balanceOf(address who) external view returns (uint256) {
        return balances[who];
    }

    function move(address to, uint256 d) external {
        balances[msg.sender] -= d;
        balances[to] += d;
    }
}
