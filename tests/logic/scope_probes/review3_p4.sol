pragma solidity 0.8.27;
// N17 a non-view function hands out the approval (no view returns it)
contract NonView {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    mapping(uint256 => address) owners; mapping(uint256 => address) approvals;
    function approve(address to, uint256 id) external { require(owners[id] == msg.sender); approvals[id] = to; }
    function peek(uint256 id) external returns (address) { return approvals[id]; }
}
// N18 a view that returns the approval through a loop / an internal helper
contract LoopView {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    mapping(uint256 => address) owners; mapping(uint256 => address) approvals;
    function approve(address to, uint256 id) external { require(owners[id] == msg.sender); approvals[id] = to; }
    function firstApproved(uint256 n) external view returns (address a) { for (uint256 i; i < n; i++) { if (approvals[i] != address(0)) return approvals[i]; } }
}
contract HelperView {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    mapping(uint256 => address) owners; mapping(uint256 => address) approvals;
    function approve(address to, uint256 id) external { require(owners[id] == msg.sender); approvals[id] = to; }
    function _get(uint256 id) internal view returns (address) { return approvals[id]; }
    function getApproved(uint256 id) external view returns (address r) { r = _get(id); }
}
// N19 a view that returns a derived value (hash / packed) of the slot
contract DerivedView {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    mapping(uint256 => address) owners; mapping(uint256 => address) approvals;
    function approve(address to, uint256 id) external { require(owners[id] == msg.sender); approvals[id] = to; }
    function digest(uint256 id) external view returns (bytes32) { return keccak256(abi.encode(approvals[id])); }
}
// N20 the holder entry is written by an open function: anyone can claim an id, then act as holder
contract Claim {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    mapping(uint256 => address) owners; mapping(uint256 => address) approvals;
    function claim(uint256 id) external { owners[id] = msg.sender; }
    function approve(address to, uint256 id) external { require(owners[id] == msg.sender); approvals[id] = to; }
}
// N21 operator approvals forged by an admin, and a holder set chosen through the caller's own key
contract Forge {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    address admin;
    mapping(address => mapping(address => bool)) op;
    mapping(address => uint256) vault;
    function setOp(address who) external { op[msg.sender][who] = true; }
    function adminOp(address u, address who) external { require(msg.sender == admin); op[u][who] = true; }
    function drain(address from, uint256 a) external { require(op[from][msg.sender]); vault[from] -= a; vault[msg.sender] += a; }
}
// N22 debit on the caller, credit to an entry whose other keys differ in meaning (array index into same var)
contract Hash {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    mapping(bytes32 => uint256) slotOf;
    function clearPacked(bytes calldata tail) external { require(allowed[msg.sender]); slotOf[keccak256(abi.encodePacked(msg.sender, tail))] = 0; }
    function setVictim(bytes32 k) external { require(allowed[msg.sender]); slotOf[k] = 0; }
}
