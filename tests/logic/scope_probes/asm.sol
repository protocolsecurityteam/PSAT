pragma solidity 0.8.27;
contract A {
    mapping(address => uint256) balances;      // 0
    mapping(address => bool) allowed;          // 1
    struct Ref { address value; }
    mapping(uint256 => Ref) _tokenApprovals;
    mapping(uint256 => address) owners;
    mapping(address => bool) flag;
    function approveA(address to, uint256 id) external { require(owners[id] == msg.sender); _tokenApprovals[id].value = to; }
    function transferFromA(address from, address to, uint256 id) external {
        require(owners[id] == from);
        Ref storage r = _tokenApprovals[id];
        address a;
        assembly { a := sload(r.slot) }
        require(msg.sender == from || msg.sender == a);
        owners[id] = to;
    }
    function clearFlag() external { require(allowed[msg.sender]); flag[msg.sender] = false; }
    function useFlag() external {
        mapping(address => bool) storage f = flag;
        bool b;
        bytes32 s = keccak256(abi.encode(msg.sender, uint256(4)));
        assembly { b := sload(s) }
        require(!b);
        balances[msg.sender] = 0;
    }
}
