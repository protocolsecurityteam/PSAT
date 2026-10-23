pragma solidity 0.8.27;
// An unchecked debit bounded on the same path by the entry it debits: the bound is no check of anyone else.
contract Bounded {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    mapping(address => uint256) dep;
    function bounded(address to, uint256 a) external {
        require(allowed[msg.sender]);
        require(a <= dep[msg.sender]);
        unchecked { dep[msg.sender] -= a; }
        dep[to] += a;
    }
}
