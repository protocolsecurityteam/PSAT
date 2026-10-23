pragma solidity 0.8.27;
// N11 two exits, only one stays in the caller's position
contract TwoExit {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    mapping(address => uint256) credits; address owner;
    function f(bool b) external { require(allowed[msg.sender]); if (b) { credits[msg.sender] = 0; return; } owner = msg.sender; }
}
// N12 entry keyed by tx.origin
contract Origin {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    mapping(address => uint256) credits;
    function clearOrigin() external { require(allowed[msg.sender]); credits[tx.origin] = 0; }
}
// N13 event only
contract EventOnly {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    event Ping(address who);
    function ping() external { require(allowed[msg.sender]); emit Ping(msg.sender); }
}
// N14 raw sstore elsewhere (in another function), and in the same function as an own clear
contract Sstore {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    mapping(address => uint256) credits; address owner;
    function clear() external { require(allowed[msg.sender]); credits[msg.sender] = 0; }
    function raw(uint256 v) external { require(msg.sender == owner); assembly { sstore(1, v) } }
}
contract Sstore2 {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    mapping(address => uint256) credits; address owner;
    function clearAndTake() external { require(allowed[msg.sender]); credits[msg.sender] = 0; assembly { sstore(2, caller()) } }
    function clearAndTake2() external { require(allowed[msg.sender]); credits[msg.sender] = 0; assembly { let s := 3 sstore(s, caller()) } }
}
// N15 delegatecall-forwarding proxy
contract Proxy {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    mapping(address => uint256) credits; address impl;
    function fwd(bytes calldata d) external { require(allowed[msg.sender]); credits[msg.sender] = 0; (bool ok,) = impl.delegatecall(d); require(ok); }
    fallback() external { require(allowed[msg.sender]); address i = impl; assembly { calldatacopy(0, 0, calldatasize()) let r := delegatecall(gas(), i, 0, calldatasize(), 0, 0) } }
}
// N16 unchecked debit with an explicit bound on the same exit / on another exit
contract Unchk {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    mapping(address => uint256) dep;
    function bounded(address to, uint256 a) external { require(allowed[msg.sender]); require(a <= dep[msg.sender]); unchecked { dep[msg.sender] -= a; } dep[to] += a; }
    function boundedOther(address to, uint256 a, bool b) external { require(allowed[msg.sender]); if (b) { require(a <= dep[msg.sender]); } unchecked { dep[msg.sender] -= a; dep[to] += a; } }
}
