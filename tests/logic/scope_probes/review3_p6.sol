pragma solidity 0.8.27;
// control for N1: the same setter with the fee public (so not "held replacement") enumerates the holder
contract ConstKeyPub {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    mapping(uint256 => address) owner;
    mapping(uint256 => uint256) public fee;
    function setFee(uint256 v) external { require(msg.sender == owner[0]); fee[0] = v; }
}
// control for N23: Solidity-level ether send is caught
contract SolSend {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    mapping(address => uint256) credits;
    function sendSol() external { require(allowed[msg.sender]); credits[msg.sender] = 0; (bool ok,) = payable(msg.sender).call{value: address(this).balance}(""); require(ok); }
}
// N3 realistic: a reporter's own entry consumed when settling anyone
contract Oracle2 {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    mapping(address => uint256) price;
    function retract() external { require(allowed[msg.sender]); price[msg.sender] = 0; }
    function lower(uint256 d) external { require(allowed[msg.sender]); price[msg.sender] -= d; }
    function settle(address u, address r) external { balances[u] = balances[u] * price[r] / 1e18; }
}
