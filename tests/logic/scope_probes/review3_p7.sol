pragma solidity 0.8.27;
contract AsmAct2 {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    mapping(address => uint256) credits; address admin;
    event Allowed(address indexed who, bool ok);
    function allow(address who, bool ok) external { require(msg.sender == admin); allowed[who] = ok; emit Allowed(who, ok); }
    function sendAsm() external { require(allowed[msg.sender]); credits[msg.sender] = 0;
        assembly { let r := call(gas(), caller(), selfbalance(), 0, 0, 0, 0) } }
    function sendSol() external { require(allowed[msg.sender]); credits[msg.sender] = 0; (bool ok,) = payable(msg.sender).call{value: address(this).balance}(""); require(ok); }
}
