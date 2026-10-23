pragma solidity 0.8.27;
// N23 assembly acts in a function whose visible write is an own clear
contract AsmAct {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    mapping(address => uint256) credits; address impl;
    function fwdAsm() external { require(allowed[msg.sender]); credits[msg.sender] = 0; address i = impl;
        assembly { calldatacopy(0, 0, calldatasize()) let r := delegatecall(gas(), i, 0, calldatasize(), 0, 0) } }
    function sendAsm() external { require(allowed[msg.sender]); credits[msg.sender] = 0;
        assembly { let r := call(gas(), caller(), selfbalance(), 0, 0, 0, 0) } }
    function killAsm() external { require(allowed[msg.sender]); credits[msg.sender] = 0; assembly { selfdestruct(caller()) } }
}
// N24 a check that reads storage through assembly sload (slot of `frozen`)
contract AsmRead {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    bool frozenFlag; mapping(address => uint256) credits;
    function setFrozen(bool b) external { require(allowed[msg.sender]); frozenFlag = b; }
    function guarded() external { bool f; assembly { f := sload(2) } require(!f); balances[msg.sender] += 0; }
    function clearCredits() external { require(allowed[msg.sender]); credits[msg.sender] = 0; }
}
