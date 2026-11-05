pragma solidity ^0.8.10;
contract Impl { address public owner; uint public value;
 function act() external { require(msg.sender == owner); value = 1; }
 function allowed(address) external pure returns(bool) { return true; }
}
contract Extra { function act() external { assembly { sstore(1, 2) } } }
contract P { bytes32 constant SLOT=0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
 constructor(address i) { assembly { sstore(SLOT,i) sstore(0,caller()) } }
 fallback() external { assembly { let i:=sload(SLOT) calldatacopy(0,0,calldatasize()) let r:=delegatecall(gas(),i,0,calldatasize(),0,0) returndatacopy(0,0,returndatasize()) if iszero(r) {revert(0,returndatasize())} return(0,returndatasize()) } }
}
contract PExtra { bytes32 constant SLOT=0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
 constructor(address i,address other) { assembly { sstore(SLOT,i) sstore(0,caller()) sstore(99,other) } }
 fallback() external { assembly { let i:=sload(SLOT) let other:=sload(99) calldatacopy(0,0,calldatasize()) let r:=delegatecall(gas(),i,0,calldatasize(),0,0) if iszero(r) {revert(0,0)} pop(delegatecall(gas(),other,0,calldatasize(),0,0)) return(0,0) } }
}
interface IM {function allowed(address) external view returns(bool);}
contract C { IM m; uint public value; constructor(address p) {m=IM(p);} function act() external payable {require(msg.value == 1);require(m.allowed(msg.sender)); value=1;} }
