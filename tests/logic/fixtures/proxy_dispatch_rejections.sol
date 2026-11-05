pragma solidity ^0.8.10;
contract Impl { uint public value; function act() external {require(false);value=1;} }
contract Good { uint public value; function act() external { value=1; } }
contract Clash { function act() external {} }
contract BadCopy { bytes32 constant SLOT=0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
constructor(address i) { assembly {sstore(SLOT,i)} }
fallback() external { assembly { let i:=sload(SLOT) calldatacopy(0,0,calldatasize()) let r:=delegatecall(gas(),i,0,calldatasize(),0,0) if iszero(r) {revert(0,0)} returndatacopy(0,1,returndatasize()) return(0,0) } }
}
