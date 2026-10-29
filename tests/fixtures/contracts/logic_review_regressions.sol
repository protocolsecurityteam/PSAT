
pragma solidity 0.8.27;
// Unicode source offset regression: café.
uint256 constant MAXIMUM_FEE=500;
contract Review {
    uint public fee;
    address public owner;
    mapping(address=>uint) public credits;
    constructor() {owner=msg.sender;}
    function setFee(uint value) external {require(msg.sender==owner); require(value<=MAXIMUM_FEE); fee=value;}
    function choose(bool privileged,address to,uint amount) external payable {
        if(privileged) {require(msg.sender==owner); credits[to]+=amount;}
        else {credits[msg.sender]+=msg.value;}
    }
}
