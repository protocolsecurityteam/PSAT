// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// Synthetic BoringVault-shaped share token. The compiled proof for two
// idiom-structural families:
//
//  * callee_pointer.rotate — `hook` is a callable scalar pointer that
//    setBeforeTransferHook rotates and the sibling transfer()/transferFrom()
//    invoke at runtime; approve() writes only a mapping, so it is the
//    counterexample that must NOT fire.
//  * supply.mint / supply.burn — enter()/exit() move `totalSupply` up/down via
//    the Binary-IR sign idiom inside the ERC-20 gate.
interface IBeforeTransferHook {
    function beforeTransfer(address from, address to, address operator) external view;
}

contract VaultHook {
    string public constant name = "Vault Share";
    string public constant symbol = "VSHARE";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    address public owner;
    IBeforeTransferHook public hook;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setBeforeTransferHook(address newHook) external onlyOwner {
        hook = IBeforeTransferHook(newHook);
    }

    function _callBeforeTransfer(address from, address to) internal view {
        if (address(hook) != address(0)) hook.beforeTransfer(from, to, msg.sender);
    }

    function enter(address to, uint256 shares) external onlyOwner {
        totalSupply += shares;
        balanceOf[to] += shares;
        emit Transfer(address(0), to, shares);
    }

    function exit(address from, uint256 shares) external onlyOwner {
        totalSupply -= shares;
        balanceOf[from] -= shares;
        emit Transfer(from, address(0), shares);
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        _callBeforeTransfer(msg.sender, to);
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        _callBeforeTransfer(from, to);
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}
