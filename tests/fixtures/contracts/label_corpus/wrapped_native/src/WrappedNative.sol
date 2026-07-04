// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice A minimal WETH-shaped wrapped-native token: a full ERC-20 whose
/// deposit()/withdraw(uint256) wrap and unwrap the chain's native asset. Written
/// as a synthetic fixture (no vendored deps) so the label corpus can exercise the
/// weth.* / erc20.* / supply.* / flow.out families with a single small compile.
contract WrappedNative {
    string public constant name = "Wrapped Native";
    string public constant symbol = "WNATIVE";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        totalSupply += msg.value;
        emit Transfer(address(0), msg.sender, msg.value);
    }

    function withdraw(uint256 wad) public {
        require(balanceOf[msg.sender] >= wad, "insufficient");
        balanceOf[msg.sender] -= wad;
        totalSupply -= wad;
        payable(msg.sender).transfer(wad);
        emit Transfer(msg.sender, address(0), wad);
    }

    function approve(address spender, uint256 wad) public returns (bool) {
        allowance[msg.sender][spender] = wad;
        emit Approval(msg.sender, spender, wad);
        return true;
    }

    function transfer(address dst, uint256 wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    function transferFrom(address src, address dst, uint256 wad) public returns (bool) {
        require(balanceOf[src] >= wad, "insufficient");
        if (src != msg.sender && allowance[src][msg.sender] != type(uint256).max) {
            require(allowance[src][msg.sender] >= wad, "allowance");
            allowance[src][msg.sender] -= wad;
        }
        balanceOf[src] -= wad;
        balanceOf[dst] += wad;
        emit Transfer(src, dst, wad);
        return true;
    }

    receive() external payable {
        deposit();
    }
}
