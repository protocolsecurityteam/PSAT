"""Shared constants for contract analysis."""

from __future__ import annotations

STANDARD_SIGNATURES = {
    "ERC20": {
        "totalSupply()",
        "balanceOf(address)",
        "transfer(address,uint256)",
        "allowance(address,address)",
        "approve(address,uint256)",
        "transferFrom(address,address,uint256)",
    },
    "ERC721": {
        "balanceOf(address)",
        "ownerOf(uint256)",
        "safeTransferFrom(address,address,uint256)",
        "safeTransferFrom(address,address,uint256,bytes)",
        "transferFrom(address,address,uint256)",
        "approve(address,uint256)",
        "getApproved(uint256)",
        "setApprovalForAll(address,bool)",
        "isApprovedForAll(address,address)",
    },
    "ERC1155": {
        "balanceOf(address,uint256)",
        "balanceOfBatch(address[],uint256[])",
        "setApprovalForAll(address,bool)",
        "isApprovedForAll(address,address)",
        "safeTransferFrom(address,address,uint256,uint256,bytes)",
        "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
    },
}
STANDARD_EVENTS = {
    "ERC20": {"Transfer", "Approval"},
    "ERC721": {"Transfer", "Approval", "ApprovalForAll"},
    "ERC1155": {"TransferSingle", "TransferBatch", "ApprovalForAll"},
}
