#!/usr/bin/env python
"""Per-label accuracy scoring of CURRENT-code emissions (runs/*.json).

Judgment standard: each label is graded against the claim consumers render:
  ownership_transfer  -> "Transfers contract ownership." / chip "changes owner"
  pause_toggle        -> "Changes the contract pause state." / chip "pause control"
  hook_update         -> "Updates hook configuration ..." / chip "changes hook"
  authority_update    -> "Updates the authority contract used for permission checks."
  role_management     -> "Changes role-based permissions."
  implementation_update -> "changes logic"
  asset_send/asset_pull/mint/burn -> "moves value out/in", "Mints/Burns ..."
  delegatecall_execution / contract_deployment / selfdestruct_capability -> sink facts
  external_contract_call -> "Calls an external contract" (fact tier)

Verdicts: C = claim true for this function; W = claim false/misleading;
U = unprovable without deeper source verification (counted separately).
Every verdict is explicit below — no name-based magic.
"""
import glob
import json
import os
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))

# (contract, function-prefix, label) -> verdict + short reason.
# Function matched by startswith to absorb overloads.
V = []


def v(contract, fn, label, verdict, why):
    V.append((contract, fn, label, verdict, why))


# ---- WETH9 ----
v("WETH9", "approve", "hook_update", "W", "ERC20 allowance write; not a hook")
v("WETH9", "deposit", "hook_update", "W", "user deposit; balance mapping write")
v("WETH9", "fallback", "hook_update", "W", "deposit alias")
v("WETH9", "withdraw", "hook_update", "W", "user withdrawal; also MISSES asset_send (.transfer())")

# ---- EETH ----
v("EETH", "approve", "hook_update", "W", "allowance write")
v("EETH", "decreaseAllowance", "hook_update", "W", "allowance write")
v("EETH", "increaseAllowance", "hook_update", "W", "allowance write")
v("EETH", "transfer(", "hook_update", "W", "shares transfer")
v("EETH", "initialize", "pause_toggle", "W", "_initialized/_initializing latch, not pause")
v("EETH", "initialize", "ownership_transfer", "C", "sets _owner (one-shot)")
v("EETH", "transferOwnership", "ownership_transfer", "C", "OZ Ownable")
v("EETH", "renounceOwnership", "ownership_transfer", "C", "OZ Ownable")
v("EETH", "upgradeTo", "delegatecall_execution", "C", "fact: delegatecall reachable; implementation_update MISSED")
v("EETH", "upgradeToAndCall", "delegatecall_execution", "C", "fact; implementation_update MISSED")
v("EETH", "balanceOf", "external_contract_call", "C", "fact: calls liquidityPool (view)")
v("EETH", "totalSupply", "external_contract_call", "C", "fact (view)")
v("EETH", "getImplementation", "external_contract_call", "C", "fact (view)")
v("EETH", "transferFrom", "external_contract_call", "C", "fact tier")

# ---- BoringVault ----
v("BoringVault", "approve", "hook_update", "W", "allowance write")
v("BoringVault", "transfer(", "hook_update", "W", "balance write")
v("BoringVault", "setBeforeTransferHook", "hook_update", "C", "genuine hook pointer")
v("BoringVault", "setAuthority", "authority_update", "C", "Solmate canonical")
v("BoringVault", "transferOwnership", "ownership_transfer", "C", "Solmate Owned")
v("BoringVault", "enter", "external_contract_call", "C", "fact; MISSES mint+asset_pull semantics")
v("BoringVault", "exit", "external_contract_call", "C", "fact; MISSES burn+asset_send semantics")
v("BoringVault", "manage(", "external_contract_call", "C", "fact; MISSES arbitrary_external_call severity")
v("BoringVault", "transferFrom", "external_contract_call", "C", "fact tier")

# ---- TellerWithMultiAssetSupport ----
for fn in ("allowFrom", "allowOperator", "allowTo", "denyFrom", "denyOperator", "denyTo"):
    v("TellerWithMultiAssetSupport", fn, "hook_update", "W", "deny/allow-list membership edit, not a hook pointer")
v("TellerWithMultiAssetSupport", "pause", "external_contract_call", "W",
  "only ext call is requiresAuth check; pause_toggle MISSED (inline require)")
v("TellerWithMultiAssetSupport", "unpause", "external_contract_call", "W", "same; pause_toggle MISSED")
v("TellerWithMultiAssetSupport", "setAuthority", "authority_update", "C", "canonical")
v("TellerWithMultiAssetSupport", "transferOwnership", "ownership_transfer", "C", "Solmate Owned")
v("TellerWithMultiAssetSupport", "deposit", "external_contract_call", "C", "fact; misses asset_pull/mint semantics")
v("TellerWithMultiAssetSupport", "bulkDeposit", "external_contract_call", "C", "fact tier")
v("TellerWithMultiAssetSupport", "bulkWithdraw", "external_contract_call", "C", "fact tier")

# ---- AccountantWithRateProviders (struct-type bug) ----
v("AccountantWithRateProviders", "pause", "hook_update", "W", "writes AccountantState struct; IS a pause")
v("AccountantWithRateProviders", "unpause", "hook_update", "W", "IS an unpause")
for fn in ("previewUpdateExchangeRate", "updateDelay", "updateExchangeRate", "updateLower",
           "updatePayoutAddress", "updatePerformanceFee", "updatePlatformFee", "updateUpper"):
    v("AccountantWithRateProviders", fn, "hook_update", "W", "struct field write; rate/fee config, not hook")
v("AccountantWithRateProviders", "setAuthority", "authority_update", "C", "canonical")
v("AccountantWithRateProviders", "transferOwnership", "ownership_transfer", "C", "Solmate Owned")

# ---- RolesAuthority ----
for fn in ("setPublicCapability", "setRoleCapability", "setUserRole"):
    v("RolesAuthority", fn, "role_management", "C", "Solmate canonical")
v("RolesAuthority", "setAuthority", "authority_update", "C", "canonical")
v("RolesAuthority", "transferOwnership", "ownership_transfer", "C", "Solmate Owned")

# ---- TimelockController ----
v("TimelockController", "execute(", "asset_send", "C", "fact: forwards value; timelock semantics MISSED")
v("TimelockController", "executeBatch", "asset_send", "C", "fact; timelock semantics MISSED")
v("TimelockController", "grantRole", "role_management", "C", "OZ canonical")
v("TimelockController", "revokeRole", "role_management", "C", "OZ canonical")

# ---- EndpointV2 ----
v("EndpointV2", "setDelegate", "hook_update", "W", "per-OApp delegate mapping; config not hook")
v("EndpointV2", "setLzToken", "hook_update", "W", "token pointer; borderline pointer-rotate, claim says hook")
v("EndpointV2", "verify", "hook_update", "W", "DVN verification write; not config at all")
v("EndpointV2", "send", "asset_send", "C", "forwards fee value")
v("EndpointV2", "recoverToken", "asset_send", "C", "token recovery")
v("EndpointV2", "transferOwnership", "ownership_transfer", "C", "OZ Ownable")
v("EndpointV2", "renounceOwnership", "ownership_transfer", "C", "OZ Ownable")
v("EndpointV2", "lzReceive", "external_contract_call", "C", "fact tier")

# ---- Dai (Maker wards) ----
v("Dai", "rely", "hook_update", "W", "root auth grant (wards); mislabeled as hook")
v("Dai", "deny", "hook_update", "W", "root auth revoke")
v("Dai", "approve", "hook_update", "W", "allowance")
# mint/burn: NO labels at all (misses) — recorded in miss table.

# ---- Comp ----
v("Comp", "approve", "hook_update", "W", "allowance")
# delegate/delegateBySig: no labels (miss)

# ---- StrategyManager (EigenLayer) ----
v("StrategyManager", "initialize", "ownership_transfer", "C", "sets _owner")
v("StrategyManager", "initialize", "pause_toggle", "W", "init latch")
v("StrategyManager", "setStrategyWhitelister", "ownership_transfer", "W", "rotates whitelister role, not contract ownership")
v("StrategyManager", "transferOwnership", "ownership_transfer", "C", "OZ")
v("StrategyManager", "renounceOwnership", "ownership_transfer", "C", "OZ")
v("StrategyManager", "depositIntoStrategy", "asset_send", "U", "user deposit: tokens leave caller via transferFrom to strategy; direction semantics debatable")
v("StrategyManager", "depositIntoStrategyWithSignature", "asset_send", "U", "same")

# ---- WrapTokenV3ETH (FiatToken family) ----
v("WrapTokenV3ETH", "approve", "hook_update", "W", "allowance")
v("WrapTokenV3ETH", "increaseAllowance", "hook_update", "W", "allowance")
v("WrapTokenV3ETH", "decreaseAllowance", "hook_update", "W", "allowance")
v("WrapTokenV3ETH", "transfer(", "hook_update", "W", "balance write")
v("WrapTokenV3ETH", "cancelAuthorization", "hook_update", "W", "EIP-3009 state")
v("WrapTokenV3ETH", "blacklist", "hook_update", "W", "sanction list edit")
v("WrapTokenV3ETH", "unBlacklist", "hook_update", "W", "sanction list edit")
v("WrapTokenV3ETH", "pause", "pause_toggle", "C", "real pause (modifier-read bool)")
v("WrapTokenV3ETH", "unpause", "pause_toggle", "C", "real unpause")
v("WrapTokenV3ETH", "transferOwnership", "ownership_transfer", "C", "owner scalar")
v("WrapTokenV3ETH", "initialize", "ownership_transfer", "C", "sets _owner et al")
v("WrapTokenV3ETH", "updateBlacklister", "ownership_transfer", "W", "rotates blacklister, not ownership")
v("WrapTokenV3ETH", "updateMasterMinter", "ownership_transfer", "W", "rotates masterMinter")
v("WrapTokenV3ETH", "updatePauser", "ownership_transfer", "W", "rotates pauser")
v("WrapTokenV3ETH", "updateRescuer", "ownership_transfer", "W", "rotates rescuer")
v("WrapTokenV3ETH", "mint(", "external_contract_call", "C", "fact; MISSES mint label on own mint fn")
v("WrapTokenV3ETH", "burn(", "external_contract_call", "C", "fact; MISSES burn")
v("WrapTokenV3ETH", "moveToStakingAddress", "asset_send", "C", "sends ETH out")
v("WrapTokenV3ETH", "rescueERC20", "asset_send", "C", "sends tokens out")

# ---- AdminUpgradeabilityProxy (wBETH zos proxy) ----
v("AdminUpgradeabilityProxy", "upgradeTo", "delegatecall_execution", "C",
  "fact (non-admin path falls through to delegatecall); implementation_update MISSED on real upgrade")
v("AdminUpgradeabilityProxy", "upgradeToAndCall", "delegatecall_execution", "C", "fact; impl_update MISSED")
v("AdminUpgradeabilityProxy", "upgradeToAndCall", "asset_send", "C", "call{value}")
v("AdminUpgradeabilityProxy", "changeAdmin", "delegatecall_execution", "C",
  "fact-true only via fallthrough; admin-change semantics MISSED entirely")
v("AdminUpgradeabilityProxy", "fallback", "delegatecall_execution", "C", "proxy fallback fact")

# ---- UUPSProxy (EETH proxy) ----
v("UUPSProxy", "fallback", "delegatecall_execution", "C", "fact")
v("UUPSProxy", "receive", "delegatecall_execution", "C", "fact")

# ---- SafeL2 ----
v("SafeL2", "approveHash", "hook_update", "W", "tx approval mapping")
v("SafeL2", "enableModule", "hook_update", "W", "module install = arbitrary exec grant; not 'hook'")
v("SafeL2", "disableModule", "hook_update", "W", "module removal")
v("SafeL2", "swapOwner", "hook_update", "W", "signer rotation")
v("SafeL2", "execTransaction", "asset_send", "C", "can send value")
v("SafeL2", "execTransaction", "delegatecall_execution", "C", "operation=delegatecall")
v("SafeL2", "execTransactionFromModule", "delegatecall_execution", "C", "fact")
v("SafeL2", "execTransactionFromModuleReturnData", "delegatecall_execution", "C", "fact")
v("SafeL2", "setup", "asset_send", "C", "payment path")
v("SafeL2", "setup", "delegatecall_execution", "C", "delegatecall setupModules")
v("SafeL2", "simulateAndRevert", "delegatecall_execution", "C", "fact")
v("SafeL2", "setGuard", "external_contract_call", "W",
  "THE Safe hook setter; labeled generic ext-call, hook semantics missed")

# ---- LiquidityPool ----
v("LiquidityPool", "initialize", "pause_toggle", "W", "init latch")
v("LiquidityPool", "initialize", "ownership_transfer", "C", "sets owner")
v("LiquidityPool", "transferOwnership", "ownership_transfer", "C", "OZ")
v("LiquidityPool", "renounceOwnership", "ownership_transfer", "C", "OZ")
v("LiquidityPool", "updateAdmin", "ownership_transfer", "W", "admin scalar rotate; claim says contract ownership")
v("LiquidityPool", "setMembershipManager", "ownership_transfer", "W", "peer-contract pointer")
for fn in ("setTokenAddress", "setTnft", "setStakingManager", "setEtherFiNodesManager", "updateBNftTreasury"):
    v("LiquidityPool", fn, "hook_update", "W", "dependency pointer, not hook")
v("LiquidityPool", "withdraw", "asset_send", "C", "sends ETH")
v("LiquidityPool", "batchCancelDeposit", "asset_send", "C", "refunds ETH")
v("LiquidityPool", "batchDepositWithBidIds", "asset_send", "C", "forwards ETH to staking mgr")
v("LiquidityPool", "swapTNftForEth", "asset_send", "C", "sends ETH")
v("LiquidityPool", "swapTNftForEth", "asset_pull", "C", "pulls TNFT")
v("LiquidityPool", "deposit(", "external_contract_call", "C", "fact; MISSES mint (eETH mintShares unlabeled)")
v("LiquidityPool", "upgradeTo", "delegatecall_execution", "C", "fact; impl_update missed")
v("LiquidityPool", "upgradeToAndCall", "delegatecall_execution", "C", "fact; impl_update missed")

# ---- CumulativeMerkleDrop (OZ v5) ----
for fn in ("owner()", "defaultAdmin()", "defaultAdminDelay()", "pendingDefaultAdmin()", "pendingDefaultAdminDelay()"):
    v("CumulativeMerkleDrop", fn.rstrip("()"), "ownership_transfer", "W", "VIEW function labeled ownership transfer")
for fn in ("setPeer", "setDelegate", "addChain", "removeChain", "initializeLayerZero"):
    v("CumulativeMerkleDrop", fn, "ownership_transfer", "W", "OZv5 storage-location ghost write")
v("CumulativeMerkleDrop", "grantRole", "ownership_transfer", "W", "role grant; not ownership transfer")
v("CumulativeMerkleDrop", "grantRole", "role_management", "C", "canonical")
v("CumulativeMerkleDrop", "revokeRole", "ownership_transfer", "W", "ghost")
v("CumulativeMerkleDrop", "revokeRole", "role_management", "C", "canonical")
v("CumulativeMerkleDrop", "renounceRole", "ownership_transfer", "W", "renounces A role; claim over-broad")
v("CumulativeMerkleDrop", "beginDefaultAdminTransfer", "ownership_transfer", "C", "does begin admin transfer (2-step)")
v("CumulativeMerkleDrop", "acceptDefaultAdminTransfer", "ownership_transfer", "C", "completes admin transfer")
v("CumulativeMerkleDrop", "cancelDefaultAdminTransfer", "ownership_transfer", "C", "cancels pending transfer (borderline)")
v("CumulativeMerkleDrop", "changeDefaultAdminDelay", "ownership_transfer", "W", "delay config")
v("CumulativeMerkleDrop", "rollbackDefaultAdminDelay", "ownership_transfer", "W", "delay config")
v("CumulativeMerkleDrop", "transferOwnership", "ownership_transfer", "C", "real")
v("CumulativeMerkleDrop", "renounceOwnership", "ownership_transfer", "C", "real")
v("CumulativeMerkleDrop", "initialize(", "ownership_transfer", "C", "sets defaultAdmin")
v("CumulativeMerkleDrop", "claim", "asset_send", "C", "sends tokens")
v("CumulativeMerkleDrop", "sweepETH", "asset_send", "C", "sweeps")
v("CumulativeMerkleDrop", "updateClaimEid", "asset_send", "C", "pays lz fee (borderline)")
v("CumulativeMerkleDrop", "upgradeToAndCall", "delegatecall_execution", "C", "fact; impl_update missed")

# ---- TopUpSource (OZ v5) ----
for fn in ("owner()", "defaultAdmin()", "defaultAdminDelay()", "pendingDefaultAdmin()", "pendingDefaultAdminDelay()"):
    v("TopUpSource", fn.rstrip("()"), "ownership_transfer", "W", "VIEW labeled")
v("TopUpSource", "grantRole", "ownership_transfer", "W", "ghost")
v("TopUpSource", "grantRole", "role_management", "C", "canonical")
v("TopUpSource", "revokeRole", "ownership_transfer", "W", "ghost")
v("TopUpSource", "revokeRole", "role_management", "C", "canonical")
v("TopUpSource", "renounceRole", "ownership_transfer", "W", "ghost")
v("TopUpSource", "beginDefaultAdminTransfer", "ownership_transfer", "C", "2-step admin transfer")
v("TopUpSource", "acceptDefaultAdminTransfer", "ownership_transfer", "C", "completes")
v("TopUpSource", "cancelDefaultAdminTransfer", "ownership_transfer", "C", "cancels (borderline)")
v("TopUpSource", "changeDefaultAdminDelay", "ownership_transfer", "W", "delay config")
v("TopUpSource", "rollbackDefaultAdminDelay", "ownership_transfer", "W", "delay config")
v("TopUpSource", "initialize", "ownership_transfer", "C", "sets admin")
v("TopUpSource", "bridge", "delegatecall_execution", "U", "bridge adapter delegatecall—needs source check")
v("TopUpSource", "upgradeToAndCall", "delegatecall_execution", "C", "fact; impl_update missed")
# pause()/unpause(): NO pause_toggle (OZv5 Pausable ghost) — miss table.

# ---- PauserRegistry ----
v("PauserRegistry", "setIsPauser", "hook_update", "W", "pauser ACL edit")
v("PauserRegistry", "setUnpauser", "ownership_transfer", "W", "rotates unpauser authority, not ownership")

# ---- TopUpV2 (Solady) ----
v("TopUpV2", "initialize", "ownership_transfer", "C", "does set owner (via ghost _OWNER_SLOT write)")
v("TopUpV2", "processTopUp", "asset_send", "C", "forwards funds")
v("TopUpV2", "receive", "asset_send", "U", "auto-forward? needs source check")
# transferOwnership/renounceOwnership: NO label (Solady assembly) — miss table.

# ---- MembershipManager ----
v("MembershipManager", "pauseContract", "pause_toggle", "C", "real pause")
v("MembershipManager", "unPauseContract", "pause_toggle", "C", "real unpause")
v("MembershipManager", "transferOwnership", "ownership_transfer", "C", "OZ")
v("MembershipManager", "renounceOwnership", "ownership_transfer", "C", "OZ")
v("MembershipManager", "initializeOnUpgrade", "ownership_transfer", "W", "writes etherFiAdmin pointer, not ownership")
v("MembershipManager", "updateAdmin", "hook_update", "W", "admins-mapping ACL edit")
v("MembershipManager", "updateTier", "hook_update", "W", "tier config struct")
v("MembershipManager", "wrapEth(", "mint", "C", "mints membership NFT + eETH shares")
v("MembershipManager", "wrapEthForEap", "mint", "C", "mints")
v("MembershipManager", "unwrapForEEthAndBurn", "asset_send", "C", "burns NFT, sends eETH")
v("MembershipManager", "upgradeTo", "delegatecall_execution", "C", "fact")
v("MembershipManager", "upgradeToAndCall", "delegatecall_execution", "C", "fact")

# ---- StakingManagerV2 ----
v("StakingManagerV2", "initialize", "ownership_transfer", "C", "sets owner")
v("StakingManagerV2", "pauseContract", "pause_toggle", "C", "real")
v("StakingManagerV2", "unPauseContract", "pause_toggle", "C", "real")
v("StakingManagerV2", "transferOwnership", "ownership_transfer", "C", "OZ")
v("StakingManagerV2", "renounceOwnership", "ownership_transfer", "C", "OZ")
v("StakingManagerV2", "registerBNFTContract", "hook_update", "W", "NFT contract pointer")
v("StakingManagerV2", "registerTNFTContract", "hook_update", "W", "NFT contract pointer")
v("StakingManagerV2", "registerEth2DepositContract", "authority_update", "W",
  "beacon deposit contract pointer; not an auth authority")
v("StakingManagerV2", "registerEtherFiNodeImplementationContract", "contract_deployment", "C",
  "creates UpgradeableBeacon; but beacon-impl-update semantics missed")
v("StakingManagerV2", "upgradeTo", "delegatecall_execution", "C", "fact")
v("StakingManagerV2", "upgradeToAndCall", "delegatecall_execution", "C", "fact")
v("StakingManagerV2", "upgradeEtherFiNode", "external_contract_call", "W",
  "beacon upgrade path; upgrade semantics entirely missed")

# ---- L1SyncPoolETH (OZ v5) ----
v("L1SyncPoolETH", "owner", "ownership_transfer", "W", "VIEW")
for fn in ("setDelegate", "setDummyToken", "setLockBox", "setPeer", "setReceiver", "setTokenOut", "setVault"):
    v("L1SyncPoolETH", fn, "ownership_transfer", "W", "OZv5 ghost write; config setter")
v("L1SyncPoolETH", "sweep", "ownership_transfer", "W", "ghost; sweep is asset movement")
v("L1SyncPoolETH", "sweep", "asset_send", "C", "sweeps funds")
v("L1SyncPoolETH", "transferOwnership", "ownership_transfer", "C", "real")
v("L1SyncPoolETH", "renounceOwnership", "ownership_transfer", "C", "real")
v("L1SyncPoolETH", "initialize", "ownership_transfer", "C", "sets owner")

# ---- EtherFiRedemptionManager ----
v("EtherFiRedemptionManager", "initialize", "pause_toggle", "W", "init latch")
v("EtherFiRedemptionManager", "pauseContract", "pause_toggle", "C", "real")
v("EtherFiRedemptionManager", "unPauseContract", "pause_toggle", "C", "real")
for fn in ("redeemEEth", "redeemEEthWithPermit", "redeemWeEth", "redeemWeEthWithPermit"):
    v("EtherFiRedemptionManager", fn, "asset_send", "C", "redemption pays out")
for fn in ("setExitFeeBasisPoints", "setExitFeeSplitToTreasuryInBps", "setLowWatermarkInBpsOfTvl"):
    v("EtherFiRedemptionManager", fn, "hook_update", "W", "fee/watermark config")
v("EtherFiRedemptionManager", "upgradeTo", "delegatecall_execution", "C", "fact")
v("EtherFiRedemptionManager", "upgradeToAndCall", "delegatecall_execution", "C", "fact")

# ---- OneSig ----
v("OneSig", "setExecutorRequired", "pause_toggle", "W", "executor-required toggle, not pause")
v("OneSig", "executeTransaction", "asset_send", "C", "executes value txs")
v("OneSig", "setSigner", "external_contract_call", "W",
  "signer-set management invisible (EnumerableSet lib write, no state_write sink)")
v("OneSig", "setExecutor", "external_contract_call", "W", "same class")
v("OneSig", "setThreshold", "external_contract_call", "W", "threshold change unlabeled semantically")

# ---- AuctionManager ----
v("AuctionManager", "initialize", "pause_toggle", "W", "init latch")
v("AuctionManager", "initialize", "ownership_transfer", "C", "sets owner")
v("AuctionManager", "pauseContract", "pause_toggle", "C", "real")
v("AuctionManager", "unPauseContract", "pause_toggle", "C", "real")
v("AuctionManager", "transferOwnership", "ownership_transfer", "C", "OZ")
v("AuctionManager", "renounceOwnership", "ownership_transfer", "C", "OZ")
v("AuctionManager", "updateAdmin", "ownership_transfer", "W", "admin scalar; claim=ownership")
v("AuctionManager", "setStakingManagerContractAddress", "ownership_transfer", "W", "peer pointer")
v("AuctionManager", "setProtocolRevenueManager", "hook_update", "W", "peer pointer")
v("AuctionManager", "cancelBid", "asset_send", "C", "refunds")
v("AuctionManager", "cancelBidBatch", "asset_send", "C", "refunds")
v("AuctionManager", "upgradeTo", "delegatecall_execution", "C", "fact")
v("AuctionManager", "upgradeToAndCall", "delegatecall_execution", "C", "fact")

# ---- LayerZeroTellerWithRateLimiting ----
for fn in ("allowAll", "allowFrom", "allowOperator", "allowPermissionedOperator", "allowTo",
           "denyAll", "denyFrom", "denyOperator", "denyPermissionedOperator", "denyTo"):
    v("LayerZeroTellerWithRateLimiting", fn, "hook_update", "W", "allow/deny-list edit")
v("LayerZeroTellerWithRateLimiting", "setAuthority", "authority_update", "C", "canonical")
v("LayerZeroTellerWithRateLimiting", "transferOwnership", "ownership_transfer", "C", "Solmate")

# =====================================================================
# Known MISSES (false negatives) observed in the same runs: label that
# SHOULD fire under the vocabulary's own claims but does not.
MISSES = [
    ("WETH9", "withdraw", "asset_send", ".transfer() not LOW_LEVEL_CALL"),
    ("Dai", "mint", "mint", "own-mint invisible (selector map is callee-only)"),
    ("Dai", "burn", "burn", "same"),
    ("Dai", "rely/deny", "role_management-equivalent", "wards grant/revoke; no canonical selector"),
    ("Comp", "delegate/delegateBySig", "(no vocabulary fits: voting-power delegation)", "silent"),
    ("EETH", "mintShares/burnShares", "mint/burn", "silent"),
    ("BoringVault", "enter/exit", "mint+asset_pull / burn+asset_send", "ext-call only"),
    ("BoringVault", "manage", "arbitrary_external_call", "label has no producer"),
    ("TellerWithMultiAssetSupport", "pause/unpause", "pause_toggle", "inline require, no modifier"),
    ("TopUpSource", "pause/unpause", "pause_toggle", "OZv5 PausableStorageLocation ghost"),
    ("CumulativeMerkleDrop", "pause/unpause", "pause_toggle", "OZv5 ghost"),
    ("LiquidityPool", "open/closeEEthLiquidStaking", "pause_toggle", "inline require"),
    ("TopUpV2", "transferOwnership/renounceOwnership", "ownership_transfer", "Solady assembly writes"),
    ("SafeL2", "addOwnerWithThreshold/removeOwner/changeThreshold", "(signer mgmt)", "silent"),
    ("SafeL2", "setGuard/setFallbackHandler", "hook_update", "assembly slot; generic/silent"),
    ("EETH/LiquidityPool/all UUPS", "upgradeTo/upgradeToAndCall", "implementation_update", "split-proxy: writer on impl, fallback on proxy"),
    ("AdminUpgradeabilityProxy", "upgradeTo/changeAdmin", "implementation_update/admin-change", "sload in _implementation(), not fallback body"),
    ("TimelockController", "schedule/execute/cancel/updateDelay", "timelock_operation", "label produced nowhere"),
    ("StakingManagerV2", "upgradeEtherFiNode", "implementation_update(beacon)", "ext call only"),
    ("OneSig", "setSigner/setExecutor/setThreshold", "(signer mgmt)", "EnumerableSet lib writes invisible"),
    ("EndpointV2", "sendCompose/lzCompose", "(none — correctly silent)", "composeQueue writes produce no sinks at all (writes=[])"),
]


def main():
    runs = {}
    for path in glob.glob(os.path.join(HERE, "runs", "*.json")):
        d = json.load(open(path))
        runs[d["contract"]] = d

    # Verify every verdict matches an actually-emitted label.
    per_label = defaultdict(lambda: {"C": 0, "W": 0, "U": 0, "examples_W": []})
    unmatched = []
    covered = defaultdict(set)
    for contract, fn_prefix, label, verdict, why in V:
        d = runs.get(contract)
        if d is None:
            unmatched.append((contract, fn_prefix, label, "NO RUN"))
            continue
        hits = [
            sig for sig, i in d["functions"].items()
            if sig.startswith(fn_prefix) and label in (i["labels"] or [])
        ]
        if not hits:
            unmatched.append((contract, fn_prefix, label, "NOT EMITTED"))
            continue
        for sig in hits:
            key = (contract, sig, label)
            if key in covered["done"]:
                continue
            covered["done"].add(key)
            per_label[label][verdict] += 1
            if verdict == "W" and len(per_label[label]["examples_W"]) < 8:
                per_label[label]["examples_W"].append(f"{contract}.{sig.split('(')[0]}: {why}")

    # Count emitted labels not covered by any verdict (residual).
    residual = defaultdict(list)
    for cname, d in runs.items():
        for sig, i in d["functions"].items():
            for label in i["labels"] or []:
                if (cname, sig, label) not in covered["done"]:
                    residual[label].append(f"{cname}.{sig}")

    print("== PER-LABEL CURRENT-CODE ACCURACY (27 real contracts, main@90d8774) ==")
    for label in sorted(per_label):
        s = per_label[label]
        n = s["C"] + s["W"] + s["U"]
        print(f"{label:28s} judged={n:3d} correct={s['C']:3d} wrong={s['W']:3d} unprovable={s['U']}")
        for e in s["examples_W"]:
            print(f"    W: {e}")
    print("\n== UNMATCHED VERDICTS (should be empty; else my table is stale) ==")
    for u in unmatched:
        print("   ", u)
    print("\n== RESIDUAL EMITTED LABELS NOT JUDGED (mostly external_contract_call fact-tier) ==")
    for label, items in sorted(residual.items()):
        print(f"{label:28s} n={len(items)}")
        if label != "external_contract_call":
            for it in items[:15]:
                print("    ", it)
    print("\n== KNOWN FALSE-NEGATIVE CLASSES (misses) ==")
    for m in MISSES:
        print(f"  {m[0]:34s} {m[1]:44s} should={m[2]}: {m[3]}")


if __name__ == "__main__":
    main()
