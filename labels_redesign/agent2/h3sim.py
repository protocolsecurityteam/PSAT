#!/usr/bin/env python
"""H3 simulator: standard/idiom matching over the 27 run JSONs.

A standard match = contract-level GATE (structural corroboration: sibling
selectors / views / sink shapes that the standard mandates) + per-function
canonical selector -> exact semantic. No gate, no claim.

Outputs per contract: matched (fn -> standard.semantic) and the residue
(state-changing fns with no standard semantics -> facts only).
"""
import glob
import json
import os
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))


def fn_names(d):
    return {sig.split("(")[0] for sig in d["functions"]}


def sigs(d):
    return set(d["functions"])


def has(d, *names):
    present = fn_names(d)
    return all(n in present for n in names)



def writes_of(d, fn_prefix):
    for sig, i in d["functions"].items():
        if sig.startswith(fn_prefix):
            return set(i.get("writes") or [])
    return set()

def match_contract(d):
    """Return {fn_sig: (standard, semantic, control_plane)}."""
    out = {}
    S = sigs(d)
    names = fn_names(d)
    ercs = set(d.get("slither_ercs") or [])

    def tag(prefixes, standard, semantic, control):
        for sig in S:
            fn = sig.split("(")[0]
            if fn in prefixes:
                out.setdefault(sig, (standard, semantic, control))

    # --- ERC20 core (gate: Slither ERC20 conformance) → user plane ---
    if "ERC20" in ercs:
        tag({"transfer", "transferFrom", "approve", "increaseAllowance", "decreaseAllowance",
             "permit", "transferWithAuthorization", "receiveWithAuthorization", "cancelAuthorization"},
            "erc20", "token user operation (allowance/balance)", False)

    # --- Ownable / Ownable2Step (gate: owner() view + transferOwnership selector) ---
    if "owner()" in S and "transferOwnership(address)" in S:
        tag({"transferOwnership"}, "ownable", "transfers contract ownership", True)
        tag({"renounceOwnership"}, "ownable", "renounces contract ownership", True)
        tag({"acceptOwnership"}, "ownable2step", "accepts pending ownership", True)

    # --- Solady Ownable handover family ---
    if "requestOwnershipHandover()" in S or "completeOwnershipHandover(address)" in S:
        tag({"requestOwnershipHandover", "completeOwnershipHandover", "cancelOwnershipHandover"},
            "solady_ownable", "two-step ownership handover", True)
        if "owner()" in S:
            tag({"transferOwnership", "renounceOwnership"}, "solady_ownable", "transfers/renounces ownership", True)

    # --- OZ AccessControl (gate: hasRole + getRoleAdmin) ---
    if "hasRole(bytes32,address)" in S and "getRoleAdmin(bytes32)" in S:
        tag({"grantRole"}, "access_control", "grants a role", True)
        tag({"revokeRole"}, "access_control", "revokes a role", True)
        tag({"renounceRole"}, "access_control", "renounces own role", True)
    # DefaultAdminRules (gate: defaultAdmin() view)
    if "defaultAdmin()" in S:
        tag({"beginDefaultAdminTransfer", "acceptDefaultAdminTransfer"},
            "access_control_dar", "staged default-admin transfer", True)
        tag({"cancelDefaultAdminTransfer"}, "access_control_dar", "cancels staged admin transfer", True)
        tag({"changeDefaultAdminDelay", "rollbackDefaultAdminDelay"},
            "access_control_dar", "changes admin-transfer delay", True)

    # --- Pausable-like (gate: pause+unpause pair + a paused/isPaused view) ---
    pw = writes_of(d, "pause()")
    if ("pause()" in S and "unpause()" in S) and (pw & {"paused", "isPaused", "_paused"} or "paused()" in S or "isPaused()" in S):
        tag({"pause"}, "pausable", "pauses gated operations", True)
        tag({"unpause"}, "pausable", "unpauses gated operations", True)

    # --- UUPS impl side (gate: proxiableUUID present) ---
    if "proxiableUUID()" in S:
        tag({"upgradeTo", "upgradeToAndCall"}, "uups", "replaces implementation (ERC-1822/1967)", True)

    # --- Proxy shell (gate: fallback with delegatecall sink) ---
    fb = d["functions"].get("fallback()")
    if fb and "delegatecall" in (fb.get("sink_kinds") or []):
        tag({"upgradeTo", "upgradeToAndCall"}, "proxy_shell", "replaces implementation slot", True)
        tag({"changeAdmin"}, "proxy_shell", "changes proxy admin", True)

    # --- Safe (gate: getThreshold + getOwners + execTransaction) ---
    if has(d, "getThreshold", "getOwners", "execTransaction"):
        tag({"addOwnerWithThreshold", "removeOwner", "swapOwner", "changeThreshold"},
            "safe", "changes signer set / threshold", True)
        tag({"enableModule", "disableModule"}, "safe", "grants/revokes module execution rights", True)
        tag({"setGuard"}, "safe", "sets transaction guard hook", True)
        tag({"setFallbackHandler"}, "safe", "sets fallback handler", True)
        tag({"execTransaction"}, "safe", "executes signed transaction (arbitrary call)", False)
        tag({"execTransactionFromModule", "execTransactionFromModuleReturnData"},
            "safe", "module executes arbitrary call", False)
        tag({"approveHash"}, "safe", "pre-approves tx hash (signer op)", False)

    # --- OZ TimelockController (gate: getMinDelay + schedule + execute) ---
    if has(d, "getMinDelay", "schedule", "execute"):
        tag({"schedule", "scheduleBatch"}, "oz_timelock", "queues a timelocked operation", True)
        tag({"execute", "executeBatch"}, "oz_timelock", "executes a matured operation (arbitrary call)", True)
        tag({"cancel"}, "oz_timelock", "cancels a queued operation", True)
        tag({"updateDelay"}, "oz_timelock", "changes the timelock delay", True)

    # --- Solmate Auth / RolesAuthority (gate: authority() view) ---
    if "setAuthority(Authority)" in S and "authority" in writes_of(d, "setAuthority("):
        tag({"setAuthority"}, "solmate_auth", "replaces the authority contract", True)
        if "getUserRoles" in writes_of(d, "setUserRole(") or "getRolesWithCapability" in writes_of(d, "setRoleCapability("):
            tag({"setUserRole"}, "solmate_roles", "grants/revokes a user role", True)
            tag({"setRoleCapability"}, "solmate_roles", "maps role to capability", True)
            tag({"setPublicCapability"}, "solmate_roles", "opens/closes public capability", True)

    # --- Maker wards idiom (gate: wards(address) view + rely + deny) ---
    if "rely(address)" in S and "deny(address)" in S and "wards" in writes_of(d, "rely("):
        tag({"rely"}, "maker_wards", "grants root authorization", True)
        tag({"deny"}, "maker_wards", "revokes root authorization", True)

    # --- Comp voting delegation (gate: delegates + getCurrentVotes) ---
    if "delegates" in writes_of(d, "delegate(") and "checkpoints" in writes_of(d, "delegate("):
        tag({"delegate", "delegateBySig"}, "comp_votes", "delegates voting power (user op)", False)

    # --- FiatToken role family (Centre; gate: masterMinter() + blacklister()) ---
    if "masterMinter" in writes_of(d, "updateMasterMinter(") and "blacklisted" in writes_of(d, "blacklist("):
        tag({"updateMasterMinter"}, "fiattoken", "rotates masterMinter authority", True)
        tag({"updateBlacklister"}, "fiattoken", "rotates blacklister authority", True)
        tag({"updatePauser"}, "fiattoken", "rotates pauser authority", True)
        tag({"updateRescuer"}, "fiattoken", "rotates rescuer authority", True)
        tag({"blacklist"}, "fiattoken", "adds address to blacklist", True)
        tag({"unBlacklist"}, "fiattoken", "removes address from blacklist", True)
        tag({"configureMinter", "removeMinter"}, "fiattoken", "manages minter allowances", True)
        tag({"mint"}, "fiattoken", "mints tokens", False)
        tag({"burn"}, "fiattoken", "burns tokens", False)
        tag({"rescueERC20"}, "fiattoken", "rescues tokens", True)

    # --- OZ Pausable wrapper idiom (writes OZ `_paused`; non-standard names) ---
    for sig, i in d["functions"].items():
        w = set(i.get("writes") or [])
        if w and w <= {"_paused"}:
            out.setdefault(sig, ("oz_pausable_var", "toggles OZ pause state", True))

    # --- ERC4626-ish vault (gate: asset() + deposit + withdraw) — none in sample ---

    # --- WETH idiom (gate: deposit()+withdraw(uint256)+ERC20) ---
    if "ERC20" in ercs and "deposit()" in S and "withdraw(uint256)" in S:
        tag({"deposit", "fallback"}, "weth", "wraps ETH (user deposit)", False)
        tag({"withdraw"}, "weth", "unwraps ETH (user withdrawal)", False)

    # --- LayerZero OApp core (gate: peers/endpoint views) ---
    if "setPeer(uint32,bytes32)" in S and ("peers(uint32)" in S or "endpoint()" in S):
        tag({"setPeer"}, "lz_oapp", "sets trusted remote peer", True)
        tag({"setDelegate"}, "lz_oapp", "sets endpoint delegate", True)

    return out


def main():
    total_sc = 0
    matched_sc = 0
    per_std = defaultdict(int)
    residue_all = []
    for path in sorted(glob.glob(os.path.join(HERE, "runs", "*.json"))):
        d = json.load(open(path))
        m = match_contract(d)
        sc_fns = [sig for sig, i in d["functions"].items() if i.get("state_changing")]
        total_sc += len(sc_fns)
        got = [sig for sig in sc_fns if sig in m]
        matched_sc += len(got)
        for sig in got:
            per_std[m[sig][0]] += 1
        residue = [sig for sig in sc_fns if sig not in m]
        residue_all.append((d["contract"], residue))
        print(f"== {d['contract']:34s} state_changing={len(sc_fns):3d} matched={len(got):3d}")
        for sig in sorted(m):
            std, sem, ctl = m[sig]
            print(f"   {sig.split('(')[0]:38s} -> {std:18s} {sem}")
    print("\nTOTAL state-changing fns:", total_sc, " matched:", matched_sc,
          f"({100*matched_sc/total_sc:.0f}%) residue:", total_sc - matched_sc)
    print("\nper-standard matches:", dict(per_std))
    print("\n== RESIDUE (facts-only under H3) ==")
    for c, residue in residue_all:
        if residue:
            print(f"  {c}: {', '.join(s.split('(')[0] for s in sorted(residue))}")


if __name__ == "__main__":
    main()
