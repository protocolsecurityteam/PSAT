// Plain-language readings of the scorer's capability ids, for the "?" beside
// a deduction row's label. The set is FIXED: these are exactly the keys of the
// scorer's BASE_SEVERITY table (services/scoring/constants.py) — the only
// capabilities a scored finding can carry. An id without an entry gets no "?"
// at all: a missing definition must not be papered over with a guessed one.
export const CAPABILITY_GLOSSARY = {
  "upgrade.implementation":
    "Replace the contract's implementation code behind its proxy. The holder can change what the contract does entirely — including the logic that guards its funds.",
  "authority.replace":
    "Swap out the address the contract's permission checks defer to (its owner or authority registry). Replacing it hands over every permission that authority gates.",
  "roles.grant":
    "Grant roles on a role registry — including, potentially, to the caller itself. Roles are what gate the registry's protected functions.",
  "roles.revoke":
    "Revoke roles from their current holders, stripping other operators — including safety actors like pausers — of their permissions.",
  "roles.configure":
    "Rewire which role a protected function requires. This changes who may call what without ever granting or revoking a role directly.",
  "authorized_caller.rotate":
    "Rotate an allow-listed caller address the contract trusts, letting the holder substitute an address under their own control.",
  "ownership.transfer":
    "Transfer the contract's ownership to a new address. The new owner inherits every owner-gated function.",
  "pause.set":
    "Freeze contract operation, blocking user actions such as deposits, withdrawals, or transfers until it is unpaused.",
  "transfer_policy.configure":
    "Change the policy that governs transfers — allow/deny lists or transfer restrictions — for the asset or system it covers.",
  "timelock.set_delay":
    "Change a timelock's delay — including shortening the waiting period that gives users time to react to queued actions.",
  "lz_oapp.set_peer":
    "Set the trusted remote peer of a LayerZero app. Cross-chain messages are accepted from whatever address this points at, so the holder chooses who can speak as the other chain.",
  "lz_oapp.set_delegate":
    "Set the LayerZero delegate — an address allowed to change the app's cross-chain messaging configuration (peers, libraries, security settings) on the endpoint.",
  "delegatecall.execute":
    "Execute arbitrary code via delegatecall in the contract's own storage context. That is full control of the contract's state — equivalent to rewriting the contract.",
  "exec.arbitrary":
    "Make the contract call any target with any calldata. Everything the contract itself is trusted or funded to do becomes exercisable by the holder.",
  "flow.out":
    "Move value out of the contract — send its tokens or native currency to some destination.",
};

export function capabilityDefinition(capability) {
  return CAPABILITY_GLOSSARY[capability] || null;
}
