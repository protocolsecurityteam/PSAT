// A capability id as a phrase for callouts and the fix-first line,
// singular/plural. Unmapped ids render as themselves.
const CAPABILITY_PHRASE = {
  "authority.replace": ["authority hole", "authority holes"],
  "authorized_caller.rotate": ["caller rotation", "caller rotations"],
  "delegatecall.execute": ["delegatecall hole", "delegatecall holes"],
  "exec.arbitrary": ["arbitrary-call hole", "arbitrary-call holes"],
  "flow.out": ["outflow path", "outflow paths"],
  "lz_oapp.set_delegate": ["bridge-delegate control", "bridge-delegate controls"],
  "lz_oapp.set_peer": ["bridge-peer control", "bridge-peer controls"],
  "ownership.transfer": ["ownership handle", "ownership handles"],
  "pause.set": ["freeze switch", "freeze switches"],
  "roles.configure": ["role configuration", "role configurations"],
  "roles.grant": ["role grant", "role grants"],
  "roles.revoke": ["role revocation", "role revocations"],
  "timelock.set_delay": ["delay control", "delay controls"],
  "transfer_policy.configure": ["transfer-policy control", "transfer-policy controls"],
  "upgrade.implementation": ["upgrade path", "upgrade paths"],
};

export function capabilityPhrase(capability, count) {
  const entry = CAPABILITY_PHRASE[capability];
  if (!entry) return String(capability || "");
  return count === 1 ? entry[0] : entry[1];
}

// Exported so parallel maps (the glossary) can assert they cover the same set.
export const CAPABILITY_PHRASE_IDS = Object.freeze(Object.keys(CAPABILITY_PHRASE));
