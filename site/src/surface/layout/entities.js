// Entity index for selection: one entry per address covering both facets
// (machine and principal).

import { isRoleIdAddress } from "../format.js";
import { entityKey } from "../entityKey.js";

// Built from all machines and principals; visibility is a canvas concern.
// Role-id pseudo addresses are excluded. Keyed by (chain, address) (inv. 13) so
// another chain's address can't alias in.
export function buildEntityIndex(allMachines = [], principals = [], chain = "ethereum") {
  const index = new Map();
  const put = (address, patch) => {
    if (!address) return;
    const lc = String(address).toLowerCase();
    if (isRoleIdAddress(lc)) return;
    const key = entityKey(chain, lc);
    const existing = index.get(key) || { address: lc, machine: null, principal: null };
    index.set(key, { ...existing, ...patch });
  };
  for (const machine of allMachines) put(machine?.address, { machine });
  for (const principal of principals) put(principal?.address, { principal });
  return index;
}

// Index hit wins; otherwise the one place a minimal principal is synthesized,
// for navigate targets that aren't first-class entities. `hint` carries { type,
// label, details }.
export function resolveEntity(index, address, { machines = [], hint = null, chain = "ethereum" } = {}) {
  if (!address) return null;
  const lc = String(address).toLowerCase();
  const hit = index?.get(entityKey(chain, lc));
  if (hit) return hit;

  // Symmetric with buildEntityIndex's exclusion.
  if (isRoleIdAddress(lc)) return null;

  const type = hint?.type || "unknown";
  const principal = {
    address: lc,
    type,
    label: hint?.label || type,
    details: hint?.details || {},
    controls: machines
      .filter((m) => m.owner?.toLowerCase() === lc)
      .map((m) => m.address),
  };
  return { address: lc, machine: null, principal };
}
