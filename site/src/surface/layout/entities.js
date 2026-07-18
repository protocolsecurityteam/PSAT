// Address-keyed entity index for surface selection. Pure — no React.
// One entry per address covering BOTH facets a surface entity can have: the
// contract "machine" (function lanes) and the principal (safe/EOA/timelock).
// Timelocks legitimately carry both. Selection state stores addresses only and
// resolves entities through this index per render, so denormalized snapshots
// can never go stale.

import { isRoleIdAddress } from "../format.js";
import { entityKey } from "../entityKey.js";

// Build from ALL machines and ALL principals — visibility (role filter,
// canvas culling) stays a canvas/search concern, not an index concern.
// Role-id pseudo addresses (mapping keys coerced to addresses) are excluded;
// they are never real selectable entities.
//
// Keyed by (chain, address) (inv. 13), not bare address: the Surface page is
// chain-scoped, so `chain` is the active chain and every entity in one index
// shares it — but the composite key means the same address on a different chain
// can never alias into this index. `chain` defaults to mainnet so legacy
// single-chain callers/tests are unaffected. Each entity still stores its bare
// `address` for display; the key is identity only.
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

// Resolve an address to an entity. Index hit wins. Otherwise this is the ONE
// place a minimal principal shape is synthesized (replaces the old inline
// navigateToPrincipal fallback) — for navigate targets like per-function
// caller buttons whose address isn't a first-class machine/principal. `hint`
// carries
// { type, label, details } from the navigate target; `type` defaults to
// 'unknown' (the entity card falls back to TYPE_META.unknown). `controls` is
// derived from the machines that name this address as owner.
export function resolveEntity(index, address, { machines = [], hint = null, chain = "ethereum" } = {}) {
  if (!address) return null;
  const lc = String(address).toLowerCase();
  const hit = index?.get(entityKey(chain, lc));
  if (hit) return hit;

  // A role-id pseudo address is never a real entity — buildEntityIndex already
  // excludes them from the index, so synthesizing one here would be the only
  // path back to a bogus principal card. Guard it for symmetry.
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
