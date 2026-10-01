import { entityKey } from "../entityKey.js";

// Keyed by each row's own chain so twins don't overwrite each other;
// chainless legacy rows use the active chain.
export function buildControlsDetailMap(rows, chain) {
  const map = new Map();
  for (const d of rows || []) {
    if (d?.address) map.set(entityKey(d.chain ?? chain, d.address), d);
  }
  return map;
}
