import { entityKey } from "../entityKey.js";

// Controls-detail rows keyed by each row's OWN chain when present — twin rows
// share a bare address, so keying them all to the active chain would last-wins
// one chain's functions onto the other (inv. 13). Rows without a chain (legacy
// payloads) fall back to the active chain and attach exactly as before.
export function buildControlsDetailMap(rows, chain) {
  const map = new Map();
  for (const d of rows || []) {
    if (d?.address) map.set(entityKey(d.chain ?? chain, d.address), d);
  }
  return map;
}
