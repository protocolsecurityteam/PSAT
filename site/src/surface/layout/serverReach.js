// Consumes the server reach block (scorer_closure_v1,
// SURFACE_REACH_UNIFICATION_SPEC.md); the client never re-walks. Composite keys
// are projected to bare addresses on the active chain (inv. 13).

import { coalesceChain, entityKey } from "../entityKey.js";

// No active chain keeps every key.
function keyOnChain(key, chain) {
  const s = String(key || "");
  const sep = s.indexOf("::");
  if (sep < 0) return null;
  if (chain && coalesceChain(s.slice(0, sep)) !== coalesceChain(chain)) return null;
  const addr = s.slice(sep + 2).trim().toLowerCase();
  return addr || null;
}

// Projects the entity's record:
// distances — hop per reached address;
// pathEdges — "from>to" pairs from `parents` (the routes the canvas lights);
// frontier — not_determined entries per destination; not drawn (owner ruling
//   2026-08-12), feeds the Governs count.
//
// Null without a block or record (fail closed).
export function deriveReachOverlay(reach, chain, address) {
  const self = String(address || "").toLowerCase();
  if (!self) return null;
  const record = reach?.entities?.[entityKey(chain, self)];
  if (!record) return null;

  const distances = new Map();
  for (const [key, value] of Object.entries(record.reached || {})) {
    const addr = keyOnChain(key, chain);
    // An entry without a hop isn't published as reached.
    if (!addr || addr === self || !Number.isFinite(value?.hop)) continue;
    distances.set(addr, value.hop);
  }

  const pathEdges = new Set();
  for (const [childKey, parentKey] of Object.entries(record.parents || {})) {
    const child = keyOnChain(childKey, chain);
    const parent = keyOnChain(parentKey, chain);
    if (!child || !parent || child === parent) continue;
    pathEdges.add(`${parent}>${child}`);
  }

  const frontier = new Map();
  for (const entry of record.frontier || []) {
    const from = keyOnChain(entry?.from, chain);
    const to = keyOnChain(entry?.to, chain);
    if (!from || !to) continue;
    // Reached wins, as on the server (fold.py:6101).
    if (to === self || distances.has(to)) continue;
    if (!frontier.has(to)) {
      frontier.set(to, { from, to, reason: entry.reason || null, basis: entry.basis || null });
    }
  }

  return { distances, pathEdges, frontier };
}
