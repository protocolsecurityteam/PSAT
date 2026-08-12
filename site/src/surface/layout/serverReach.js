// Consumption of the server-computed reach block (`companyData.reach`, model
// scorer_closure_v1 — SURFACE_REACH_UNIFICATION_SPEC.md). The scorer walks;
// the client only follows the keys it shipped. Pure — no React.
//
// Payload keys are composite "<chain>::<addr>" entity keys; the canvas keys
// nodes by bare lowercased address on the single active chain, so everything
// here is projected through the chain filter (inv. 13) down to bare addresses.

import { coalesceChain, entityKey } from "../entityKey.js";

// "<chain>::<addr>" → bare lowercased address when the key is on ``chain``,
// else null. No active chain means the page is single-chain and every key is
// kept — same convention as flowOnChain / principalOnChain.
function keyOnChain(key, chain) {
  const s = String(key || "");
  const sep = s.indexOf("::");
  if (sep < 0) return null;
  if (chain && coalesceChain(s.slice(0, sep)) !== coalesceChain(chain)) return null;
  const addr = s.slice(sep + 2).trim().toLowerCase();
  return addr || null;
}

// The selected entity's server reach record, projected into what the canvas
// and the Governs tab render:
//   distances     — Map<addrLc, hop> over `reached` (the walked state);
//   pathEdges     — Set<"from>to"> reconstructed from `parents` (the walk tree
//                   behind the hop counts — the routes the canvas lights);
//   frontier      — Map<destination addrLc, { from, to, reason, basis }> over
//                   the not_determined entries, first entry per destination.
//                   Not drawn on the canvas (proven reach only, owner ruling
//                   2026-08-12); it feeds the Governs tab's count line.
//
// Null when the payload carries no reach block or no record for this entity —
// absence of the witness is not reach, and the caller renders no overlay at
// all (fail closed).
export function deriveReachOverlay(reach, chain, address) {
  const self = String(address || "").toLowerCase();
  if (!self) return null;
  const record = reach?.entities?.[entityKey(chain, self)];
  if (!record) return null;

  const distances = new Map();
  for (const [key, value] of Object.entries(record.reached || {})) {
    const addr = keyOnChain(key, chain);
    // The hop is the witness of the walked distance; an entry without one is
    // not published as reached.
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
    // Reached wins — the server merges this way too (spec, fold.py:6101);
    // re-asserted so a payload carrying both can never render a walked node
    // as unconfirmed.
    if (to === self || distances.has(to)) continue;
    if (!frontier.has(to)) {
      frontier.set(to, { from, to, reason: entry.reason || null, basis: entry.basis || null });
    }
  }

  return { distances, pathEdges, frontier };
}
