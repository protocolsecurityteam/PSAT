// Address-keyed entity index for surface selection. Pure — no React.
// One entry per address covering BOTH facets a surface entity can have: the
// contract "machine" (function lanes) and the principal (safe/EOA/timelock).
// Timelocks legitimately carry both. Selection state stores addresses only and
// resolves entities through this index per render, so denormalized snapshots
// can never go stale.

import { isRoleIdAddress } from "../format.js";

// Build from ALL machines and ALL principals — visibility (role filter,
// canvas culling) stays a canvas/search concern, not an index concern.
// Role-id pseudo addresses (mapping keys coerced to addresses) are excluded;
// they are never real selectable entities.
export function buildEntityIndex(allMachines = [], principals = []) {
  const index = new Map();
  const put = (address, patch) => {
    if (!address) return;
    const lc = String(address).toLowerCase();
    if (isRoleIdAddress(lc)) return;
    const existing = index.get(lc) || { address: lc, machine: null, principal: null };
    index.set(lc, { ...existing, ...patch });
  };
  for (const machine of allMachines) put(machine?.address, { machine });
  for (const principal of principals) put(principal?.address, { principal });
  return index;
}

// Resolve an address to an entity. Index hit wins. Otherwise this is the ONE
// place a minimal principal shape is synthesized (replaces the old inline
// navigateToPrincipal fallback) — for navigate targets like `other_callers`
// chips whose address isn't a first-class machine/principal. `hint` carries
// { type, label, details } from the navigate target; `type` defaults to
// 'unknown' (PrincipalDetail falls back to TYPE_META.unknown). `controls` is
// derived from the machines that name this address as owner.
export function resolveEntity(index, address, { machines = [], hint = null } = {}) {
  if (!address) return null;
  const lc = String(address).toLowerCase();
  const hit = index?.get(lc);
  if (hit) return hit;

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

// Every address a principal touches: itself plus every contract it controls,
// co-controls, or has verified call rights on (controls_detail). Lowercased.
export function principalTouchSet(principal) {
  const set = new Set();
  const self = principal?.address?.toLowerCase();
  if (self) set.add(self);
  for (const a of principal?.controls || []) if (a) set.add(String(a).toLowerCase());
  for (const a of principal?.co_controls || []) if (a) set.add(String(a).toLowerCase());
  for (const d of principal?.controls_detail || []) {
    if (d?.address) set.add(String(d.address).toLowerCase());
  }
  return set;
}

// Canvas highlight overlay for a selected principal that owns no canvas node
// (a co-controller safe that isn't the primary owner of any visible contract).
// Returns the touch set to dim the canvas around, or null when the principal
// is group-backed (canvasNodeAddrs has it — the canvas keeps its own
// ring/focus) or reaches nothing on-canvas beyond itself (a highlight would
// blank the canvas and ring nothing).
export function nodelessPrincipalHighlight(principal, canvasNodeAddrs) {
  const addr = principal?.address?.toLowerCase();
  if (!addr) return null;
  if (canvasNodeAddrs && canvasNodeAddrs.has(addr)) return null;
  const set = principalTouchSet(principal);
  set.delete(addr); // the principal itself owns no node — only its reach matters
  if (!set.size) return null;
  // If none of the reach is actually on the canvas there is nothing to ring;
  // emitting the set anyway would dim every node and highlight none (a blank
  // canvas), which is worse than the no-op. Require at least one visible touch.
  if (canvasNodeAddrs && ![...set].some((a) => canvasNodeAddrs.has(a))) return null;
  return set;
}
