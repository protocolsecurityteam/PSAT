
import { entityKey } from "../entityKey.js";
import { principalBadge } from "../format.js";

// Principals with no primary_for drop off the canvas but stay searchable.
const MIN_GROUP_SIZE = 1;

// Contract → group from the server's primary-controller assignment
// (principal.primary_for), the same decision enrollment uses. Client-side
// derivation double-counted state-variable destinations.
//
// Returns contractToGroup, groupChildren and groupedPrincipals.
export function assignGroups(machines, principals) {
  const contractAddrs = new Set();
  for (const m of machines) {
    if (m.address) contractAddrs.add(m.address.toLowerCase());
  }

  const principalAddrs = new Set(
    (principals || []).map((p) => p?.address?.toLowerCase()).filter(Boolean),
  );
  // Server placement override (contract.grouped_with): a passthrough mediator
  // renders with the contracts it operates on; primary_for still names the
  // driver. Only honoured for known principals.
  const groupedWith = new Map();
  for (const m of machines) {
    const lc = m.address?.toLowerCase();
    const gw = typeof m.grouped_with === "string" ? m.grouped_with.toLowerCase() : null;
    if (lc && gw && gw !== lc && principalAddrs.has(gw)) groupedWith.set(lc, gw);
  }

  const contractToGroup = new Map();
  const groupChildren = new Map();

  for (const p of principals || []) {
    const principalAddr = p?.address?.toLowerCase();
    if (!principalAddr) continue;
    const primary = Array.isArray(p.primary_for) ? p.primary_for : [];
    const owned = [];
    for (const c of primary) {
      const lc = c?.toLowerCase();
      if (!lc || lc === principalAddr) continue;
      if (!contractAddrs.has(lc)) continue;
      if (groupedWith.has(lc) && groupedWith.get(lc) !== principalAddr) continue;
      // The server enforces one primary per contract; skip duplicates
      // defensively.
      if (contractToGroup.has(lc)) continue;
      contractToGroup.set(lc, principalAddr);
      owned.push(lc);
    }
    for (const [lc, gw] of groupedWith) {
      if (gw !== principalAddr || !contractAddrs.has(lc)) continue;
      if (contractToGroup.has(lc)) continue;
      contractToGroup.set(lc, principalAddr);
      owned.push(lc);
    }
    if (owned.length >= MIN_GROUP_SIZE) {
      groupChildren.set(principalAddr, owned);
    }
  }

  return {
    contractToGroup,
    groupChildren,
    groupedPrincipals: new Set(groupChildren.keys()),
  };
}

// Controllers accordion model: primary first, then co-controllers, each scoped
// to this group's children. Capability tags are unioned verbatim from
// controls_detail.
export function buildGroupControllers(primary, kids, principalList, nameByAddr, chain = "ethereum") {
  const childOrder = kids;
  const childSet = new Set(kids);

  const rowFor = (principal, isPrimary) => {
    // A twin-governing principal's other-chain row finds no child and drops
    // out; chainless legacy rows use the active chain.
    const detailByAddr = new Map();
    for (const d of principal.controls_detail || []) {
      if (d?.address) detailByAddr.set(entityKey(d.chain ?? chain, d.address), d);
    }
    const governs = [];
    const caps = new Set();
    const funcs = new Set();
    for (const childLc of childOrder) {
      const d = detailByAddr.get(entityKey(chain, childLc));
      if (!d) continue;
      const functions = Array.isArray(d.functions) ? d.functions : [];
      const capabilities = Array.isArray(d.capabilities) ? d.capabilities : [];
      if (functions.length === 0 && capabilities.length === 0) continue;
      governs.push({ address: childLc, name: nameByAddr.get(childLc) || childLc, capabilities, functions });
      for (const c of capabilities) caps.add(c);
      for (const f of functions) funcs.add(f);
    }
    governs.sort((a, b) => a.name.localeCompare(b.name));
    return {
      address: principal.address,
      type: principal.type,
      isPrimary,
      label: principalBadge(principal),
      capabilities: [...caps].sort(),
      // Fallback for the summary when no tag maps.
      functions: [...funcs].sort(),
      governs,
    };
  };

  const primaryAddrLc = primary.address?.toLowerCase();
  const controllers = [rowFor(primary, true)];

  const coRows = [];
  for (const q of principalList) {
    const qLc = q.address?.toLowerCase();
    if (!qLc || qLc === primaryAddrLc) continue;
    const co = Array.isArray(q.co_controls) ? q.co_controls : [];
    // A grouped_with contract's real controller must appear here; it may have
    // no other canvas footprint.
    const owns = Array.isArray(q.primary_for) ? q.primary_for : [];
    if (
      !co.some((c) => childSet.has(c?.toLowerCase())) &&
      !owns.some((c) => childSet.has(c?.toLowerCase()))
    )
      continue;
    const row = rowFor(q, false);
    if (row.governs.length === 0) continue;
    coRows.push(row);
  }
  // Deterministic so layout and snapshots are stable.
  coRows.sort(
    (a, b) =>
      b.governs.length - a.governs.length ||
      b.capabilities.length - a.capabilities.length ||
      a.address.localeCompare(b.address),
  );
  return controllers.concat(coRows);
}

