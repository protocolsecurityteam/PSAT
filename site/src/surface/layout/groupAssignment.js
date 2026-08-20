// Contract→group assignment for the surface canvas: which principal's box a
// contract renders inside, and the per-group controller rows. Split from
// elkLayout.js; consumed by buildGraphLayout and the elkLayout driver.

import { entityKey } from "../entityKey.js";
import { principalBadge } from "../format.js";

// Every principal (Safe / Timelock / EOA / proxy admin) that owns at
// least this many contracts becomes a group container. We default to 1
// — a Safe that touches a single contract still gets a labeled box,
// matching the visual the user wants for EOAs as well. Principals that
// the server didn't mark primary for any contract drop off the canvas
// entirely; they remain addressable via search and sidebar.
const MIN_GROUP_SIZE = 1;

// Compute the contract→group assignment used by both buildGraphLayout
// (for node parentId + edge filtering) and elkLayout (for ELK compound
// children).
//
// The server's primary-controller assignment (services.governance.
// primary_controller, exposed as principal.primary_for) is the source
// of truth: a contract belongs to principal P's group iff P.primary_for
// includes it. That's the same decision monitoring enrollment uses, so
// the canvas and the Monitoring tab never disagree about who governs
// what. We previously derived this client-side from principal.controls
// + a local priority constant, which double-counted state-variable
// destinations (e.g. payoutAddress Safes) that have no call authority.
//
// Returns:
//   contractToGroup: Map<contractAddr_lc, principalAddr_lc>
//   groupChildren:   Map<principalAddr_lc, contractAddr_lc[]>
//   groupedPrincipals: Set<principalAddr_lc> (principals materialized as a group)
export function assignGroups(machines, principals) {
  const contractAddrs = new Set();
  for (const m of machines) {
    if (m.address) contractAddrs.add(m.address.toLowerCase());
  }

  const principalAddrs = new Set(
    (principals || []).map((p) => p?.address?.toLowerCase()).filter(Boolean),
  );
  // Server-published placement override for governance mediators (contract
  // .grouped_with): a passthrough timelock/proxy-admin renders inside the
  // group holding the contracts it operates on, not its driver's group —
  // primary_for still names the driver, so the Controllers accordion and
  // every authority claim stay truthful. Honored only when the target is a
  // known principal; otherwise the primary_for placement stands.
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
      // Overridden mediators join their operand group below instead.
      if (groupedWith.has(lc) && groupedWith.get(lc) !== principalAddr) continue;
      // A contract should only ever appear in one principal's primary_for
      // (server enforces this), but defensively skip duplicates.
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

// Build the Controllers-accordion model for one group: the primary owner
// first, then every co-controller that holds authority on a contract inside
// this group. Each row carries the contracts it governs WITHIN this group,
// with the concrete functions + capability tags it can call on each — all
// scoped to the group's own children, so a co-controller spanning several
// groups shows only the authority relevant to the box it's rendered in.
//
// Capability tags are taken verbatim from controls_detail[].capabilities
// (the shared _EFFECT_CAPABILITY vocabulary: pause / upgrade / fund-out / …)
// and unioned per row — never remapped, so a row reads the same word the
// per-contract chips do.
export function buildGroupControllers(primary, kids, principalList, nameByAddr, chain = "ethereum") {
  const childOrder = kids; // group's child addresses (lc), in owned order
  const childSet = new Set(kids);

  const rowFor = (principal, isPrimary) => {
    // Keyed by (chain, address). A controls_detail row carries its own
    // chain, so a twin-governing principal's two same-address rows key to their
    // own chains — only the row on the page's active chain matches a visible kid
    // below; the other-chain row finds no child and is dropped. Legacy rows with
    // no chain fall back to the active chain, keying exactly as before.
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
      // Unioned function names — the row summary falls back to these (like the
      // sidebar's "Can Call") for controllers whose functions map to no
      // high-level capability tag, so the summary is never blank.
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
    // primary_for counts too: a grouped_with machinery contract renders in
    // this box while ANOTHER principal primary-controls it — that controller
    // must appear as a controller row here (it may have no other canvas
    // footprint at all when this was its only owned contract).
    const owns = Array.isArray(q.primary_for) ? q.primary_for : [];
    if (
      !co.some((c) => childSet.has(c?.toLowerCase())) &&
      !owns.some((c) => childSet.has(c?.toLowerCase()))
    )
      continue;
    const row = rowFor(q, false);
    // The authority list says it has rights here; if we have no verified
    // function detail for any of this group's contracts there's nothing to
    // show, so skip the empty row rather than render "governs 0".
    if (row.governs.length === 0) continue;
    coRows.push(row);
  }
  // Most-capable co-controllers first; deterministic tie-breaks keep the
  // layout (and visual snapshots) stable across renders.
  coRows.sort(
    (a, b) =>
      b.governs.length - a.governs.length ||
      b.capabilities.length - a.capabilities.length ||
      a.address.localeCompare(b.address),
  );
  return controllers.concat(coRows);
}

// `bandHeights` ({ groupId: px }) reserves each group's real header-band
// height. GroupNode measures the rendered band (colored bar + Controllers
// accordion, including any capability summary that wraps to several lines) and
// reports it per group; we reserve that exact height so ELK packs the canvas
// to fit (rather than a wrapped row overflowing / overlapping cards). Until a
