// Helpers for separating "active" addresses from "historical implementations"
// in the AddressesModal. The address inventory legitimately keeps every past
// proxy implementation (the audit-matcher pairs reports named for an old impl
// to the new address by walking these rows), so they have to remain in the
// API response — but stacking 16 past EtherFiNodesManager rows next to the
// current one visually dominates the company page.
//
// Logic:
//   - A row is "active" if it surfaced from a high-confidence discovery source
//     (deployer expansion, inventory, AI/SPA crawls), OR
//   - it is the implementation address currently behind one of the proxies in
//     the same payload (so an upgrade_history-tagged row stays visible when
//     it's the live impl).
// Otherwise it's "pure historical" — a past implementation that has since
// been replaced.

export const HIGH_SOURCES = new Set([
  "deployer_expansion",
  "defillama",
  "ai_inventory",
  "exa_deep_research",
  "inventory",
  "spa_override",
  "dependency_two_pass",
]);

export function computeCurrentImplAddrs(rows) {
  const set = new Set();
  for (const r of rows || []) {
    if (r?.is_proxy && r?.implementation_address) {
      set.add(String(r.implementation_address).toLowerCase());
    }
  }
  return set;
}

export function isPureHistorical(row, currentImplAddrs) {
  const sources = row?.discovery_sources || [];
  const hasHigh = sources.some((s) => HIGH_SOURCES.has(s));
  if (hasHigh) return false;
  const addr = String(row?.address || "").toLowerCase();
  if (currentImplAddrs.has(addr)) return false;
  return true;
}

export function splitHistorical(rows) {
  const list = rows || [];
  const current = computeCurrentImplAddrs(list);
  const active = [];
  const historical = [];
  for (const r of list) {
    if (isPureHistorical(r, current)) historical.push(r);
    else active.push(r);
  }
  return { active, historical, currentImplAddrs: current };
}

// Rows eligible for the bulk "Analyze pending" action: discovered-but-not-
// analyzed addresses that survive the historical filter. The caller passes
// the current view (already filtered/searched/sorted), but we re-apply the
// historical guard here so a user with "Show historical" toggled on can't
// accidentally enqueue 90 stale impls.
export function bulkAnalyzeCandidates(rows, currentImplAddrs) {
  const out = [];
  for (const r of rows || []) {
    if (!r || !r.address) continue;
    if (r.analyzed) continue;
    if (r._compareStatus) continue; // compare-mode synthesized rows
    if (isPureHistorical(r, currentImplAddrs)) continue;
    out.push(r);
  }
  return out;
}
