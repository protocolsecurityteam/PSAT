// Filter + sort the machines/principals list for SearchNavigator. Pure.

import { principalLabel } from "../format.js";

export function buildSearchResults(machines, principals, mode, sortKey, query) {
  let items = [];

  if (mode === "safe" || mode === "eoa" || mode === "timelock") {
    // Show principals of this type
    const targetType = mode;
    for (const p of principals) {
      if (p.type !== targetType) continue;
      const controlled = (p.controls || []);
      const controlledMachines = machines.filter((m) =>
        controlled.some((a) => a.toLowerCase() === m.address?.toLowerCase())
      );
      const totalValue = controlledMachines.reduce((sum, m) => sum + (m.total_usd || 0), 0);
      const signers = p.details?.threshold || (p.details?.owners?.length) || 0;
      const delay = p.details?.delay || 0;
      items.push({
        kind: "principal",
        address: p.address,
        name: principalLabel(p.label, p.type, p.address),
        type: p.type,
        value: totalValue,
        signers,
        ownersCount: p.details?.owners?.length || 0,
        delay,
        functions: controlled.length,
      });
    }
    // Timelock contracts (control-graph type=timelock) aren't principals, but
    // they belong under the Timelocks filter just like timelock principals.
    // Surface them as contract results, deduped against any principal already
    // added at the same address.
    if (mode === "timelock") {
      const seen = new Set(items.map((i) => i.address?.toLowerCase()));
      for (const m of machines) {
        if (!m.isTimelock) continue;
        const lc = m.address?.toLowerCase();
        if (seen.has(lc)) continue;
        seen.add(lc);
        items.push({
          kind: "contract",
          address: m.address,
          name: m.name || "",
          type: "timelock",
          value: m.total_usd || 0,
          signers: 0,
          ownersCount: 0,
          delay: m.timelockDelay || 0,
          functions: m.totalFunctions || 0,
        });
      }
    }
  } else {
    // Show contracts
    for (const m of machines) {
      const ownerPrincipal = principals.find((p) =>
        (p.controls || []).some((a) => a.toLowerCase() === m.address?.toLowerCase())
      );
      items.push({
        kind: "contract",
        address: m.address,
        name: m.name || "",
        type: ownerPrincipal?.type || "unknown",
        value: m.total_usd || 0,
        signers: ownerPrincipal?.details?.threshold || 0,
        ownersCount: ownerPrincipal?.details?.owners?.length || 0,
        delay: 0,
        functions: m.totalFunctions || 0,
      });
    }
    if (mode === "funds") items = items.filter((i) => i.value > 0);
  }

  // Text query
  if (query) {
    const q = query.toLowerCase().trim();
    const minMatch = q.match(/(?:min(?:imum)?\s*)?value\s*(?:of\s*|>\s*|>=\s*)?\$?(\d+(?:\.\d+)?)\s*(m|k)?/i);
    if (minMatch) {
      let threshold = parseFloat(minMatch[1]);
      const unit = (minMatch[2] || "").toLowerCase();
      if (unit === "m") threshold *= 1e6;
      else if (unit === "k") threshold *= 1e3;
      items = items.filter((i) => i.value >= threshold);
    } else {
      items = items.filter((i) => {
        const haystack = [i.name, i.address, i.type].join(" ").toLowerCase();
        return haystack.includes(q);
      });
    }
  }

  // Sort
  if (sortKey === "value") items.sort((a, b) => b.value - a.value);
  else if (sortKey === "signers") items.sort((a, b) => b.signers - a.signers);
  else if (sortKey === "functions") items.sort((a, b) => b.functions - a.functions);
  else if (sortKey === "name") items.sort((a, b) => a.name.localeCompare(b.name));

  return items;
}
