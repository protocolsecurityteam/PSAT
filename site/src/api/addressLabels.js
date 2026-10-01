// /api/address_labels wrappers. A label is global (EOAs/Safe signers) or a
// chain-qualified override (contracts differ per chain); omit
// `chain` for the global row.

import { api } from "./client.js";

export function listAddressLabels() {
  return api("/api/address_labels");
}

export function upsertAddressLabel(address, name, note = null, chain = null) {
  const body = note == null ? { name } : { name, note };
  const q = chain ? `?chain=${encodeURIComponent(chain)}` : "";
  return api(`/api/address_labels/${encodeURIComponent(address)}${q}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export function deleteAddressLabel(address, chain = null) {
  const q = chain ? `?chain=${encodeURIComponent(chain)}` : "";
  return api(`/api/address_labels/${encodeURIComponent(address)}${q}`, {
    method: "DELETE",
  });
}

// `{ global, byChain }`, lowercased. Tolerates legacy responses without
// `chain_labels`.
export function buildLabelMaps(resp) {
  const global = new Map();
  for (const [addr, row] of Object.entries(resp?.labels || {})) {
    global.set(String(addr).toLowerCase(), row?.name);
  }
  const byChain = new Map();
  for (const [chain, rows] of Object.entries(resp?.chain_labels || {})) {
    const m = new Map();
    for (const [addr, row] of Object.entries(rows || {})) {
      m.set(String(addr).toLowerCase(), row?.name);
    }
    byChain.set(chain, m);
  }
  return { global, byChain };
}

// Chain-specific wins, else global, else null.
export function lookupLabel(maps, address, chain = null) {
  const addr = String(address || "").toLowerCase();
  if (chain) {
    const m = maps?.byChain?.get?.(chain);
    if (m && m.has(addr)) return m.get(addr) ?? null;
  }
  return maps?.global?.get?.(addr) ?? null;
}

// Accepts a legacy Map or the buildLabelMaps struct.
export function resolveLabelName(labels, address, chain = null) {
  const addr = String(address || "").toLowerCase();
  if (labels && typeof labels.get === "function" && !("global" in labels)) {
    return labels.get(addr) ?? null;
  }
  return lookupLabel(labels, addr, chain);
}
