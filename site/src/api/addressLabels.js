// Thin API wrappers for /api/address_labels/*. See api.py for the server
// shapes. Admin mutations (put/delete) use the shared api() helper so the
// X-PSAT-Admin-Key header is auto-injected; a missing/invalid key triggers
// the built-in 401 prompt-retry flow.
//
// Global-plus-override model (invariant 12): a label is either GLOBAL (applies
// on every chain — the right thing for EOA/Safe-signer accounts) or
// CHAIN-QUALIFIED (overrides the global label for one network — the right thing
// for contracts, which are a different deployment at the same address per
// chain). Omit `chain` to operate on the global row; pass it for the override.

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

// Build lookup maps from the /api/address_labels response. Returns
// `{ global: Map<addr,name>, byChain: Map<chain, Map<addr,name>> }`. Addresses
// are lowercased so lookups are case-insensitive. Tolerant of the legacy shape
// (a response with only `labels` and no `chain_labels`).
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

// Chain-specific-wins-else-global lookup. A chain-qualified label for
// (address, chain) overrides the global one; with no chain, or no override for
// that chain, the global label is returned. Missing -> null.
export function lookupLabel(maps, address, chain = null) {
  const addr = String(address || "").toLowerCase();
  if (chain) {
    const m = maps?.byChain?.get?.(chain);
    if (m && m.has(addr)) return m.get(addr) ?? null;
  }
  return maps?.global?.get?.(addr) ?? null;
}

// Resolve the display name from either shape AddressLabelInline may be handed:
// a plain Map<addr,name> (legacy global-only callers) or the maps struct from
// buildLabelMaps (chain-aware callers). Keeps the component's `labels` prop
// backward compatible.
export function resolveLabelName(labels, address, chain = null) {
  const addr = String(address || "").toLowerCase();
  if (labels && typeof labels.get === "function" && !("global" in labels)) {
    return labels.get(addr) ?? null;
  }
  return lookupLabel(labels, addr, chain);
}
