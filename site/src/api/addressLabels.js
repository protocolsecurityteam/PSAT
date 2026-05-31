// Thin API wrappers for /api/address_labels/*. See api.py for the server
// shapes. Admin mutations (put/delete) use the shared api() helper so the
// X-PSAT-Admin-Key header is auto-injected; a missing/invalid key triggers
// the built-in 401 prompt-retry flow.
//
// Labels are per-(address, chain): the same address can carry a different
// name on different networks, so the chain is part of the key everywhere.

import { api } from "./client.js";

export function listAddressLabels() {
  return api("/api/address_labels");
}

// Build a Map keyed by `${chain}:${address}` (both lowercased) → name from the
// /api/address_labels response (`{ labels: { "<chain>:<addr>": {address, chain,
// name, ...} } }`).
export function buildLabelMap(resp) {
  const m = new Map();
  const labels = resp?.labels || {};
  for (const info of Object.values(labels)) {
    if (!info || !info.address) continue;
    const chain = String(info.chain || "ethereum").toLowerCase();
    const addr = String(info.address).toLowerCase();
    m.set(`${chain}:${addr}`, info.name);
  }
  return m;
}

// Look up a label by (address, chain). Defaults chain to ethereum and falls
// back to the ethereum label when the requested chain has none, so callers
// that don't know the chain still get the common-case label.
export function lookupLabel(map, address, chain = "ethereum") {
  if (!map || typeof map.get !== "function") return null;
  const addr = String(address || "").toLowerCase();
  const c = String(chain || "ethereum").toLowerCase();
  return map.get(`${c}:${addr}`) ?? map.get(`ethereum:${addr}`) ?? null;
}

function chainQuery(chain) {
  return `?chain=${encodeURIComponent(String(chain || "ethereum"))}`;
}

export function upsertAddressLabel(address, name, note = null, chain = "ethereum") {
  const body = note == null ? { name } : { name, note };
  return api(`/api/address_labels/${encodeURIComponent(address)}${chainQuery(chain)}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export function deleteAddressLabel(address, chain = "ethereum") {
  return api(`/api/address_labels/${encodeURIComponent(address)}${chainQuery(chain)}`, {
    method: "DELETE",
  });
}
