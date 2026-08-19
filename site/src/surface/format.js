// Pure formatters + small predicates used across the surface tree.
// No React, no closures — safe to import from anywhere.

import { middleSlice } from "../shared/format.js";

export function shortAddr(address) {
  if (!address || address.length < 12) return address || "";
  return middleSlice(address, "..");
}

// Display name for a principal. The server label is sometimes just the bare
// type token (e.g. label "safe" on a type "safe" principal), which renders as
// "safe safe" beside the type badge. When the label adds nothing over the
// type, fall back to the short address. Shared by the search preview and
// the entity card so the fallback can't drift between them.
export function principalLabel(label, type, address) {
  const l = String(label || "").trim();
  if (l && l.toLowerCase() !== String(type || "").trim().toLowerCase()) return l;
  return shortAddr(address);
}

export function formatDelay(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value <= 0) return "";
  if (value >= 86400) return `${Math.round(value / 86400)}d`;
  if (value >= 3600) return `${Math.round(value / 3600)}h`;
  return `${Math.round(value / 60)}m`;
}

// Short type badge for a principal — "6/10 SAFE", "TL · 2d", or the bare
// type ("EOA", "PROXY_ADMIN"). Shared by the group header, the controllers
// accordion rows, and anywhere a principal needs a one-glance label so they
// never drift apart.
export function principalBadge(p) {
  const owners = Array.isArray(p?.details?.owners) ? p.details.owners : [];
  const threshold = p?.details?.threshold;
  const delay = p?.details?.delay;
  if (p?.type === "safe" && threshold) return `${threshold}/${owners.length || "?"} SAFE`;
  if (p?.type === "timelock" && delay) return `TL · ${formatDelay(delay)}`;
  return (p?.type || "").toUpperCase();
}

export function maskWebhook(url) {
  if (!url) return "";
  const value = String(url);
  if (value.length <= 24) return value;
  return `${value.slice(0, 18)}...${value.slice(-8)}`;
}

export function functionName(signature) {
  return String(signature || "?").split("(")[0] || "?";
}

// Light category tint for a function chip — upgrade/ownership, pause, and
// fund movements get a hint of color so the dangerous powers pop out of a
// long list. Everything else stays neutral. Polish, not load-bearing. Shared
// by the Controllers accordion and the contract card's Governs tab so the
// chips never drift apart.
export function fnChipClass(fn) {
  if (/upgrade|transferownership|renounceownership|setowner|changeadmin/i.test(fn)) return "ps-ctrl-fnchip--upgrade";
  if (/pause/i.test(fn)) return "ps-ctrl-fnchip--pause";
  if (/recover|withdraw|sweep|sendto|fund|claim|seize/i.test(fn)) return "ps-ctrl-fnchip--fund";
  return "";
}

export function isRoleConstant(name) {
  return /^[A-Z][A-Z0-9_]+$/.test(name);
}

export function hasHint(name, hints) {
  return hints.some((hint) => name.includes(hint));
}

export function isRoleIdAddress(address) {
  const hex = address.slice(2);
  const leadingZeros = hex.match(/^0*/)[0].length;
  return leadingZeros >= 24;
}

// Reader-facing words for the payload's edge vocabulary. The DATA keeps its
// witness-plane names — flow type `principal` means a FunctionPrincipal row
// proved the from-address can call the target's gated functions; `controller`
// means a control-plane edge (slot value, role grant) the scorer's reach
// closure walks — and those names are shared with the backend and scorer, so
// only the display layer translates. A token outside the map renders
// verbatim: showing the raw witness name beats inventing a friendlier one for
// vocabulary this map has never seen.
const FLOW_TYPE_WORDS = {
  principal: "can call",
  controller: "controls",
  controls: "controls",
  controls_value: "controls value of",
};

const RELATION_WORDS = {
  controller_value: "control slot",
  role_principal: "role holder",
  mapping_member: "mapping member",
  safe_owner: "safe owner",
};

export function flowTypeWord(type) {
  return FLOW_TYPE_WORDS[type] || type || "";
}

export function relationWord(relation) {
  return RELATION_WORDS[relation] || relation || "";
}

export function formatUsd(value) {
  if (!value || value < 0.01) return null;
  if (value >= 1e9) return `$${(value / 1e9).toFixed(1)}B`;
  if (value >= 1e6) return `$${(value / 1e6).toFixed(1)}M`;
  if (value >= 1e3) return `$${(value / 1e3).toFixed(1)}K`;
  return `$${value.toFixed(2)}`;
}

export function dedupeShas(list) {
  const fulls = new Map(); // prefix(7) → full sha
  const shorts = new Set();
  for (const raw of list || []) {
    const sha = String(raw || "").trim().toLowerCase();
    if (!/^[0-9a-f]+$/.test(sha)) continue;
    if (sha.length >= 20) fulls.set(sha.slice(0, 7), sha);
    else if (sha.length >= 4) shorts.add(sha);
  }
  const out = [...fulls.values()];
  for (const s of shorts) {
    if (!fulls.has(s.slice(0, 7))) out.push(s);
  }
  return out;
}
