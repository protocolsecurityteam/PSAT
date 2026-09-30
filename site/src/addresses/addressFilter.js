// Membership display for AddressesModal (DISCOVERY_MEMBERSHIP_GATE spec §5.3);
// states come from the payload, never computed here.
//
// - members: proven present. A member admitted only as a historical
//     implementation and not behind a live proxy is collapsed behind a toggle.
// - candidates: not determined, with a reason built only from persisted probe
//     fields.
// - pruned: proven absent (no code at the probed block).

import { shortenAddress } from "../shared/format.js";

export function membershipState(row) {
  // Rows without the field render as members rather than vanishing.
  return row?.membership_state || "member";
}

export function computeCurrentImplAddrs(rows) {
  const set = new Set();
  for (const r of rows || []) {
    if (r?.is_proxy && r?.implementation_address) {
      set.add(String(r.implementation_address).toLowerCase());
    }
  }
  return set;
}

// Every admitting witness is a historical_implementation edge and it isn't a
// live impl here. Members with no recorded witnesses stay visible.
export function isPureHistorical(row, currentImplAddrs) {
  if (membershipState(row) !== "member") return false;
  const witnesses = row?.membership_witnesses || [];
  if (witnesses.length === 0) return false;
  const allHistorical = witnesses.every(
    (w) => w?.rule === "w2_structural" && w?.edge_kind === "historical_implementation",
  );
  if (!allHistorical) return false;
  const addr = String(row?.address || "").toLowerCase();
  if (currentImplAddrs.has(addr)) return false;
  return true;
}

export function splitMembership(rows) {
  const members = [];
  const candidates = [];
  const pruned = [];
  for (const r of rows || []) {
    const state = membershipState(r);
    if (state === "candidate") candidates.push(r);
    else if (state === "pruned") pruned.push(r);
    else members.push(r);
  }
  return { members, candidates, pruned };
}

export function candidateReasonText(row) {
  const reason = row?.membership_reason;
  const kind = reason?.kind;
  if (kind === "probe_unresolved") {
    const parts = [];
    const resolved = reason.resolved_reads || {};
    for (const name of Object.keys(resolved)) {
      parts.push(`${name} ${shortenAddress(resolved[name])} not in perimeter`);
    }
    const unresolved = reason.unresolved_reads || [];
    if (unresolved.length > 0) {
      parts.push(`${unresolved.join(", ")} resolved nowhere`);
    }
    const at = reason.probe_block != null ? `probed at block ${reason.probe_block}` : "probed";
    return parts.length > 0 ? `${at} — ${parts.join("; ")}` : at;
  }
  if (kind === "chain_not_routable") {
    return reason.chain ? `probe pending — chain ${reason.chain} not routable` : "probe pending — chain not routable";
  }
  if (kind === "probe_error") return "probe attempt failed";
  if (kind === "no_probe_attempt") return "no probe attempt yet";
  // Unknown kinds surface verbatim (invariant 5).
  return typeof kind === "string" && kind ? kind : "";
}

export function prunedReasonText(row) {
  const reason = row?.membership_reason;
  if (reason?.kind === "code_absent" && reason.code_probe_block != null) {
    return `no code at block ${reason.code_probe_block}`;
  }
  return "no code at probed block";
}

// Skips pruned rows and pure-historical impls even when visible.
export function bulkAnalyzeCandidates(rows, currentImplAddrs) {
  const out = [];
  for (const r of rows || []) {
    if (!r || !r.address) continue;
    if (r.analyzed) continue;
    if (r._compareStatus) continue; // compare-mode synthesized rows
    if (membershipState(r) === "pruned") continue;
    if (isPureHistorical(r, currentImplAddrs)) continue;
    out.push(r);
  }
  return out;
}
