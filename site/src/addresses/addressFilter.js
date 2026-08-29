// Membership-state helpers for the AddressesModal (DISCOVERY_MEMBERSHIP_GATE
// spec §5.3). The addresses payload carries `membership_state` derived by the
// backend gate helper plus witness/probe reason fields; nothing here computes
// a state of its own — display logic only reads those fields.
//
// Sections:
//   - members: proven-present rows (the main table). A member whose only
//     admitting witness is a `historical_implementation` structural edge and
//     which is not currently behind any proxy in the payload is a stale past
//     impl — kept for audit-coverage matching, collapsed behind a toggle.
//   - candidates: not-determined rows, each with a token-templated reason
//     built ONLY from the payload's persisted probe fields.
//   - pruned: proven-absent rows (no code at the probed block), collapsed
//     behind a count.

import { shortenAddress } from "../shared/format.js";

export function membershipState(row) {
  // Rows without the field (compare-mode synthesized rows, legacy fixtures)
  // render in the main table rather than vanishing.
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

// A member is "pure historical" iff every admitting witness is a
// historical_implementation structural edge AND it is not the live impl of a
// proxy in the same payload. Witness-field-driven: a member with no recorded
// witnesses (or any other admitting edge) stays visible.
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

// Token-templated candidate reason — assembled from the payload's persisted
// probe fields only.
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
  // An unknown kind surfaces its token verbatim — never a vague default
  // (invariant 5: the missing piece is always named).
  return typeof kind === "string" && kind ? kind : "";
}

export function prunedReasonText(row) {
  const reason = row?.membership_reason;
  if (reason?.kind === "code_absent" && reason.code_probe_block != null) {
    return `no code at block ${reason.code_probe_block}`;
  }
  return "no code at probed block";
}

// Rows eligible for the bulk "Analyze pending" action: discovered-but-not-
// analyzed rows that are worth analyzing. Pruned rows (proven no code) and
// pure-historical impls are skipped even when the user has them visible.
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
