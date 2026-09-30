// Every figure the score page renders, derived from the published document.
// Anything unwitnessed comes back `null` and must render as not-determined,
// never zero or blank.

import { capabilityPhrase } from "../vocab/capabilityPhrase.js";
import { entityKey } from "../surface/entityKey.js";
import {
  countWord,
  pctOf,
  shortAddress,
  splitEntity,
  usdCompact,
} from "./format.js";
import { lambdaOf, protectionDelta, rankedFindings, recoveryFrom, round4 } from "./fold.js";

const ADDRESS_RE = /0x[0-9a-fA-F]{40}/;
const SAFE_RE = /(\d+)\s*\/\s*(\d+)/;
const TIMELOCK_DELAY_RE = /timelock\s+([0-9]+\s*[smhd])/i;


// From the display string, not `principal_unit`: for a Safe that can be any
// member, and naming a signer misattributes the power.
export function controllerAddress(finding) {
  const match = ADDRESS_RE.exec(String(finding?.principal || ""));
  return match ? match[0].toLowerCase() : null;
}

function safeShape(finding) {
  if (finding?.principal_kind !== "safe") return null;
  const match = SAFE_RE.exec(String(finding?.principal || ""));
  if (!match) return null;
  const k = Number(match[1]);
  const n = Number(match[2]);
  if (!n) return null;
  return { k, n };
}

function timelockDelayLabel(finding) {
  const match = TIMELOCK_DELAY_RE.exec(String(finding?.principal || ""));
  return match ? match[1].replace(/\s+/g, "") : null;
}

export function timelockProposer(finding) {
  const principal = String(finding?.principal || "");
  if (/proposer\s+not_determined/i.test(principal)) {
    return { text: "proposer unproven", proven: false };
  }
  const via = /via\s+(\d+\s*\/\s*\d+)/i.exec(principal);
  if (via) return { text: `via Safe ${via[1].replace(/\s+/g, "")}`, proven: true };
  return null;
}

// Merged members' k/n from the overlap table; null when any is unwitnessed (the
// chip then counts members).
function memberShapes(doc, finding, members) {
  const shapes = new Map();
  for (const overlap of doc?.provenance?.safe_keyset_overlaps || []) {
    if (overlap?.a && overlap?.a_k_of_n) shapes.set(overlap.a, overlap.a_k_of_n);
    if (overlap?.b && overlap?.b_k_of_n) shapes.set(overlap.b, overlap.b_k_of_n);
  }
  const out = members.map((member) => shapes.get(entityKey(finding?.chain, member)));
  return out.every(Boolean) ? out : null;
}

// Single-member k/n and timelock delay are parsed from the display string (no
// structured principal_shape yet).
export function principalChip(finding, doc = null) {
  const kind = finding?.principal_kind || "";
  if (kind === "eoa") return { kind, label: "EOA" };
  if (kind === "anyone") return { kind, label: "Anyone" };
  if (kind === "safe") {
    // The display string names one member; building the chip from it would
    // attribute the whole unit to one Safe.
    const members = principalAddresses(finding);
    if (members.length > 1) {
      const shapes = doc ? memberShapes(doc, finding, members) : null;
      return {
        kind,
        label: shapes
          ? `Safes ${shapes.join(" + ")} · shared keys`
          : `${members.length} Safes · shared keys`,
        merged: true,
        // Absent when shapes are unwitnessed.
        ...(shapes ? { members: members.map((address, i) => ({ address, shape: shapes[i] })) } : {}),
      };
    }
    const shape = safeShape(finding);
    return { kind, label: shape ? `Safe ${shape.k}/${shape.n}` : "Safe" };
  }
  if (kind === "timelock") {
    const delay = timelockDelayLabel(finding);
    return { kind, label: delay ? `Timelock ${delay}` : "Timelock" };
  }
  return { kind, label: kind ? kind.toUpperCase() : "Principal" };
}

const KIND_WORD = {
  eoa: "EOA",
  anyone: "anyone-callable",
  safe: "Safe",
  timelock: "Timelock",
};

function kindWord(kind) {
  return KIND_WORD[kind] || String(kind || "").toUpperCase();
}


// From the published field only: the `value_at_stake_is_floor` boolean can't
// tell a floor from a sum of ceilings, so boolean-only documents get no badge.
export const BOUND_DIRECTIONS = ["floor", "ceiling", "not_determined"];

// `determined: false` is a third state and must not render as $0 or empty.
export function valueCell(finding) {
  const band = finding?.value_band;
  if (!band || band === "not_determined") return { determined: false, text: null, direction: null };
  const direction = finding?.value_at_stake_bound_direction;
  return {
    determined: true,
    // The direction is carried as state beside the band, never as a prefix.
    text: String(band).replace(/^[<>]=\s*/, ""),
    direction: BOUND_DIRECTIONS.includes(direction) ? direction : null,
  };
}

// An earned negative: reach was answered, and the answer was nothing.
export function isProvenNoReach(finding) {
  return finding?.value_at_stake_basis === "proven_no_reach";
}


// Label tables, not allow-lists: unregistered tokens fall through to the raw
// token (in `sheetStateLabel`) rather than disappearing.
const SHEET_STATE_LABELS = {
  priced: "priced",
  priced_below_resolution: "below resolution",
  unpriced: "unpriced",
  proven_empty: "proven empty",
  no_rows: "nothing observed",
  airdrop_determined: "unpriced (legacy classification)",
};

const CEILING_REASON_LABELS = {
  admitted: "admitted",
  proven_empty: "proven empty",
  no_rows: "nothing observed",
  below_resolution: "below resolution",
  unpriced: "unpriced",
  asset_list_truncated: "asset list cut off",
  alias_ambiguous: "alias ambiguous",
  airdrop_determined: "unpriced (legacy classification)",
};

function label(table, token) {
  const key = String(token || "");
  if (!key) return null;
  return table[key] || key;
}

export function sheetStateLabel(state) {
  return label(SHEET_STATE_LABELS, state);
}

export function ceilingReasonLabel(reason) {
  return label(CEILING_REASON_LABELS, reason);
}

export function sheetDisposition() {
  return null;
}


function functionsLabel(finding) {
  const example = (finding?.example_functions || [])[0];
  return example ? [example] : [];
}

// An implementation collapses onto its proxy: one deployed thing, one target.
export function buildContractIndex(contracts) {
  const byEntity = new Map();
  const implToProxy = new Map();
  for (const contract of contracts || []) {
    if (!contract?.address) continue;
    const key = entityKey(contract.chain, contract.address);
    byEntity.set(key, contract);
    if (contract.implementation) {
      implToProxy.set(entityKey(contract.chain, contract.implementation), key);
    }
    for (const secondary of contract.secondary_implementations || []) {
      const address = typeof secondary === "string" ? secondary : secondary?.address;
      if (address) implToProxy.set(entityKey(contract.chain, address), key);
    }
  }
  return { byEntity, implToProxy };
}

function contractName(contract) {
  return contract?.name || contract?.contract_name || null;
}

export function resolveTargets(entities, index) {
  const out = [];
  const seen = new Set();
  for (const entity of entities || []) {
    const canonical = index?.implToProxy?.get(entity) || entity;
    if (seen.has(canonical)) continue;
    seen.add(canonical);
    const contract = index?.byEntity?.get(entity) || index?.byEntity?.get(canonical);
    // The canonical entity, so the button goes where its label says.
    const { chain, address } = splitEntity(canonical);
    out.push({
      entity,
      canonical,
      chain,
      address,
      short: shortAddress(address),
      name: contractName(contract),
    });
  }
  return out;
}

// Unwitnessed reach renders in the not-determined style with no arrow.
export function undeterminedTargets(finding, index) {
  return resolveTargets(
    [...new Set((finding?.undetermined_instances || []).map((i) => i?.entity).filter(Boolean))],
    index,
  );
}


// The published net wins over the re-fold. Present-but-non-numeric
// is unwitnessed, not zero.
function publishedNet(finding, refolded) {
  const published = finding?.net_points_lambda;
  if (published === undefined) return refolded;
  return typeof published === "number" && Number.isFinite(published) ? published : null;
}

export function deductionRows(doc, index) {
  const findings = doc?.findings || [];
  const ranked = rankedFindings(findings);
  const maxRaw = ranked.reduce((max, r) => (r.raw === null ? max : Math.max(max, r.raw)), 0);
  // Withheld documents drop net_points_lambda; its absence is the signal.
  const hasNet = findings.some((f) => f?.net_points_lambda !== undefined);
  return ranked.map((entry) => {
    const finding = findings[entry.index];
    // Hosts are where the functions live; reach is what they endanger through
    // the graph. A host also in reach shows once, as a host.
    const hosts = resolveTargets(finding?.host_entities, index);
    const hostKeys = new Set(hosts.map((h) => h.canonical));
    const reachWitnessed = (finding?.reach_entities || []).length > 0;
    const proven = resolveTargets(finding?.reach_entities, index).filter((t) => !hostKeys.has(t.canonical));
    const net = hasNet ? publishedNet(finding, entry.net) : null;
    return {
      index: entry.index,
      rank: entry.rank,
      finding,
      raw: entry.raw,
      net,
      chip: principalChip(finding, doc),
      capability: finding?.capability || "",
      controller: controllerAddress(finding),
      // The display string names only one member; showing the row under it
      // alone attributes the others' gates to it.
      controllers: principalAddresses(finding),
      functions: functionsLabel(finding),
      exampleFunction: (finding?.example_functions || [])[0] || null,
      value: valueCell(finding),
      // Published even when the value is not determined: those are exactly the
      // rows where omission would read as "nothing here".
      sheetDisposition: sheetDisposition(finding),
      provenNoReach: isProvenNoReach(finding),
      trackPct: maxRaw && entry.raw !== null ? (entry.raw / maxRaw) * 100 : 0,
      fillPct: maxRaw && net !== null ? (net / maxRaw) * 100 : 0,
      reachWitnessed,
      hosts,
      targets: reachWitnessed
        ? proven
        : undeterminedTargets(finding, index).filter((t) => !hostKeys.has(t.canonical)),
      undeterminedCount: (finding?.undetermined_instances || []).length,
    };
  });
}


// Consecutive rows sharing (principal_kind, capability) are one hole. A group
// with an unpublished net has no sum.
export function groupRows(rows) {
  const groups = [];
  for (const row of rows) {
    const kind = row.finding?.principal_kind || "";
    const last = groups[groups.length - 1];
    if (last && last.kind === kind && last.capability === row.capability) {
      last.rows.push(row);
      last.sum = last.sum === null || row.net === null ? null : last.sum + row.net;
      continue;
    }
    groups.push({ kind, capability: row.capability, rows: [row], sum: row.net ?? null });
  }
  return groups.map((g) => ({ ...g, sum: g.sum === null ? null : round4(g.sum) }));
}

const CALLOUT_MIN_POINTS = 5;

function namedGroups(groups) {
  const named = [];
  for (const group of groups) {
    if (!(group.sum >= CALLOUT_MIN_POINTS)) break;
    named.push(group);
  }
  return named;
}

// Groups are named while each carries ≥5 points; the rest collapse into "N
// others". Measured off λ, so no λ means no callouts.
export function calloutsFor(rows, lambda) {
  if (typeof lambda !== "number" || !Number.isFinite(lambda)) return [];
  const groups = groupRows(rows);
  const named = namedGroups(groups);
  const callouts = [];
  let cursor = lambda;
  let namedRows = 0;
  for (const group of named) {
    const start = cursor;
    cursor += group.sum;
    namedRows += group.rows.length;
    callouts.push({
      id: `g${group.rows[0].index}`,
      sum: group.sum,
      centerPct: (start + cursor) / 2,
      text: `${countWord(group.rows.length)} ${kindWord(group.kind)} ${capabilityPhrase(group.capability, group.rows.length)}`,
    });
  }
  const restRows = rows.length - namedRows;
  const restSum = Math.round((100 - cursor) * 1e4) / 1e4;
  if (restRows > 0 && restSum > 0) {
    callouts.push({
      id: "rest",
      sum: restSum,
      centerPct: (cursor + 100) / 2,
      text: `${restRows} other${restRows === 1 ? "" : "s"}`,
    });
  }
  return callouts;
}


const LEDGER_TAIL_FLOOR = 0.4;

export function ledgerSegments(rows, lambda) {
  const kept = typeof lambda === "number" ? lambda : 0;
  // Partition, not filter+slice: a non-monotone net sequence must not land a
  // row in both.
  const head = [];
  const tail = [];
  for (const r of rows) ((r.net || 0) >= LEDGER_TAIL_FLOOR ? head : tail).push(r);
  const tailSum = Math.round(tail.reduce((sum, r) => sum + (r.net || 0), 0) * 1e4) / 1e4;
  const segments = head.map((row) => ({
    id: `f${row.index}`,
    kind: "deduction",
    basis: row.net,
    title: `${row.chip.label} · ${row.capability} · −${(row.net || 0).toFixed(2)}`,
  }));
  if (tail.length && tailSum > 0) {
    segments.push({
      id: "tail",
      kind: "deduction",
      basis: tailSum,
      title: `${tail.length} more finding${tail.length === 1 ? "" : "s"} · −${tailSum.toFixed(2)}`,
    });
  }
  return { kept, segments };
}


// Recovery comes from re-folding the survivors, never summing nets: rank decay
// promotes everything below. Hence the max modeled recovery, not the first
// group.
export function fixFirst(doc, rows) {
  const groups = groupRows(rows);
  const named = namedGroups(groups);
  const candidates = (named.length ? named : groups).filter((g) => g.rows.length);
  const findings = doc?.findings || [];
  let best = null;
  for (const candidate of candidates) {
    const modeled = recoveryFrom(
      findings,
      candidate.rows.map((r) => r.index),
    );
    if (modeled.recovery === null || !(modeled.recovery > 0)) continue;
    if (!best || modeled.recovery > best.recovery) best = { group: candidate, ...modeled };
  }
  if (!best) return null;
  const { group, before, after, recovery } = best;
  const subsumed = [];
  for (const row of group.rows) {
    for (const entry of row.finding?.subsumed_capabilities || []) {
      if (entry?.capability && !subsumed.includes(entry.capability)) subsumed.push(entry.capability);
    }
  }
  const count = group.rows.length;
  const open = group.kind === "eoa" || group.kind === "anyone";
  return {
    count,
    subject: `the ${countWord(count)} ${kindWord(group.kind)} ${capabilityPhrase(group.capability, count)}`,
    verb: open ? "Move" : "Harden",
    remedy: open ? " behind a strong multisig or timelock" : "",
    recovery,
    lambdaBefore: before,
    lambdaAfter: after,
    subsumed,
    exampleFunction: (group.rows[0].finding?.example_functions || [])[0] || null,
    chain: group.rows[0].finding?.chain || null,
    // Only when every instance is on one contract.
    host: group.rows[0].hosts?.length === 1 ? group.rows[0].hosts[0] : null,
    controller: group.rows[0].controller || null,
    controllers: group.rows[0].controllers || [],
  };
}


// The display string carries one member; matching on it alone drops overlaps
// naming the others.
function principalAddresses(finding) {
  const listed = (finding?.principal_addresses || [])
    .map((address) => String(address || "").toLowerCase())
    .filter((address) => ADDRESS_RE.test(address));
  if (listed.length) return [...new Set(listed)];
  const single = controllerAddress(finding);
  return single ? [single] : [];
}

const PROTECTION_WEAKNESS_CEILING = 0.9;
// Rows before the tail toggle, not a cap on the derivation.
export const PROTECTION_ROWS = 4;

// Ranked by λ-delta (what the grade loses if the principal were unconditional),
// not by the finding's own net.
export function protectionRows(doc, limit = Infinity, rowsByIndex = null) {
  const findings = doc?.findings || [];
  const ranked = rankedFindings(findings);
  const netByIndex = new Map(ranked.map((r) => [r.index, r.net]));
  const rows = [];
  findings.forEach((finding, index) => {
    if (!["safe", "timelock"].includes(finding?.principal_kind)) return;
    if (!(Number(finding?.weakness) < PROTECTION_WEAKNESS_CEILING)) return;
    const delta = protectionDelta(findings, index);
    if (delta === null || !(delta > 0)) return;
    const value = valueCell(finding);
    rows.push({
      index,
      finding,
      delta,
      // The same finding's deduction row, rendered through the same components.
      // null without the map.
      anatomy: rowsByIndex?.get(index) || null,
      net: netByIndex.get(index) ?? 0,
      chip: principalChip(finding, doc),
      // So the kind chip selects the Safe/timelock it names.
      chain: finding.chain || null,
      address: controllerAddress(finding),
      what: value.determined ? `${finding.capability} on ${value.text}` : finding.capability,
      capability: finding.capability,
      // The whole cell: flattening it loses `direction` and the never-measured
      // state.
      value,
      valueText: value.determined ? value.text : null,
      // The deduction row distinguishes these; the protection row must too.
      provenNoReach: isProvenNoReach(finding),
    });
  });
  rows.sort((a, b) => b.delta - a.delta || a.index - b.index);
  const top = rows.slice(0, limit);
  const scale = top.reduce((max, r) => Math.max(max, r.delta + r.net), 0);
  return top.map((row) => ({
    ...row,
    widthPct: scale ? ((row.delta + row.net) / scale) * 100 : 0,
    avoidedPct: row.delta + row.net ? (row.delta / (row.delta + row.net)) * 100 : 100,
    chargedPct: row.delta + row.net ? (row.net / (row.delta + row.net)) * 100 : 0,
  }));
}


// Never re-derived from /api/company: the naive join double-counts.
export function auditPosture(doc) {
  const posture = doc?.provenance?.audit_posture;
  if (!posture) return null;
  const tracked = doc?.provenance?.value?.tracked_total_usd;
  const num = (v) => (typeof v === "number" && Number.isFinite(v) ? v : null);
  const covered = num(posture.value_covered_usd);
  const provenValue = num(posture.value_proven_usd);
  const total = num(tracked);
  const contractsTotal = num(posture.contracts_total);
  const contractsCovered = num(posture.contracts_covered);
  const contractsProven = num(posture.contracts_proven);
  return {
    reportsOnFile: num(posture.reports_on_file),
    contractsTotal,
    contractsCovered,
    contractsProven,
    coveredUsd: covered,
    provenUsd: provenValue,
    trackedTotalUsd: total,
    valueProvenPct: pctOf(provenValue, total),
    valueCoveredOnlyPct:
      covered !== null && provenValue !== null ? pctOf(covered - provenValue, total) : null,
    contractProvenPct: pctOf(contractsProven, contractsTotal),
    contractCoveredOnlyPct:
      contractsCovered !== null && contractsProven !== null
        ? pctOf(contractsCovered - contractsProven, contractsTotal)
        : null,
    provablyDiffers: num(posture.non_coverage_classified?.deployed_source_provably_differs),
  };
}


const CONFIDENCE_CHANNELS = [
  {
    id: "capability_scored_pct",
    name: "Capability scored",
    desc: "How much of the protocol's value had its privileged functions graded.",
  },
  {
    id: "reachability_answered_pct",
    name: "Reachability",
    desc: "How much of that surface has a proven answer to who can call it.",
  },
  {
    id: "value_priced_pct",
    name: "Value priced",
    desc: "How much of the protocol's value we could price.",
  },
  {
    id: "reach_magnitude_witnessed_pct",
    name: "Reach magnitude witnessed",
    desc: "How much of the protocol's value has a measured limit on what a permission can move.",
  },
];

// The MIN tag follows whichever channel is actually lowest. Must list every
// term the producer minimises over, or the tag and confidence_pct can disagree.
export function confidenceChannels(doc) {
  const detail = doc?.model_parameters?.confidence_detail || {};
  const channels = CONFIDENCE_CHANNELS.map((channel) => {
    const value = detail[channel.id];
    return { ...channel, pct: typeof value === "number" && Number.isFinite(value) ? value : null };
  });
  const measured = channels.filter((c) => c.pct !== null);
  const min = measured.length ? Math.min(...measured.map((c) => c.pct)) : null;
  let tagged = false;
  return channels.map((channel) => {
    const isMin = !tagged && min !== null && channel.pct === min;
    if (isMin) tagged = true;
    return { ...channel, isMin };
  });
}


export function projectScore(doc, contracts) {
  const index = buildContractIndex(contracts);
  const rows = deductionRows(doc, index);
  // Reconstructing λ from raw points would republish exactly what was withheld,
  // so nothing derived from λ is shown.
  const withheld = doc?.grade_state === "not_determined";
  const lambda = withheld
    ? null
    : typeof doc?.grade_lambda === "number"
      ? doc.grade_lambda
      : lambdaOf(doc?.findings);
  return {
    rows,
    lambda,
    withheld,
    ledger: ledgerSegments(rows, lambda),
    callouts: calloutsFor(rows, lambda),
    fix: withheld ? null : fixFirst(doc, rows),
    protections: protectionRows(doc, Infinity, new Map(rows.map((r) => [r.index, r]))),
    posture: auditPosture(doc),
    confidence: confidenceChannels(doc),
  };
}
