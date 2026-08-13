// Every figure the score page renders, derived from the published document.
// Pure functions, no React — the page is a projection of these and nothing
// here invents a fact the document did not witness. Anything the document
// leaves unwitnessed comes back as `null` and must render as not-determined,
// never as zero and never as blank.

import { capabilityPhrase } from "../claimsVocab.js";
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

// ── principals ──────────────────────────────────────────────────────────────

// The controlling address is the one embedded in the principal DISPLAY string.
// `principal_unit` is deliberately not used: for a Safe it can be an arbitrary
// member of the unit, and naming a signer as the controller misattributes the
// power to a person who only holds one key of k.
export function controllerAddress(finding) {
  const match = ADDRESS_RE.exec(String(finding?.principal || ""));
  return match ? match[0].toLowerCase() : null;
}

export function safeShape(finding) {
  if (finding?.principal_kind !== "safe") return null;
  const match = SAFE_RE.exec(String(finding?.principal || ""));
  if (!match) return null;
  const k = Number(match[1]);
  const n = Number(match[2]);
  if (!n) return null;
  return { k, n };
}

export function timelockDelayLabel(finding) {
  const match = TIMELOCK_DELAY_RE.exec(String(finding?.principal || ""));
  return match ? match[1].replace(/\s+/g, "") : null;
}

// The routing clause of a timelock principal: who can propose through it.
export function timelockProposer(finding) {
  const principal = String(finding?.principal || "");
  if (/proposer\s+not_determined/i.test(principal)) {
    return { text: "proposer unproven", proven: false };
  }
  const via = /via\s+(\d+\s*\/\s*\d+)/i.exec(principal);
  if (via) return { text: `via Safe ${via[1].replace(/\s+/g, "")}`, proven: true };
  return null;
}

// Each merged member's own k/n, read off the overlap table — the display
// string carries only one member's shape. null when any member's shape is not
// witnessed there; the chip then counts members instead of guessing one.
function memberShapes(doc, finding, members) {
  const shapes = new Map();
  for (const overlap of doc?.provenance?.safe_keyset_overlaps || []) {
    if (overlap?.a && overlap?.a_k_of_n) shapes.set(overlap.a, overlap.a_k_of_n);
    if (overlap?.b && overlap?.b_k_of_n) shapes.set(overlap.b, overlap.b_k_of_n);
  }
  const out = members.map((member) => shapes.get(entityKey(finding?.chain, member)));
  return out.every(Boolean) ? out : null;
}

// Short chip: the shape of the principal. A single member's k/n and a
// timelock's delay are parsed from the display string (a structured
// principal_shape on the document would remove the regex; it does not exist
// yet); a merged unit's member shapes come from the overlap table instead.
export function principalChip(finding, doc = null) {
  const kind = finding?.principal_kind || "";
  if (kind === "eoa") return { kind, label: "EOA" };
  if (kind === "anyone") return { kind, label: "Anyone" };
  if (kind === "safe") {
    // A merged unit's display string names one member and that member's k/n —
    // a chip built from it would attribute the whole unit's power to one Safe.
    // Every member keeps its signer shape, in principal_addresses order.
    const members = principalAddresses(finding);
    if (members.length > 1) {
      const shapes = doc ? memberShapes(doc, finding, members) : null;
      return {
        kind,
        label: shapes
          ? `Safes ${shapes.join(" + ")} · shared keys`
          : `${members.length} Safes · shared keys`,
        merged: true,
        // Each member beside its own shape, so a consumer can hand every Safe
        // its own click target. Absent when the shapes are unwitnessed — a
        // handle labelled with a guessed shape would be worse than none.
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

export function kindWord(kind) {
  return KIND_WORD[kind] || String(kind || "").toUpperCase();
}

// ── value ───────────────────────────────────────────────────────────────────

// Which direction the producer proved the total bounds the principal in. Read
// from the published field only: `value_at_stake_is_floor` is a boolean over a
// three-sided question and cannot tell a floor from a sum of extraction
// ceilings, so a document that carries only the boolean gets `null` — no badge
// — rather than the floor its own flag would claim. `not_determined` is the
// producer's fall-through and is itself no claim about the figure.
export const BOUND_DIRECTIONS = ["floor", "ceiling", "not_determined"];

// The value cell. `determined: false` is a third state — the band was never
// measured — and must not render as $0 or as an empty cell.
export function valueCell(finding) {
  const band = finding?.value_band;
  if (!band || band === "not_determined") return { determined: false, text: null, direction: null };
  const direction = finding?.value_at_stake_bound_direction;
  return {
    determined: true,
    // Both qualifiers are stripped: the direction is carried as a state beside
    // the band, never as a prefix a reader has to parse.
    text: String(band).replace(/^[<>]=\s*/, ""),
    direction: BOUND_DIRECTIONS.includes(direction) ? direction : null,
  };
}

// An earned negative, not an unknown: the reach question was answered, and the
// answer was "nothing". Branching on value_state alone reads it as unmeasured.
export function isProvenNoReach(finding) {
  return finding?.value_at_stake_basis === "proven_no_reach";
}

// ── sheet state / ceiling reason ────────────────────────────────────────────

// The producer's sheet-state and ceiling-reason vocabularies, in the words the
// page shows. These are LABEL tables and NOT allow-lists: an unregistered token
// falls through to the raw token rather than to a blank, because a state the
// page cannot name is still a state the document published, and rendering it as
// nothing would silently withdraw it. `sheetStateLabel` is where that
// fall-through lives; every consumer goes through it.
export const SHEET_STATE_LABELS = {
  priced: "priced",
  priced_below_resolution: "below resolution",
  unpriced: "unpriced",
  proven_empty: "proven empty",
  no_rows: "nothing observed",
  // 1.4.0. Every recorded delivery of this sheet's remaining holdings was a
  // mass distribution. A DELIVERY shape, never a worth claim — real tokens are
  // airdropped too — so the word is "airdrop-delivered" and never "spam".
  airdrop_determined: "airdrop-delivered",
};

export const CEILING_REASON_LABELS = {
  admitted: "admitted",
  proven_empty: "proven empty",
  no_rows: "nothing observed",
  below_resolution: "below resolution",
  unpriced: "unpriced",
  asset_list_truncated: "asset list cut off",
  alias_ambiguous: "alias ambiguous",
  airdrop_determined: "airdrop-delivered",
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

export const AIRDROP_DETERMINED = "airdrop_determined";

// The backend's own claim, not a weaker paraphrase of it. The superseded
// sentence said the holdings "are not presented as positions this protocol
// holds", which describes what the PAGE does and leaves a reader to infer the
// figure covers them. It does not: the assets are still held, and this document
// values none of them.
const AIRDROP_NOTE =
  "the figure totals what this document PRICES at these nodes; the holdings behind it are STILL HELD and their " +
  "worth is not_determined here — every delivery of them on record was a mass distribution, which is a claim " +
  "about how they arrived and never about what they are worth";

// The disposed part of a row's sheet ceilings, or `null` where there is none.
//
// `usd` is the sum of what the disposed entries PUBLISHED, and it is a real
// measured figure — normally 0, because a sheet whose remaining holdings are all
// airdrop-delivered has nothing left to price. It is carried so the page can
// render "$0 · airdrop-delivered" rather than a bare zero: a zero with no reason
// beside it reads as "this reaches nothing", which is a different claim and one
// nobody proved. A published entry with no number gets `usd: null`, which the
// cell renders as not-determined rather than as another zero.
export function sheetDisposition(finding) {
  const records = (finding?.reach_sheet_ceiling_magnitudes || []).filter(
    (r) => r?.sheet_state === AIRDROP_DETERMINED || r?.ceiling_reason === AIRDROP_DETERMINED,
  );
  if (!records.length) return null;
  const numbers = records.map((r) => r?.published_usd).filter((v) => typeof v === "number" && Number.isFinite(v));
  const usd = numbers.length === records.length ? numbers.reduce((sum, v) => sum + v, 0) : null;
  return {
    count: records.length,
    entities: records.map((r) => r?.entity).filter(Boolean),
    usd,
    // `$0` is printed exactly, not routed through the compact formatter: a
    // disposed sheet's figure is small on purpose and rounding it away would
    // hide the one number the label is attached to.
    usdText: usd === null ? null : usd === 0 ? "$0" : usdCompact(usd),
    label: sheetStateLabel(AIRDROP_DETERMINED),
    reason: AIRDROP_NOTE,
  };
}

// ── functions / targets ─────────────────────────────────────────────────────

// The example function alone. The row's n_functions count used to render
// beside it ("upgradeToAndCall · 3 functions") and was cut for space — the
// count survives on the finding for any consumer that needs it.
export function functionsLabel(finding) {
  const example = (finding?.example_functions || [])[0];
  return example ? [example] : [];
}

// entity → contract, plus the implementation→proxy alias. A finding can reach a
// proxy and its implementation; they are one deployed thing, so they collapse
// to one target rather than reading as two contracts at risk.
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

export function contractName(contract) {
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
    // The CANONICAL entity, not the raw one: the label already names the
    // canonical contract (an implementation resolves to its proxy's name), and
    // a button that navigates to the raw address would send the user somewhere
    // other than the thing it is labelled with.
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

// Where reach was never witnessed the instance list is all there is. It is
// rendered in the not-determined style with no arrow, because "this is what it
// reaches" and "this is where we could not tell" must not look alike.
export function undeterminedTargets(finding, index) {
  return resolveTargets(
    [...new Set((finding?.undetermined_instances || []).map((i) => i?.entity).filter(Boolean))],
    index,
  );
}

// ── deduction rows ──────────────────────────────────────────────────────────

// spec §3.2 pins the row's points to −net_points_lambda. The re-fold reproduces
// that field exactly today, but the published number is the witness and the
// reconstruction is only a model of it: where the producer published one, it
// wins. A field that is present but not a number is unwitnessed, not zero.
function publishedNet(finding, refolded) {
  const published = finding?.net_points_lambda;
  if (published === undefined) return refolded;
  return typeof published === "number" && Number.isFinite(published) ? published : null;
}

export function deductionRows(doc, index) {
  const findings = doc?.findings || [];
  const ranked = rankedFindings(findings);
  const maxRaw = ranked.reduce((max, r) => (r.raw === null ? max : Math.max(max, r.raw)), 0);
  // In the withheld state the producer pops net_points_lambda off the rows;
  // absence of the field is the signal, so the row shows raw points only.
  const hasNet = findings.some((f) => f?.net_points_lambda !== undefined);
  return ranked.map((entry) => {
    const finding = findings[entry.index];
    // The hosts are the contracts the row's functions actually live on — the
    // direct targets. Reach is the closure those functions endanger THROUGH
    // the control graph, so a host also present in reach is shown once, as a
    // host: the two lists answer different questions and must not blur.
    const hosts = resolveTargets(finding?.host_entities, index);
    const hostKeys = new Set(hosts.map((h) => h.canonical));
    const reachWitnessed = (finding?.reach_entities || []).length > 0;
    const proven = resolveTargets(finding?.reach_entities, index).filter((t) => !hostKeys.has(t.canonical));
    // The published net is the charge the grade was actually built from; the
    // re-fold only stands in where the producer published no net for this row.
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
      // Every member of the (possibly merged) unit — principal_addresses[] is
      // the witnessed list; the display string carries only one of them, and a
      // row shown under that one address alone attributes the other members'
      // gates to it.
      controllers: principalAddresses(finding),
      functions: functionsLabel(finding),
      exampleFunction: (finding?.example_functions || [])[0] || null,
      value: valueCell(finding),
      // Published beside the value on every row that has one, including the rows
      // whose value cell is not determined: the disposition is a fact about the
      // sheet the figure would have come from, and it is exactly on the rows
      // with no figure that a silent omission would read as "nothing here".
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

// ── grouping / callouts ─────────────────────────────────────────────────────

// Greedy run-length grouping over the ranked rows: consecutive rows sharing a
// (principal_kind, capability) are one story about one hole. A group whose
// members include an unpublished net has NO sum — a total that skipped the
// absent terms would read as a measured one.
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

export const CALLOUT_MIN_POINTS = 5;

// The leading run of groups each carrying at least 5 points. The first group
// that does not — including one whose sum was never published — ends the run.
export function namedGroups(groups) {
  const named = [];
  for (const group of groups) {
    if (!(group.sum >= CALLOUT_MIN_POINTS)) break;
    named.push(group);
  }
  return named;
}

// Callouts sit under the ledger bar. The leading groups are named while they
// each carry at least 5 points; the first group that does not ends the naming,
// and everything from there collapses into one "N others". Every position and
// the trailing sum are measured off λ, so with no λ there are no callouts.
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

// ── ledger ──────────────────────────────────────────────────────────────────

export const LEDGER_TAIL_FLOOR = 0.4;

export function ledgerSegments(rows, lambda) {
  const kept = typeof lambda === "number" ? lambda : 0;
  // Partition, not filter+slice: the producer publishes rank-ordered rows so
  // the floor selects a prefix today, but a non-monotone net sequence must
  // not double-count a row into both head and tail.
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

// ── fix first ───────────────────────────────────────────────────────────────

// The group worth fixing first, and what removing it is modeled to recover.
// Recovery comes from a re-fold over the survivors, never from summing the
// group's nets: rank decay promotes everything below, so the sum understates
// the recovery — and by different amounts per group. That is exactly why the
// pick is the MAXIMUM modeled recovery over the called-out groups rather than
// the first of them: five cheap rows can be worth more than one expensive one.
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
    // The host is published only when the row's instances live on exactly one
    // contract — the displayed example function is then unambiguously on it.
    host: group.rows[0].hosts?.length === 1 ? group.rows[0].hosts[0] : null,
    controller: group.rows[0].controller || null,
    controllers: group.rows[0].controllers || [],
  };
}

// ── protections ─────────────────────────────────────────────────────────────

// Every address this principal acts through. `principal_addresses[]` is the
// witnessed list; the display string carries only one of them, so matching on
// the string alone silently drops any overlap that names one of the others.
export function principalAddresses(finding) {
  const listed = (finding?.principal_addresses || [])
    .map((address) => String(address || "").toLowerCase())
    .filter((address) => ADDRESS_RE.test(address));
  if (listed.length) return [...new Set(listed)];
  const single = controllerAddress(finding);
  return single ? [single] : [];
}

export const PROTECTION_WEAKNESS_CEILING = 0.9;
// How many rows the panel shows before the tail toggle, not a cap on the
// derivation: every qualifying row is returned, ranked by λ-delta.
export const PROTECTION_ROWS = 4;

// Coordination that is modeled to be holding points on. Ranked by λ-delta —
// what the grade would lose if the principal were unconditional — not by the
// finding's own net, which measures the opposite thing.
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
      // The same finding's deduction row, so the panel renders the function
      // and target anatomy through the SAME components — one derivation, like
      // the possible-deductions table's join. null without the map.
      anatomy: rowsByIndex?.get(index) || null,
      net: netByIndex.get(index) ?? 0,
      chip: principalChip(finding, doc),
      // The principal's own address, so the row's kind chip selects the Safe or
      // timelock it names on the surface — the same pathway the deduction rows'
      // controller chips use.
      chain: finding.chain || null,
      address: controllerAddress(finding),
      what: value.determined ? `${finding.capability} on ${value.text}` : finding.capability,
      // The same reading split apart, for consumers that wrap the capability
      // in its own control (the glossary tag) — one derivation, two shapes.
      capability: finding.capability,
      // The whole cell, not its text: flattening it drops `direction` and
      // collapses "the band was never measured" into the same null a row with
      // no value carries. `valueText` stays for consumers that only print.
      value,
      valueText: value.determined ? value.text : null,
      // An unmeasured band and an answered-nothing band are different states,
      // and the deduction row already tells them apart — a protection row that
      // could not would contradict the same finding one column over.
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

// ── audit posture ───────────────────────────────────────────────────────────

// Straight off provenance.audit_posture. Never re-derived from /api/company:
// the naive join double-counts, and a page that recomputes a witnessed number
// publishes a different one under the same name.
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

// ── confidence ──────────────────────────────────────────────────────────────

// Every channel is value-weighted, so the copy says "of the protocol's value"
// rather than repeating the weighting mechanics on each line.
export const CONFIDENCE_CHANNELS = [
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

// The headline is the MINIMUM of the channels; the MIN tag goes on whichever
// channel actually is the minimum, so a re-ordering of the channels or a shift
// in the data can never leave the tag pointing at the wrong one. This list must
// carry EVERY term the producer minimises over, or the tagged minimum and the
// published confidence_pct can disagree.
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

// ── the whole projection ────────────────────────────────────────────────────

export function projectScore(doc, contracts) {
  const index = buildContractIndex(contracts);
  const rows = deductionRows(doc, index);
  // A withheld grade is the producer refusing to publish λ. Reconstructing it
  // from the raw points would republish the exact quantity that was withheld,
  // so in that state the page holds no λ and nothing derived from one — no
  // ledger position, no callout, no modeled fix-first recovery.
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
