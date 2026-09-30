// The "possible deductions" projection: unresolved_levers as questions, never
// charges. Nothing here enters λ, the letter or exposure; every figure is an
// at-most, and an unanswered question never collapses into zero or a charge.

import { controllerAddress, principalChip, timelockProposer } from "./derive.js";

// A fixed 1:1 table, not an allow-list: an unclaimed token renders
// not-determined with the raw token beside it.
export const MISSING_WITNESS_CATEGORIES = [
  {
    id: "reachability",
    label: "Reachability",
    tokens: [
      "gate_does_not_confer_this_scope",
      "caller_condition_not_satisfiable",
      "reach_not_witnessed",
    ],
    description:
      "The permission is proven at its host contract. Whether it extends through each control link to further contracts has not been established. A link can resolve as access or as no access.",
  },
  {
    id: "magnitude",
    label: "Reach magnitude",
    tokens: ["reach_magnitude_not_witnessed", "code_control_sheet_ceiling_refused"],
    description:
      "The permission provably reaches these contracts. The amount it can move at them has not been measured. The dollar figure is the sum of what they hold, an upper bound only.",
  },
  {
    id: "value",
    label: "Value",
    tokens: ["closure_entity_value_not_determined"],
    description:
      "Reach is established. The reached contracts’ balances have not been read, so no dollar bound exists for this question.",
  },
  {
    id: "effect",
    label: "Effect",
    tokens: ["pause_effective_not_witnessed"],
    description:
      "The capability and its holder are proven. What invoking it actually does has not been verified.",
  },
];

const CATEGORY_BY_ID = new Map(MISSING_WITNESS_CATEGORIES.map((c) => [c.id, c]));
const KNOWN_TOKENS = new Set(MISSING_WITNESS_CATEGORIES.flatMap((c) => c.tokens));

export function categoryById(id) {
  return CATEGORY_BY_ID.get(id) || null;
}

// Read off the basis name. The dollars decide which question the row is about.
const CATEGORY_OF_BASIS = {
  reached_unwitnessed: "magnitude",
  behind_unestablished_hops: "reachability",
};

function usdOrNull(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function unknownTokensOf(missing) {
  const out = [];
  for (const [token, count] of Object.entries(missing || {})) {
    if (KNOWN_TOKENS.has(token)) continue;
    out.push({ token, count: Number(count) || 0 });
  }
  return out;
}

// A proven-$0 basis renders nothing, so it can't be added to the one that holds
// the money. An unbounded (null) basis is louder.
export function statusLines(lever) {
  const lines = [];
  for (const [basis, entry] of Object.entries(lever?.by_basis || {})) {
    const ceilingUsd = usdOrNull(entry?.ceiling_usd);
    if (ceilingUsd === 0) continue;
    lines.push({
      basis,
      categoryId: CATEGORY_OF_BASIS[basis] ?? null,
      ceilingUsd,
      entities: Number(entry?.entities) || 0,
      unknownTokens: unknownTokensOf(entry?.missing_witnesses),
    });
  }
  return lines;
}

// Entities the dollar-carrying bases declined to price, as one count: the real
// ceiling may be higher. Never rendered as $0. Null-ceiling bases count too;
// that's where the ceiling is most incomplete.
export function refusalCount(lever) {
  let total = 0;
  for (const entry of Object.values(lever?.by_basis || {})) {
    if (usdOrNull(entry?.ceiling_usd) === 0) continue;
    for (const count of Object.values(entry?.entities_refused_by_reason || {})) {
      total += Number(count) || 0;
    }
  }
  return total;
}

// Benign by design or a proven $0: earned answers, so they leave the queue.
export function isClosed(lever, row) {
  if (row?.finding?.severity_proven === 0) return true;
  return usdOrNull(lever?.ceiling_usd) === 0;
}

// Only bases carrying money; a $0-basis entity must not widen a pool.
export function ceilingBearingEntities(lever) {
  const entities = new Set();
  for (const entry of Object.values(lever?.by_basis || {})) {
    if (!(usdOrNull(entry?.ceiling_usd) > 0)) continue;
    for (const item of entry?.entities_itemized || []) {
      if (item?.entity) entities.add(item.entity);
    }
  }
  return entities;
}

function joinKey(row) {
  return `${row?.capability}|${row?.principal}|${row?.chain}`;
}

function stableString(value) {
  if (Array.isArray(value)) return `[${value.map(stableString).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableString(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value === undefined ? null : value);
}

// The row's own chip wins: it was derived with the document, so a merged unit's
// member shapes survive.
export function leverChip(lever, row) {
  return row?.chip || principalChip(row?.finding || { principal_kind: "", principal: lever?.principal });
}

// Not printed on the row but part of the group key: differently-answered rows
// never merge.
function proposerUnproven(row) {
  return row?.finding ? timelockProposer(row.finding)?.proven === false : false;
}

// Levers merge only when the row would say exactly the same thing about both; a
// grouped row renders the lead's claim once. Only the controller address may
// vary. Any field added to the row must be added here too.
export function claimSignature(lever, row) {
  const chip = leverChip(lever, row);
  return stableString({
    capability: lever?.capability ?? null,
    chain: lever?.chain ?? null,
    pointsCeiling: lever?.points_ceiling ?? null,
    ceilingUsd: lever?.ceiling_usd ?? null,
    entitiesTotal: lever?.entities_total ?? null,
    byBasis: lever?.by_basis ?? null,
    chip: [chip.kind, chip.label],
    proposerUnproven: proposerUnproven(row),
    functions: row?.functions ?? null,
    exampleFunction: row?.exampleFunction ?? null,
    hosts: (row?.hosts || []).map((host) => host.canonical),
    targets: (row?.targets || []).map((target) => target.canonical),
    reachWitnessed: row?.reachWitnessed ?? null,
    undeterminedCount: row?.undeterminedCount ?? null,
  });
}

const POOL_EPSILON_USD = 0.01;
const POOL_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

// One pot reachable by several questions: same chain, same ceiling, and
// overlapping ceiling entities. Pooled rows print the pot once so it can't be
// added up.
export function assignPools(rows) {
  const pools = [];
  for (const row of rows) {
    const ceilingUsd = usdOrNull(row.lever?.ceiling_usd);
    if (!(ceilingUsd > 0)) continue;
    const entities = ceilingBearingEntities(row.lever);
    const joined = pools.find(
      (pool) =>
        pool.chain === row.lever.chain &&
        Math.abs(pool.ceilingUsd - ceilingUsd) < POOL_EPSILON_USD &&
        [...entities].some((entity) => pool.entities.has(entity)),
    );
    if (joined) {
      joined.members.push(row);
      for (const entity of entities) joined.entities.add(entity);
      continue;
    }
    pools.push({ chain: row.lever.chain, ceilingUsd, entities, members: [row] });
  }
  let next = 0;
  for (const pool of pools) {
    if (pool.members.length < 2) continue;
    const name = POOL_LETTERS[next] || String(next + 1);
    next += 1;
    for (const member of pool.members) {
      member.pool = { name, contracts: pool.entities.size, ceilingUsd: pool.ceilingUsd };
    }
  }
  return pools;
}

const VISIBLE_LEVER_ROWS = 6;

// `deductionRows` supplies the proven half of each row, joined on (capability,
// principal, chain), since the lever rollup carries no functions or targets.
export function confidenceZone(doc, deductionRows) {
  const rollup = doc?.provenance?.unresolved_levers;
  if (!rollup) return { published: false, rows: [], head: [], tail: [], remaining: 0, open: 0 };
  const byKey = new Map();
  for (const row of deductionRows || []) byKey.set(joinKey(row.finding), row);
  const grouped = new Map();
  const rows = [];
  // The producer's ranking; never re-sorted client-side.
  for (const lever of rollup.levers || []) {
    const row = byKey.get(joinKey(lever)) || null;
    if (isClosed(lever, row)) continue;
    const key = claimSignature(lever, row);
    const existing = grouped.get(key);
    if (existing) {
      existing.levers.push(lever);
      existing.rows.push(row);
      continue;
    }
    const entry = { key, lever, levers: [lever], row, rows: [row], pool: null };
    grouped.set(key, entry);
    rows.push(entry);
  }
  assignPools(rows);
  for (const entry of rows) {
    entry.controllers = [
      ...new Set(entry.levers.map((lever) => controllerAddress(lever)).filter(Boolean)),
    ];
    entry.refusals = refusalCount(entry.lever);
    entry.status = statusLines(entry.lever);
  }
  const tail = rows.slice(VISIBLE_LEVER_ROWS);
  return {
    published: true,
    rows,
    head: rows.slice(0, VISIBLE_LEVER_ROWS),
    tail,
    // Counts levers, not rows: a grouped row hides several questions.
    remaining: tail.reduce((count, entry) => count + entry.levers.length, 0),
    open: rows.reduce((count, entry) => count + entry.levers.length, 0),
  };
}
