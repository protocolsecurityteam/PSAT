// The "possible deductions" projection: provenance.unresolved_levers rendered
// as questions, never as charges. Nothing derived here enters λ, the letter or
// the exposure grade — every figure is an at-most on what ANSWERING the
// question could put at stake, and a question with no answer yet is a third
// state that must not collapse into either a zero or a charge.
//
// Pure functions, no React.

import { controllerAddress } from "./derive.js";

// The category a missing-witness token belongs to. This is a fixed 1:1 table,
// not an allow-list with a default: a token no category claims renders as
// not-determined WITH the raw token beside it, because a class the page cannot
// name is still a class the document published.
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

// Which question a basis IS, read off the basis name rather than off its
// tokens: `reached_unwitnessed` holds entities the row provably reaches whose
// magnitude is unmeasured, `behind_unestablished_hops` holds entities behind a
// link that was never established. The dollars decide which one the row is
// about — the basis carrying the ceiling is the question holding the stake.
export const CATEGORY_OF_BASIS = {
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

// One status line per basis that carries dollars. A basis whose ceiling is a
// proven $0 renders NOTHING here: it holds none of the money the row is about,
// and printing it beside the one that does invites the two figures to be added.
// A basis whose ceiling was never bounded (null) is louder, not quieter.
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

// Every entity the dollar-carrying bases declined to price, folded to one
// count. The reasons (`unpriced`, `no_rows`) differ but the consequence does
// not: these contracts contribute nothing to the ceiling, so the real ceiling
// may be higher — which is what the chip says. A refused set is never rendered
// as a $0.
export function refusalCount(lever) {
  let total = 0;
  for (const entry of Object.values(lever?.by_basis || {})) {
    if (!(usdOrNull(entry?.ceiling_usd) > 0)) continue;
    for (const count of Object.values(entry?.entities_refused_by_reason || {})) {
      total += Number(count) || 0;
    }
  }
  return total;
}

// A lever with no question left to ask: its act ranks benign by design, or its
// ceiling resolved to a proven $0. Both are earned answers, not gaps, so they
// leave the queue rather than sitting in it at zero.
export function isClosed(lever, row) {
  if (row?.finding?.severity_proven === 0) return true;
  return usdOrNull(lever?.ceiling_usd) === 0;
}

// The entities holding the dollars this row's ceiling is made of. Read off the
// bases that carry money — an entity itemised under a $0 basis holds none of it
// and must not widen a pool.
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

export function joinKey(row) {
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

// Two levers are one row when they are the same capability on the same chain
// waiting on a byte-identical set of unanswered entities. Answering it answers
// both, and their ceilings are one pot of money seen twice — so they are shown
// once, with a count of who holds the permission. Capability is part of the
// key: a row names one capability, and merging two under one label would
// publish a claim the document does not make.
export function groupKey(lever) {
  return `${lever?.capability}|${lever?.chain}|${stableString(lever?.by_basis)}`;
}

export const POOL_EPSILON_USD = 0.01;
export const POOL_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

// One pot of money reachable by several questions. Membership needs the same
// chain, the same ceiling, and an OVERLAP in the entities the ceiling is made
// of — containment counts, equality is not required. Rows in a pool print the
// pot once so a reader cannot add them together; a row whose ceiling merely
// happens to be similar is not in the pool, because it is not the same money.
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

export const VISIBLE_LEVER_ROWS = 6;

// The whole table. `deductionRows` is the projection Deductions already renders
// from — the lever rollup carries no functions or targets of its own, so the
// proven half of every row is the SAME derivation the deduction beside it uses,
// joined on (capability, principal, chain). A lever with no matching finding
// keeps its row and shows only what the lever itself witnesses.
export function confidenceZone(doc, deductionRows) {
  const rollup = doc?.provenance?.unresolved_levers;
  if (!rollup) return { published: false, rows: [], head: [], tail: [], remaining: 0, open: 0 };
  const byKey = new Map();
  for (const row of deductionRows || []) byKey.set(joinKey(row.finding), row);
  const grouped = new Map();
  const rows = [];
  // Arrival order is the producer's ranking by points ceiling. It is never
  // re-sorted here: a client-side rank would be a second opinion on a figure
  // the document already published.
  for (const lever of rollup.levers || []) {
    const row = byKey.get(joinKey(lever)) || null;
    if (isClosed(lever, row)) continue;
    const key = groupKey(lever);
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
    // The tail counts LEVERS, not rows: it stands for the questions still to
    // read, and a grouped row hides more than one of them.
    remaining: tail.reduce((count, entry) => count + entry.levers.length, 0),
    open: rows.reduce((count, entry) => count + entry.levers.length, 0),
  };
}
