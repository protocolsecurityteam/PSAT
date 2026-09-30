// Turns `dependency_graph_viz` into "Depends on" rows: resolve proxies to
// implementations, drop DELEGATES_TO/BEACON and self-calls, group calls by
// target into reads / writes / delegatecall / creates, and split internal (on
// canvas) from external.

import { api } from "../../api/client.js";
import { shortAddr } from "../format.js";

// STATIC_REF is a bytecode reference never seen called, still shown on the
// trust surface.
const OP_VERB = {
  STATICCALL: "reads",
  CALL: "writes",
  DELEGATECALL: "delegate",
  CREATE: "creates",
  CREATE2: "creates",
  STATIC_REF: "referenced",
};
const RESOLVE_OPS = new Set(["DELEGATES_TO", "BEACON"]);

// `static` = in bytecode; `dynamic` = observed in a trace.
function provenanceLabel(sources) {
  const s = new Set(sources || []);
  const hasStatic = s.has("static");
  const hasDynamic = s.has("dynamic");
  if (hasStatic && hasDynamic) return "static + observed";
  if (hasStatic) return "static";
  if (hasDynamic) return "observed";
  return "resolved";
}

// Over both proxy and implementation addresses.
export function buildAddrToMachine(machines) {
  const map = new Map();
  for (const m of machines || []) {
    const a = (m.address || "").toLowerCase();
    if (a && !map.has(a)) map.set(a, m);
    const impl = (m.implementation || "").toLowerCase();
    if (impl && !map.has(impl)) map.set(impl, m);
  }
  return map;
}

function rowFnCount(r) {
  return r.reads.length + r.writes.length + (r.delegate ? 1 : 0) + r.creates + (r.referenced ? 1 : 0);
}

/**
 * @param {object} graph  dependency_graph_viz artifact ({nodes, edges})
 * @param {object} opts
 * @param {object[]} opts.machines   the protocol's canvas machines
 * @param {string}   opts.targetAddress  the selected contract's address
 * @returns {{ external: object[], internal: object[], total: number }}
 */
export function buildDependencyView(graph, { machines = [], targetAddress = "" } = {}) {
  if (!graph || !Array.isArray(graph.nodes) || !graph.nodes.length) {
    return { external: [], internal: [], total: 0 };
  }
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const addrToMachine = buildAddrToMachine(machines);

  const delegatesTo = new Map();
  for (const e of graph.edges || []) {
    if (RESOLVE_OPS.has(e.op)) delegatesTo.set(e.from, e.to);
  }
  const resolve = (id) => {
    const seen = new Set();
    while (delegatesTo.has(id) && !seen.has(id)) {
      seen.add(id);
      id = delegatesTo.get(id);
    }
    return byId.get(id) || null;
  };

  // A contract delegatecalling its own impl isn't a dependency.
  const selfAddrs = new Set();
  const targetNode = graph.nodes.find((n) => n.is_target);
  if (targetNode?.address) selfAddrs.add(targetNode.address.toLowerCase());
  if (targetAddress) selfAddrs.add(String(targetAddress).toLowerCase());
  for (const n of graph.nodes) {
    if (n.is_proxy_context && n.address) selfAddrs.add(n.address.toLowerCase());
  }

  const groups = new Map();
  for (const e of graph.edges || []) {
    const verb = OP_VERB[e.op];
    if (!verb) continue;
    const origNode = byId.get(e.to);
    if (!origNode) continue;
    const terminal = resolve(e.to) || origNode;
    const termAddr = (terminal.address || "").toLowerCase();
    const origAddr = (origNode.address || "").toLowerCase();
    if (selfAddrs.has(termAddr) || selfAddrs.has(origAddr)) continue;

    const machine = addrToMachine.get(termAddr) || addrToMachine.get(origAddr) || null;
    const key = machine ? (machine.address || "").toLowerCase() : termAddr;
    if (!key) continue;

    if (!groups.has(key)) {
      groups.set(key, {
        key,
        name: machine ? machine.name || shortAddr(machine.address) : terminal.label || shortAddr(terminal.address),
        external: !machine,
        kind: (machine ? "regular" : terminal.type) || "regular",
        onCanvasAddress: machine ? machine.address : null,
        explorerAddress: machine ? machine.address : terminal.address || origNode.address,
        chain: machine ? machine.chain : null,
        sources: new Set(),
        reads: new Set(),
        writes: new Set(),
        delegateSeen: false,
        creates: 0,
        referencedSeen: false,
      });
    }
    const g = groups.get(key);
    for (const s of origNode.source || []) g.sources.add(s);
    if (verb === "reads" && e.function_name) g.reads.add(e.function_name);
    else if (verb === "writes" && e.function_name) g.writes.add(e.function_name);
    else if (verb === "delegate") g.delegateSeen = true;
    else if (verb === "creates") g.creates += 1;
    else if (verb === "referenced") g.referencedSeen = true;
  }

  const rows = [...groups.values()].map((g) => ({
    key: g.key,
    name: g.name,
    external: g.external,
    kind: g.kind,
    onCanvasAddress: g.onCanvasAddress,
    explorerAddress: g.explorerAddress,
    chain: g.chain,
    provenance: provenanceLabel([...g.sources]),
    reads: [...g.reads],
    writes: [...g.writes],
    delegate: g.delegateSeen,
    creates: g.creates,
    referenced: g.referencedSeen,
  }));

  const live = rows.filter((r) => rowFnCount(r) > 0);
  const external = live.filter((r) => r.external).sort((a, b) => rowFnCount(b) - rowFnCount(a));
  const internal = live.filter((r) => !r.external).sort((a, b) => rowFnCount(b) - rowFnCount(a));
  return { external, internal, total: live.length };
}


const _cache = new Map(); // cacheKey → graph|null

// A proxy's graph lives under its implementation job: try impl_job_id, then the
// proxy job, then the address. Fetches the ~30KB artifact, not the merged
// analysis blob.
export async function fetchDependencyGraphViz(machine, fetchFn = api) {
  if (!machine) return null;
  const ids = [machine.impl_job_id, machine.job_id, machine.address]
    .filter(Boolean)
    .filter((id, i, arr) => arr.indexOf(id) === i);
  if (!ids.length) return null;
  const cacheKey = ids.join("|");
  if (_cache.has(cacheKey)) return _cache.get(cacheKey);

  let result = null;
  let sawResponse = false;
  let sawUnknown = false;
  let lastError = null;
  for (const id of ids) {
    try {
      const art = await fetchFn(`/api/analyses/${encodeURIComponent(id)}/artifact/dependency_graph_viz`);
      sawResponse = true;
      if (art?.nodes?.length) {
        result = art;
        break;
      }
      // An empty graph is definitive for that id; keep trying the others.
    } catch (e) {
      // Only a 404 is a proven negative; any other failure (5xx, network
      // without `status`) leaves the question open.
      if (e?.status !== 404) sawUnknown = true;
      lastError = e;
    }
  }
  // Cache positives and proven empties only. One open id disqualifies an empty
  // sibling (it proves only its own absence), so the caller gets the error
  // state.
  if (result) {
    _cache.set(cacheKey, result);
    return result;
  }
  if (sawResponse && !sawUnknown) {
    _cache.set(cacheKey, null);
    return null;
  }
  throw lastError || new Error("Dependency graph unavailable");
}
