import { describe, it, expect } from "vitest";

import { buildAddrToMachine, buildDependencyView, fetchDependencyGraphViz } from "./dependencies.js";

const TARGET_IMPL = "0x6bd191582f40012b2f2cdf66bd3d32bde41191f7";
const TARGET_PROXY = "0xdadef1ffbfeaab4f68a9fd181395f68b4e4e7ae0";
const LP_PROXY = "0x308861a430be4cce5502d0a12724771fc6daf216";
const LP_IMPL = "0x83bc649fcdb2c8da146b2154a559ddedf937ef12";
const LIDO_PROXY = "0xae7ab96520de3a18e5e111b5eaab095312d7fe84";
const LIDO_IMPL = "0x6ca84080381e43938476814be61b779a8bb6a600";
const LIB = "0x4f9a642789a4f0254f5f02bdac39664c174233b3";

// A trimmed dependency_graph_viz mirroring the real RedemptionManager shape:
// calls land on proxy nodes, a DELEGATES_TO edge maps proxy → impl, and the
// off-canvas Lido is reached through its own proxy.
const GRAPH = {
  nodes: [
    { id: "addr:proxy", address: TARGET_PROXY, label: "RedemptionManager", type: "proxy", is_proxy_context: true, source: [] },
    { id: "addr:target", address: TARGET_IMPL, label: "RedemptionManager", type: "implementation", is_target: true, source: [] },
    { id: "addr:lp_proxy", address: LP_PROXY, label: "UUPSProxy", type: "proxy", source: ["dynamic"] },
    { id: "addr:lp_impl", address: LP_IMPL, label: "LiquidityPool", type: "implementation", source: ["classification"] },
    { id: "addr:lido_proxy", address: LIDO_PROXY, label: "AppProxyUpgradeable", type: "proxy", source: ["dynamic"] },
    { id: "addr:lido_impl", address: LIDO_IMPL, label: "Lido", type: "implementation", source: ["classification"] },
    { id: "addr:lib", address: LIB, label: "BucketLimiter", type: "library", source: ["dynamic", "static"] },
  ],
  edges: [
    { from: "addr:target", to: "addr:lp_proxy", op: "CALL", function_name: "withdraw" },
    { from: "addr:target", to: "addr:lp_proxy", op: "STATICCALL", function_name: "sharesForAmount" },
    { from: "addr:target", to: "addr:lp_proxy", op: "STATICCALL", function_name: "getTotalPooledEther" },
    { from: "addr:target", to: "addr:lido_proxy", op: "STATICCALL", function_name: "balanceOf" },
    { from: "addr:target", to: "addr:lib", op: "DELEGATECALL" },
    // resolution edges — must not appear as dependencies
    { from: "addr:lp_proxy", to: "addr:lp_impl", op: "DELEGATES_TO" },
    { from: "addr:lido_proxy", to: "addr:lido_impl", op: "DELEGATES_TO" },
    { from: "addr:proxy", to: "addr:target", op: "DELEGATES_TO" },
    // self delegatecall — noise
    { from: "addr:target", to: "addr:target", op: "DELEGATECALL", function_name: "initialize" },
  ],
};

const MACHINES = [
  { address: TARGET_PROXY, implementation: TARGET_IMPL, name: "EtherFiRedemptionManager", chain: "ethereum" },
  { address: LP_PROXY, implementation: LP_IMPL, name: "LiquidityPool", chain: "ethereum" },
];

describe("buildAddrToMachine", () => {
  it("maps both proxy and implementation addresses to the machine", () => {
    const map = buildAddrToMachine(MACHINES);
    expect(map.get(LP_PROXY).name).toBe("LiquidityPool");
    expect(map.get(LP_IMPL).name).toBe("LiquidityPool");
  });
});

describe("buildDependencyView", () => {
  const view = buildDependencyView(GRAPH, { machines: MACHINES, targetAddress: TARGET_PROXY });

  it("splits on-canvas internal from off-canvas external", () => {
    expect(view.internal.map((r) => r.name)).toEqual(["LiquidityPool"]);
    expect(view.external.map((r) => r.name).sort()).toEqual(["BucketLimiter", "Lido"]);
  });

  it("resolves proxy calls to the implementation name, keyed on the canvas node", () => {
    const lp = view.internal[0];
    expect(lp.onCanvasAddress).toBe(LP_PROXY); // focus target is the canvas node
    expect(lp.writes).toEqual(["withdraw"]);
    expect(lp.reads.sort()).toEqual(["getTotalPooledEther", "sharesForAmount"]);
  });

  it("classifies a delegatecall library as external with a library kind", () => {
    const lib = view.external.find((r) => r.name === "BucketLimiter");
    expect(lib.kind).toBe("library");
    expect(lib.delegate).toBe(true);
    expect(lib.provenance).toBe("static + observed");
  });

  it("names the off-canvas integration by its impl, not its proxy", () => {
    const lido = view.external.find((r) => r.name === "Lido");
    expect(lido.reads).toEqual(["balanceOf"]);
    expect(lido.explorerAddress).toBe(LIDO_IMPL);
    expect(lido.provenance).toBe("observed");
  });

  it("drops DELEGATES_TO resolution edges and self-calls", () => {
    // 3 dependencies total (LiquidityPool, Lido, BucketLimiter); the target's
    // self-delegatecall and every DELEGATES_TO edge are excluded.
    expect(view.total).toBe(3);
    expect(view.internal.every((r) => r.name !== "EtherFiRedemptionManager")).toBe(true);
  });

  it("returns an empty view for a graph with no nodes", () => {
    expect(buildDependencyView(null, {})).toEqual({ external: [], internal: [], total: 0 });
    expect(buildDependencyView({ nodes: [] }, {})).toEqual({ external: [], internal: [], total: 0 });
  });

  it("surfaces a STATIC_REF as a 'referenced' dependency (no call decoded)", () => {
    const LIB2 = "0x1234567890123456789012345678901234567890";
    const graph = {
      nodes: [
        { id: "t", address: TARGET_IMPL, label: "RedemptionManager", type: "implementation", is_target: true, source: [] },
        { id: "ref", address: LIB2, label: "SomeLib", type: "library", source: ["static"] },
      ],
      edges: [{ from: "t", to: "ref", op: "STATIC_REF" }],
    };
    const view = buildDependencyView(graph, { machines: [], targetAddress: TARGET_IMPL });
    expect(view.total).toBe(1);
    const row = view.external[0];
    expect(row.name).toBe("SomeLib");
    expect(row.referenced).toBe(true);
    expect(row.reads).toEqual([]);
    expect(row.writes).toEqual([]);
    expect(row.provenance).toBe("static"); // static-only discovery is now reachable
  });
});

describe("fetchDependencyGraphViz — only a proven negative may render as absence", () => {
  // DependsOnTab renders `null` as "No outbound calls detected" and a throw as
  // "Couldn't load dependency data". Any id the server did not answer for must
  // land in the second, even when a sibling id answered with an empty graph —
  // otherwise an unanswered question is cached and rendered as a fact about the
  // contract for the rest of the session.
  //
  // The mapping under test is deliberately *not* an enumeration of failure
  // codes: 404 is the only proven negative, everything else is a non-answer.
  // The three throwing cases below are the three shapes that a 503-only
  // enumeration silently dropped — a plain 500, an edge 502/504, and a network
  // failure that arrives with no `status` at all.
  const MACHINE = { impl_job_id: "job-impl", job_id: "job-proxy", address: "0xabc" };
  const failWith = (status, message) => () => {
    const e = new Error(message);
    if (status !== null) e.status = status;
    throw e;
  };
  const notDetermined = failWith(503, "Artifact state not determined");
  const graphOf = (addr) => ({
    nodes: [{ id: "addr:x", address: addr, label: "X", type: "contract", source: [] }],
    edges: [],
  });

  it("throws instead of returning an empty graph when any id answered 503", async () => {
    const fetchFn = async (url) => (url.includes("job-impl") ? notDetermined() : { nodes: [] });
    await expect(fetchDependencyGraphViz({ ...MACHINE, address: "0xa1" }, fetchFn)).rejects.toThrow(
      /not determined/i,
    );
  });

  // The three below are the reviewer's repro, inverted to pin the fix. Under
  // the previous `status === 503` mapping every one of them resolved to `null`
  // — the absence state — and cached it.
  it.each([
    ["a 500", 500, "Internal Server Error"],
    ["an edge 502 while the web machine autostops", 502, "Bad Gateway"],
    ["a network failure carrying no status", null, "Failed to fetch"],
  ])("throws when one id hit %s and a sibling returned an empty graph", async (_label, status, message) => {
    const boom = failWith(status, message);
    const fetchFn = async (url) => (url.includes("job-impl") ? boom() : { nodes: [] });
    await expect(
      fetchDependencyGraphViz({ ...MACHINE, address: `0xa-${status}` }, fetchFn),
    ).rejects.toThrow(message);
  });

  it("leaves the cache unset after a non-answer, so a later healthy fetch answers", async () => {
    // The half of the defect that outlived the request: a `null` derived from a
    // non-answer was written to the module-level cache, so every later open of
    // the tab short-circuited to "No outbound calls detected" for the rest of
    // the session and no healthy fetch could correct it.
    const machine = { ...MACHINE, address: "0xcache" };
    const boom = failWith(500, "Internal Server Error");
    const failing = async (url) => (url.includes("job-impl") ? boom() : { nodes: [] });
    await expect(fetchDependencyGraphViz(machine, failing)).rejects.toThrow(/Internal Server Error/);

    const graph = graphOf("0xdef");
    await expect(fetchDependencyGraphViz(machine, async () => graph)).resolves.toBe(graph);
  });

  it("still returns a confirmed empty when every id simply had nothing", async () => {
    // NEGATIVE CONTROL: a real "no dependencies" must keep rendering as one.
    const fetchFn = async () => ({ nodes: [] });
    await expect(fetchDependencyGraphViz({ ...MACHINE, address: "0xa2" }, fetchFn)).resolves.toBeNull();
  });

  it("treats a 404 as the proven negative it is: an empty sibling still confirms", async () => {
    // NEGATIVE CONTROL for the over-correction. Widening the hedge to "any
    // thrown error" would turn the ordinary case — the graph lives under the
    // impl job, so the proxy job legitimately 404s — into a permanent
    // "couldn't load", and the test above could not tell the difference.
    const missing = failWith(404, "Artifact not found");
    const fetchFn = async (url) => (url.includes("job-proxy") ? missing() : { nodes: [] });
    await expect(fetchDependencyGraphViz({ ...MACHINE, address: "0xa4" }, fetchFn)).resolves.toBeNull();
  });

  it("still prefers a real graph over a sibling's 503", async () => {
    const graph = graphOf("0xdef");
    const fetchFn = async (url) => (url.includes("job-impl") ? notDetermined() : graph);
    await expect(fetchDependencyGraphViz({ ...MACHINE, address: "0xa3" }, fetchFn)).resolves.toBe(graph);
  });
});
