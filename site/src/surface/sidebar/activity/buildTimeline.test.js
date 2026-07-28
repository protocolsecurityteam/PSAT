import { describe, it, expect } from "vitest";

import { buildTimeline } from "./buildTimeline.js";
import { shortenAddress } from "../../../graph.js";

const I1 = "0x1111111111111111111111111111111111111111"; // first deployment
const I2 = "0x2222222222222222222222222222222222222222";
const CUR = "0x3333333333333333333333333333333333333333"; // current impl

const PROXY = {
  proxy_type: "ERC1967",
  current_implementation: CUR,
  upgrade_count: 2,
  implementations: [
    { address: I1, block_introduced: 100, block_replaced: 200, timestamp_introduced: 1000 },
    { address: I2, block_introduced: 200, block_replaced: 300, timestamp_introduced: 2000 },
    { address: CUR, block_introduced: 300, timestamp_introduced: 3000 }, // block_replaced ∞
  ],
};

function ev(id, type, block, data = {}) {
  return {
    id,
    event_type: type,
    block_number: block,
    tx_hash: `0x${"a".repeat(64)}`,
    data,
    detected_at: new Date(block * 1000).toISOString(),
  };
}

describe("buildTimeline — proxy with enrollment boundary", () => {
  const events = [
    ev("e-upgrade", "upgraded", 300, { implementation: CUR }),
    ev("e-role", "role_granted", 260, { account: I1, sender: I2 }),
  ];
  const out = buildTimeline({ events, proxy: PROXY, enrollmentBlock: 250, isProxy: true });

  it("puts live-captured events above the boundary, newest-first", () => {
    expect(out.boundaryBlock).toBe(250);
    expect(out.above.map((r) => r.block)).toEqual([300, 260]);
    expect(out.above[0].source).toBe("event");
    expect(out.above[0].isUpgrade).toBe(true);
    expect(out.above[0].isCurrent).toBe(true); // event impl === current_implementation
  });

  it("back-fills only pre-boundary upgrades, dimmed + tagged", () => {
    expect(out.below.map((r) => r.block)).toEqual([200, 100]);
    expect(out.below.every((r) => r.backfill && r.isUpgrade)).toBe(true);
    expect(out.below[1].title).toBe("First deployment");
    expect(out.below[0].title).toBe("Implementation upgraded");
  });

  it("dedups the post-enrollment upgrade present in both stores", () => {
    // The upgrade at block 300 → CUR appears as a monitored event AND as the
    // current impl in upgrade_history. Only the event row survives.
    const at300 = [...out.above, ...out.below].filter((r) => r.block === 300);
    expect(at300).toHaveLength(1);
    expect(at300[0].source).toBe("event");
  });

  it("attributes each logic event to the impl live at its block", () => {
    const role = out.above.find((r) => r.kind === "role");
    // block 260 → era [200, 300) → I2
    expect(role.implAttr).toBe(shortenAddress(I2));
  });
});

describe("buildTimeline — non-proxy", () => {
  it("keeps only above-boundary events; drops sub-boundary non-upgrades", () => {
    const events = [ev("a", "role_granted", 260, {}), ev("b", "paused", 100, {})];
    const out = buildTimeline({ events, proxy: null, enrollmentBlock: 250, isProxy: false });
    expect(out.above.map((r) => r.block)).toEqual([260]);
    expect(out.below).toEqual([]);
    expect(out.boundaryBlock).toBe(250);
  });
});

describe("buildTimeline — null enrollment_block (legacy row)", () => {
  it("draws no boundary and renders all history as-is", () => {
    const events = [ev("e-role", "role_granted", 260, {})];
    const out = buildTimeline({ events, proxy: PROXY, enrollmentBlock: null, isProxy: true });
    expect(out.boundaryBlock).toBeNull();
    expect(out.below).toEqual([]);
    // First deployment still present — nothing is hidden below a (missing) line.
    expect(out.above.some((r) => r.title === "First deployment")).toBe(true);
    // Never tagged as backfill without a boundary.
    expect(out.above.every((r) => !r.backfill)).toBe(true);
  });
});

// `synthesize_from_events` emits `block_number: null` for a poll-detected upgrade,
// so an impl era can carry an unknown boundary. Folding it to 0 / Infinity is the
// same ±infinity spread W0-9 removed server-side (L-19 / L-26).
describe("buildTimeline — an unknown era boundary is not a boundary value", () => {
  const POLL_PROXY = {
    current_implementation: CUR,
    implementations: [
      // A poll-detected first impl: introduced block unknown, and its successor's
      // block is known, so `block_replaced` is present and set.
      { address: I1, block_introduced: null, block_replaced: 200, timestamp_introduced: 1000 },
      { address: I2, block_introduced: 200, block_replaced: 300, timestamp_introduced: 2000 },
      { address: CUR, block_introduced: 300, timestamp_introduced: 3000 },
    ],
  };

  it("does not attribute an early event to an era whose start is unknown", () => {
    // `from` folded to 0 made this era start at genesis and claim every event
    // before block 200 — including one that predates the impl entirely.
    const out = buildTimeline({
      events: [ev("e-role", "role_granted", 50, {})],
      proxy: POLL_PROXY,
      enrollmentBlock: null,
      isProxy: true,
    });
    const row = out.above.find((r) => r.key === "ev:e-role");
    expect(row.implAttr).toBeNull();
  });

  it("still attributes an event inside a fully-known era", () => {
    // POSITIVE CONTROL: skipping every era would erase impl attribution wholesale.
    const out = buildTimeline({
      events: [ev("e-role", "role_granted", 250, {})],
      proxy: POLL_PROXY,
      enrollmentBlock: null,
      isProxy: true,
    });
    expect(out.above.find((r) => r.key === "ev:e-role").implAttr).toBe(shortenAddress(I2));
  });

  it("distinguishes a missing block_replaced KEY from a null one", () => {
    // The producer writes `block_replaced` from the NEXT event unconditionally, so
    // key-absent means "current era, runs to now" and present-but-null means "a
    // successor exists whose block was never determined". Only the first may run
    // to infinity.
    const openEnded = {
      current_implementation: CUR,
      implementations: [{ address: CUR, block_introduced: 300, timestamp_introduced: 3000 }],
    };
    const unknownEnd = {
      current_implementation: CUR,
      implementations: [
        { address: I1, block_introduced: 300, block_replaced: null, timestamp_introduced: 3000 },
        { address: CUR, block_introduced: null, timestamp_introduced: 4000 },
      ],
    };
    const later = [ev("e-role", "role_granted", 900, {})];
    expect(
      buildTimeline({ events: later, proxy: openEnded, enrollmentBlock: null, isProxy: true })
        .above.find((r) => r.key === "ev:e-role").implAttr,
    ).toBe(shortenAddress(CUR));
    expect(
      buildTimeline({ events: later, proxy: unknownEnd, enrollmentBlock: null, isProxy: true })
        .above.find((r) => r.key === "ev:e-role").implAttr,
    ).toBeNull();
  });

  it("attributes every block to a proxy that has only ever had one impl", () => {
    // `_build_implementation_timeline` returns a bare `{address}` when there are no
    // upgrade events. Any block is under it — a fact about the LIST, not a guessed
    // introduction block, and the one case an unknown `from` is still answerable.
    const single = { current_implementation: CUR, implementations: [{ address: CUR }] };
    const out = buildTimeline({
      events: [ev("e-role", "role_granted", 7, {})],
      proxy: single,
      enrollmentBlock: null,
      isProxy: true,
    });
    expect(out.above.find((r) => r.key === "ev:e-role").implAttr).toBe(shortenAddress(CUR));
  });
});
