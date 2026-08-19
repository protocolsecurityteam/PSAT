import { describe, expect, it } from "vitest";

import { isInertOneShot, isLiveOneShot, oneShotState } from "./oneShot.js";
import { guardSummary } from "./guardSummary.js";

function fnWithCondition(latch_state) {
  return {
    function: "initialize(address)",
    authority_public: true,
    conditions: latch_state === undefined
      ? [{ kind: "one_shot", description: "init latch" }]
      : [{ kind: "one_shot", description: "init latch", latch_state }],
  };
}

describe("oneShotState", () => {
  it("reads consumed / live / indeterminate from the one_shot condition", () => {
    expect(oneShotState(fnWithCondition("consumed"))).toBe("consumed");
    expect(oneShotState(fnWithCondition("live"))).toBe("live");
    expect(oneShotState(fnWithCondition(undefined))).toBe("indeterminate");
  });

  it("returns null for a function with no one_shot condition", () => {
    expect(oneShotState({ conditions: [{ kind: "pause" }] })).toBe(null);
    expect(oneShotState({})).toBe(null);
  });

  it("live dominates when multiple one_shot conditions disagree", () => {
    const fn = { conditions: [{ kind: "one_shot", latch_state: "consumed" }, { kind: "one_shot", latch_state: "live" }] };
    expect(oneShotState(fn)).toBe("live");
  });

  it("inert/live predicates key off the latch state", () => {
    expect(isInertOneShot(fnWithCondition("consumed"))).toBe(true);
    expect(isInertOneShot(fnWithCondition("live"))).toBe(false);
    expect(isLiveOneShot(fnWithCondition("live"))).toBe(true);
    expect(isLiveOneShot(fnWithCondition("consumed"))).toBe(false);
  });
});

describe("guardSummary one-shot dispositions", () => {
  it("renders a consumed one-shot as inert (resolved_empty), not open", () => {
    const guard = guardSummary(fnWithCondition("consumed"), {});
    expect(guard.kind).toBe("resolved_empty");
    expect(guard.sublabel).toBe("one-shot · consumed");
  });

  it("renders a live one-shot as its own high-severity badge", () => {
    const guard = guardSummary(fnWithCondition("live"), {});
    expect(guard.kind).toBe("one_shot_live");
    expect(guard.sublabel).toBe("one-shot · LIVE");
  });

  it("renders an unread one-shot as a labeled open (neither inert nor critical)", () => {
    const guard = guardSummary(fnWithCondition(undefined), {});
    expect(guard.kind).toBe("open");
    expect(guard.sublabel).toBe("one-shot");
  });

  it("leaves a plain public function unchanged", () => {
    const guard = guardSummary({ function: "deposit()", authority_public: true, conditions: [] }, {});
    expect(guard.kind).toBe("open");
    expect(guard.sublabel).toBe("public");
  });
});

describe("guardSummary open-path shapes", () => {
  const pub = (conditions) => ({ function: "f()", authority_public: true, conditions });

  it("gives denylist / permit / self-service their own sublabel and shape", () => {
    const deny = guardSummary(pub([{ kind: "denylist" }]), {});
    expect(deny.sublabel).toBe("denylist");
    expect(deny.shape).toBe("denylist");

    const permit = guardSummary(pub([{ kind: "permit_sig" }]), {});
    expect(permit.sublabel).toBe("signature");
    expect(permit.shape).toBe("permit");

    const selfsvc = guardSummary(pub([{ kind: "self_service" }]), {});
    expect(selfsvc.sublabel).toBe("self-service");
    expect(selfsvc.shape).toBe("self_service");
  });

  it("keeps a plain permissionless function as public", () => {
    const plain = guardSummary(pub([]), {});
    expect(plain.label).toBe("OPEN");
    expect(plain.sublabel).toBe("public");
    expect(plain.shape).toBe("public");
  });

  it("tags one-shot states with a distinct shape", () => {
    expect(guardSummary(pub([{ kind: "one_shot", latch_state: "consumed" }]), {}).shape).toBe("one_shot_consumed");
    expect(guardSummary(pub([{ kind: "one_shot", latch_state: "live" }]), {}).shape).toBe("one_shot_live");
    expect(guardSummary(pub([{ kind: "one_shot" }]), {}).shape).toBe("one_shot_unread");
  });
});
