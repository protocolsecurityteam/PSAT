import { describe, expect, it } from "vitest";

import { upgradeCountText } from "./upgradeFacts.js";

const basis = (recorded_count_relation, over = {}) => ({ history_fetch_status: "complete", recorded_count_relation, ...over });

describe("upgradeCountText", () => {
  it("words each recorded_count_relation token", () => {
    expect(upgradeCountText({ upgrade_count: 2, upgrade_count_basis: basis("exact") })).toBe("2 recorded upgrades");
    expect(upgradeCountText({ upgrade_count: 1, upgrade_count_basis: basis("exact") })).toBe("1 recorded upgrade");
    expect(upgradeCountText({ upgrade_count: 4, upgrade_count_basis: basis("upper_bound") })).toBe("up to 4 upgrades");
    expect(upgradeCountText({ upgrade_count: 4, upgrade_count_basis: basis("not_determined") })).toBe(
      "4 upgrades · bound not determined",
    );
  });

  it("renders an unknown relation token raw", () => {
    expect(upgradeCountText({ upgrade_count: 2, upgrade_count_basis: basis("lower_bound") })).toBe("2 upgrades · lower_bound");
  });

  it("keeps a basis with no count as not determined, never zero", () => {
    const entry = { upgrade_count: null, upgrade_count_basis: basis("not_determined", { history_fetch_status: "error" }) };
    expect(upgradeCountText(entry)).toBe("upgrades not determined");
  });

  it("makes no claim without a count or a basis", () => {
    expect(upgradeCountText({ upgrade_count: null, upgrade_count_basis: null })).toBeNull();
    expect(upgradeCountText({})).toBeNull();
    expect(upgradeCountText(null)).toBeNull();
    expect(upgradeCountText({ upgrade_count: 0 })).toBeNull();
  });

  it("adds no qualifier the backend didn't send", () => {
    expect(upgradeCountText({ upgrade_count: 3 })).toBe("3 upgrades");
  });
});
