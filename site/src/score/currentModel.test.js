import { describe, it, expect } from "vitest";
import CURRENT from "../test/fixtures/score_current_synthetic.json";
import { projectScore, valueCell } from "./derive.js";

describe("current synthetic score document", () => {
  it("retains a security finding without pretending holdings cap its magnitude", () => {
    expect(CURRENT.model_version).toBe("1.5.0-provisional");
    expect(CURRENT.grade_state).toBe("not_determined");
    expect(CURRENT.grade_lambda).toBeNull();
    expect(CURRENT.findings).toHaveLength(1);
    expect(CURRENT.findings[0].raw_points).toBeGreaterThan(0);
    expect(CURRENT.findings[0].value_at_stake_usd).toBeNull();
    expect(valueCell(CURRENT.findings[0]).determined).toBe(false);
    expect(projectScore(CURRENT, []).rows).toHaveLength(1);
  });
});
