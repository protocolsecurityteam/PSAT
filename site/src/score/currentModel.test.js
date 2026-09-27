import { describe, it, expect } from "vitest";
import CURRENT from "../test/fixtures/score_current_synthetic.json";
import { projectScore, valueCell } from "./derive.js";

describe("current synthetic score document", () => {
  it("retains a security finding without pretending holdings cap its magnitude", () => {
    expect(CURRENT.model_version).toBe("1.5.1-provisional");
    expect(CURRENT.grade_state).toBe("computed");
    expect(CURRENT.grade_lambda).toBeGreaterThan(0);
    expect(CURRENT.confidence_pct).toBeGreaterThanOrEqual(0);
    expect(CURRENT.grade_exposure).toBeNull();
    expect(CURRENT.findings).toHaveLength(1);
    expect(CURRENT.findings[0].raw_points).toBeGreaterThan(0);
    expect(CURRENT.findings[0].value_at_stake_usd).toBe(2000000);
    expect(CURRENT.findings[0].value_at_stake_bound_direction).toBe("not_determined");
    expect(valueCell(CURRENT.findings[0]).determined).toBe(true);
    expect(projectScore(CURRENT, []).rows).toHaveLength(1);
  });
});
