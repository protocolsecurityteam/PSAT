import { describe, expect, it } from "vitest";

import { roleLabel } from "./role.js";

describe("roleLabel", () => {
  it("never renders a role reached through not-determined inputs as a fact", () => {
    expect(roleLabel({ role: "utility", role_evidence: "not_determined" })).toBe("Role not determined");
  });

  it("words a witnessed role", () => {
    expect(roleLabel({ role: "value_handler", role_evidence: "witnessed" })).toBe("Value Handler");
    expect(roleLabel({ role: "utility", role_evidence: "witnessed" })).toBe("Utility");
  });

  it("renders unknown role and evidence tokens raw", () => {
    expect(roleLabel({ role: "oracle", role_evidence: "witnessed" })).toBe("oracle");
    expect(roleLabel({ role: "token", role_evidence: "inferred" })).toBe("Token · inferred");
  });
});
