import { describe, it, expect } from "vitest";

import { flowTypeWord, principalLabel, relationWord, shortAddr } from "./format.js";

const ADDR = "0x2aca71020de61bb532008049e1bd41e451ae8adc";

describe("principalLabel", () => {
  it("keeps a meaningful label", () => {
    expect(principalLabel("EtherFi Ops", "safe", ADDR)).toBe("EtherFi Ops");
  });

  it("falls back to the short address when the label is just the type token", () => {
    // The 'safe safe 0x..' duplication: label === type carries no information
    // beyond the type badge, so show the address instead.
    expect(principalLabel("safe", "safe", ADDR)).toBe(shortAddr(ADDR));
  });

  it("treats the label/type match case-insensitively", () => {
    expect(principalLabel("Safe", "safe", ADDR)).toBe(shortAddr(ADDR));
    expect(principalLabel("TIMELOCK", "timelock", ADDR)).toBe(shortAddr(ADDR));
  });

  it("falls back for an empty label", () => {
    expect(principalLabel("", "eoa", ADDR)).toBe(shortAddr(ADDR));
    expect(principalLabel(null, "eoa", ADDR)).toBe(shortAddr(ADDR));
  });
});

describe("edge vocabulary words", () => {
  it("projects the caller-plane and control-plane flow types", () => {
    expect(flowTypeWord("principal")).toBe("can call");
    expect(flowTypeWord("controller")).toBe("controls");
  });

  it("projects the witnessed control-graph relations", () => {
    expect(relationWord("controller_value")).toBe("control slot");
    expect(relationWord("role_principal")).toBe("role holder");
    expect(relationWord("mapping_member")).toBe("mapping member");
  });

  it("renders unknown tokens verbatim rather than inventing a word", () => {
    expect(flowTypeWord("some_future_type")).toBe("some_future_type");
    expect(relationWord("some_future_relation")).toBe("some_future_relation");
    expect(flowTypeWord(null)).toBe("");
    expect(relationWord(undefined)).toBe("");
  });
});
