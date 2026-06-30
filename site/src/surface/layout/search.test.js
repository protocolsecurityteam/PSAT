import { describe, it, expect } from "vitest";
import { buildSearchResults } from "./search.js";

const tlPrincipal = { address: "0xcd42", type: "timelock", label: "timelock", controls: ["0xowned"], details: { delay: 172800 } };
const safePrincipal = { address: "0xsafe", type: "safe", label: "safe", controls: [] };
const tlMachine = { address: "0x9f26", name: "EtherFiTimelock", isTimelock: true, timelockDelay: 172800, total_usd: 0, totalFunctions: 9 };
const plainMachine = { address: "0xweeth", name: "WeETH", isTimelock: false, total_usd: 100, totalFunctions: 22 };

describe("buildSearchResults — Timelocks filter", () => {
  it("includes timelock principals AND timelock contracts", () => {
    const r = buildSearchResults([tlMachine, plainMachine], [tlPrincipal, safePrincipal], "timelock", "name", "");
    const addrs = r.map((i) => i.address);
    expect(addrs).toContain("0xcd42"); // timelock principal
    expect(addrs).toContain("0x9f26"); // timelock contract (control-graph type=timelock)
    expect(addrs).not.toContain("0xweeth"); // plain contract excluded
    expect(addrs).not.toContain("0xsafe"); // safe principal excluded
  });

  it("does not leak timelock contracts into the Safes filter", () => {
    const r = buildSearchResults([tlMachine, plainMachine], [tlPrincipal, safePrincipal], "safe", "name", "");
    expect(r.map((i) => i.address)).toEqual(["0xsafe"]);
  });

  it("dedupes an address that is both a timelock principal and a timelock contract", () => {
    const dual = { address: "0x9f26", type: "timelock", label: "tl", controls: [] };
    const r = buildSearchResults([tlMachine], [dual], "timelock", "name", "");
    expect(r.filter((i) => i.address?.toLowerCase() === "0x9f26").length).toBe(1);
  });
});
