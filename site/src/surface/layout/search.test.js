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

  it("badges a contract by its own role, not the controlling principal's type", () => {
    const owned = { address: "0xowned", name: "Vault", role: "value_handler", total_usd: 5, totalFunctions: 3 };
    const owner = { address: "0xsafe2", type: "safe", label: "s", controls: ["0xowned"] };
    const [item] = buildSearchResults([owned], [owner], "contracts", "value", "");
    expect(item.kind).toBe("contract");
    expect(item.type).toBe("Value Handler"); // singular role label — never the owner's "safe"
  });

  it("falls back to the Utility role label for a role-less contract (no more 'unknown')", () => {
    const [item] = buildSearchResults([plainMachine], [], "contracts", "name", "");
    expect(item.type).toBe("Utility");
    expect(item.type).not.toBe("unknown");
  });

  it("singularizes roles a naive trailing-`s` strip would mangle (factory → Factory, not Factorie)", () => {
    const f = { address: "0xf", name: "AvsOperatorManager", role: "factory", total_usd: 0, totalFunctions: 1 };
    const [item] = buildSearchResults([f], [], "contracts", "name", "");
    expect(item.type).toBe("Factory");
  });

  it("does not surface a bare-type label as the name (kills the 'safe safe' duplication)", () => {
    const bareSafe = {
      address: "0x2aca71020de61bb532008049e1bd41e451ae8adc",
      type: "safe",
      label: "safe", // server emitted the bare type token as the label
      controls: [],
    };
    const [item] = buildSearchResults([], [bareSafe], "safe", "name", "");
    // Falls back to the short address rather than repeating the type.
    expect(item.name).not.toBe("safe");
    expect(item.name).toBe("0x2aca..8adc");
  });
});
