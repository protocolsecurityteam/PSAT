import { describe, it, expect } from "vitest";

import { proxyDisplayName } from "./displayName.js";

describe("proxyDisplayName", () => {
  it("leads with the implementation name and tucks the template into 'via'", () => {
    expect(
      proxyDisplayName({ name: "UUPSProxy", isProxy: true, implName: "LiquidityPool" }),
    ).toBe("LiquidityPool (via UUPSProxy)");
  });

  it("distinguishes proxies that share the same template name", () => {
    const a = proxyDisplayName({ name: "UUPSProxy", isProxy: true, implName: "EETH" });
    const b = proxyDisplayName({ name: "UUPSProxy", isProxy: true, implName: "WeETH" });
    expect(a).not.toBe(b);
    expect(a).toBe("EETH (via UUPSProxy)");
    expect(b).toBe("WeETH (via UUPSProxy)");
  });

  it("uses the impl name alone when there's no distinct template name", () => {
    expect(proxyDisplayName({ name: "", isProxy: true, implName: "Vault" })).toBe("Vault");
    // name == impl (case-insensitively): no "(via …)" suffix, returns the impl.
    expect(proxyDisplayName({ name: "vault", isProxy: true, implName: "vault" })).toBe("vault");
  });

  it("returns the raw name for non-proxy rows", () => {
    expect(proxyDisplayName({ name: "WETH9", isProxy: false, implName: null })).toBe("WETH9");
  });

  it("returns the raw name when a proxy has no resolved implementation", () => {
    expect(proxyDisplayName({ name: "UUPSProxy", isProxy: true, implName: null })).toBe("UUPSProxy");
  });

  it("returns '' for empty/missing input", () => {
    expect(proxyDisplayName()).toBe("");
    expect(proxyDisplayName({})).toBe("");
  });
});
