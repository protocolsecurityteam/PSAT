import React from "react";
import { describe, it, expect } from "vitest";
import { render } from "@testing-library/react";

import { InspectorCard } from "./InspectorCard.jsx";
import { guardSummary } from "../layout/guardSummary.js";

// A principal-less function (no direct callers) so the inspector renders the
// empty-callers copy — the line that used to be a flat "marked public" for
// every open shape.
function selectedFor(conditions, authority_public = true) {
  const fn = { function: "f(address)", authority_public, conditions };
  return {
    name: "f",
    contractName: "Vault",
    contractAddress: "0xcontract",
    lane: "top",
    signature: "f(address)",
    action: "does a thing",
    effectLabels: [],
    guard: guardSummary(fn, {}),
    principals: [],
    indirectPrincipals: [],
    authorityPublic: authority_public,
  };
}

function body(conditions, authority_public = true) {
  const { container } = render(<InspectorCard selected={selectedFor(conditions, authority_public)} />);
  return container.textContent;
}

describe("InspectorCard empty-callers copy", () => {
  it("never falls back to the flat 'marked public' line for an open shape", () => {
    for (const conditions of [
      [{ kind: "one_shot", latch_state: "consumed" }],
      [{ kind: "denylist" }],
      [{ kind: "permit_sig" }],
      [],
    ]) {
      expect(body(conditions)).not.toContain("marked public in the authority state");
    }
  });

  it("describes a consumed one-shot as spent, not exploitable", () => {
    expect(body([{ kind: "one_shot", latch_state: "consumed" }])).toContain("Consumed one-shot initializer");
  });

  it("describes a live one-shot as live", () => {
    expect(body([{ kind: "one_shot", latch_state: "live" }])).toContain("Live one-shot initializer");
  });

  it("describes a denylist-open function as permissionless-except-denylist", () => {
    expect(body([{ kind: "denylist" }])).toContain("denylist");
  });

  it("describes a plain permissionless function as callable by anyone", () => {
    expect(body([])).toContain("Permissionless — callable by anyone");
  });

  it("still flags a non-public, unresolved function as such", () => {
    expect(body([], false)).toContain("No controlling principal was resolved");
  });
});
