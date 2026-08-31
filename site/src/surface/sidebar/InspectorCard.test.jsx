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
    claims: [],
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

// SCORING plan §7.3 — the verbose witness surface. These assert the render, not
// just the derivation (memory: verify render logic before claiming what shows).
function selectedWithClaims(claims, principals = []) {
  return {
    name: "withdrawEther",
    contractName: "EtherFiRestaker",
    contractAddress: "0xcontract",
    lane: "right",
    signature: "withdrawEther(uint256)",
    action: "moves value out (fixed destination)",
    claims,
    guard: guardSummary({ function: "withdrawEther(uint256)", authority_public: false }, {}),
    principals,
    indirectPrincipals: [],
    authorityPublic: false,
  };
}

describe("InspectorCard witnessed-facts block", () => {
  it("renders destination + amount rows from the flow.out lattice witness", () => {
    const claims = [{
      claim_id: "flow.out",
      tier: "standard_exact",
      witness: {
        kind: "value_flow",
        direction: "out",
        flows: [{
          kind: "low_level_value_call",
          target_kind: { kind: "immutable", tier: "dispositive_ast" },
          amount_kind: { kind: "whole_balance", tier: "static_trace" },
        }],
        sink_ids: [],
      },
    }];
    const { container } = render(<InspectorCard selected={selectedWithClaims(claims)} />);
    const text = container.textContent;
    expect(text).toContain("Witnessed facts");
    expect(text).toContain("immutable address · dispositive AST");
    expect(text).toContain("the whole balance · static trace");
  });

  it("names every resolved destination when the folded kind is a site disagreement", () => {
    const claims = [{
      claim_id: "flow.out",
      tier: "standard_exact",
      witness: {
        kind: "value_flow",
        direction: "out",
        flows: [{
          kind: "low_level_value_call",
          target_kind: { kind: "indeterminate", tier: "static_trace" },
          target_kinds: [
            { kind: "token_owner", tier: "static_trace" },
            { kind: "immutable", tier: "static_trace" },
          ],
        }],
        sink_ids: [],
      },
    }];
    const { container } = render(<InspectorCard selected={selectedWithClaims(claims)} />);
    const text = container.textContent;
    expect(text).toContain("2 sites: the token's current owner · static trace / immutable address · static trace");
  });

  it("renders nothing extra when a function carries no witnessed facts", () => {
    const claims = [{ claim_id: "flow.out", tier: "standard_exact", witness: {} }];
    const { container } = render(<InspectorCard selected={selectedWithClaims(claims)} />);
    expect(container.textContent).not.toContain("Witnessed facts");
  });
});

describe("InspectorCard principal terminal + signer notes", () => {
  const safeTerminal = { resolved_type: "safe", terminal: true, threshold: 4, owners: ["0xa", "0xb", "0xc", "0xd", "0xe", "0xf", "0xg"] };

  function contractPrincipal(details) {
    return { address: "0x7b57ad1a", resolvedType: "contract", details, origins: ["controller"], label: null };
  }

  it("flags a bare contract way-point without implying a settled key", () => {
    const p = contractPrincipal({ terminal: false });
    const { container } = render(<InspectorCard selected={selectedWithClaims([], [p])} />);
    expect(container.textContent).toContain("ultimate key unresolved");
  });

  it("shows the terminated ultimate key when the walk resolved it", () => {
    const p = contractPrincipal({
      terminal: false,
      terminal_principal: { terminal: true, resolved_type: "safe", address: "0x2aca7102", status: "terminated" },
    });
    const { container } = render(<InspectorCard selected={selectedWithClaims([], [p])} />);
    expect(container.textContent).toContain("ultimate key:");
    expect(container.textContent).toContain("safe");
  });

  it("shows multiple planes for ambiguous controllers, never a single key", () => {
    const p = contractPrincipal({
      terminal: false,
      terminal_principal: { terminal: false, resolved_type: "unknown", address: null, status: "ambiguous_controllers", controllers: ["0x1", "0x2"] },
    });
    const { container } = render(<InspectorCard selected={selectedWithClaims([], [p])} />);
    expect(container.textContent).toContain("parallel control planes witnessed");
  });

  it("renders each plane's own terminal outcome for a multi_plane controller", () => {
    const p = contractPrincipal({
      terminal: false,
      terminal_principal: {
        terminal: false, resolved_type: "unknown", address: null, status: "multi_plane",
        controllers: ["0xaaa", "0xbbb"],
        planes: [
          { controller: "0xaaa", terminal_record: { terminal: true, resolved_type: "safe", address: "0xsafe1234", status: "terminated" } },
          { controller: "0xbbb", terminal_record: { terminal: false, resolved_type: "unknown", address: null, status: "unknown_unfetched" } },
        ],
      },
    });
    const { container } = render(<InspectorCard selected={selectedWithClaims([], [p])} />);
    const text = container.textContent;
    expect(text).toContain("no single settled key");
    expect(text).toContain("ultimate key"); // the resolved plane
    expect(text).toContain("unresolved (unknown_unfetched)"); // the weakest plane
    // Never a single top-level "ultimate key: 0x…" settled-key line.
    expect(text).not.toContain("ultimate key:");
  });

  it("renders the shared-deployer HINT with its heuristic hedge, never as control", () => {
    const p = {
      address: "0xself",
      resolvedType: "contract",
      details: {
        terminal: false,
        shared_deployer: { provenance: "deployer_read", heuristic: true, deployer: "0xdep", addresses: ["0xself", "0xaaa", "0xbbb"] },
      },
      origins: ["controller"],
      label: null,
    };
    const { container } = render(<InspectorCard selected={selectedWithClaims([], [p])} />);
    const text = container.textContent;
    expect(text).toContain("shares a deployer with 2 other addresses");
    expect(text).toContain("heuristic — not proof of common control");
  });

  it("omits the shared-deployer hint when the fact is absent", () => {
    const p = contractPrincipal({ terminal: false });
    const { container } = render(<InspectorCard selected={selectedWithClaims([], [p])} />);
    expect(container.textContent).not.toContain("shares a deployer");
  });

  it("renders the signer-overlap fact for a Safe principal", () => {
    const p = {
      address: "0x4279",
      resolvedType: "safe",
      details: {
        ...safeTerminal,
        signer_overlap: {
          provenance: "onchain_owner_read",
          self_owner_count: 5,
          overlaps: [{ address: "0x2aca7102", other_owner_count: 7, shared_count: 5, shared_owners: [], subset: true, superset: false, equal: false, jaccard: 0.71 }],
        },
      },
      origins: ["role 1"],
      label: null,
    };
    const { container } = render(<InspectorCard selected={selectedWithClaims([], [p])} />);
    expect(container.textContent).toContain("signers all also sign");
  });
});
