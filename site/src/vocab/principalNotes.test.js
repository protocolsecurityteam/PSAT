import { describe, it, expect } from "vitest";

import {
  sharedDeployerNote,
  signerOverlapNote,
  terminalControllerNote,
} from "./principalNotes.js";

describe("terminalControllerNote — non-terminal way-points never read as settled keys", () => {
  it("returns null for a principal that is itself a settled key", () => {
    expect(terminalControllerNote({ resolvedType: "safe", details: { terminal: true } })).toBeNull();
    expect(terminalControllerNote({ resolvedType: "eoa", details: { terminal: true } })).toBeNull();
  });

  it("flags a bare contract way-point (no terminal walk) as unresolved", () => {
    const note = terminalControllerNote({ resolvedType: "contract", details: { terminal: false } });
    expect(note).toEqual({ kind: "unresolved", status: "unknown_unfetched" });
  });

  it("surfaces a terminated walk's ultimate key", () => {
    const note = terminalControllerNote({
      resolvedType: "contract",
      details: {
        terminal: false,
        terminal_principal: { terminal: true, resolved_type: "safe", address: "0xabc", chain: ["0x1", "0xabc"], status: "terminated" },
      },
    });
    expect(note).toEqual({ kind: "terminated", address: "0xabc", resolvedType: "safe" });
  });

  it("shows multiple control planes for ambiguous_controllers, never one key", () => {
    const note = terminalControllerNote({
      resolvedType: "contract",
      details: {
        terminal: false,
        terminal_principal: { terminal: false, resolved_type: "unknown", address: null, status: "ambiguous_controllers", controllers: ["0x1", "0x2"] },
      },
    });
    expect(note.kind).toBe("ambiguous");
    expect(note.planes).toEqual(["0x1", "0x2"]);
  });

  it("renders each plane's own terminal outcome for a multi_plane walk, never one key", () => {
    const note = terminalControllerNote({
      resolvedType: "contract",
      details: {
        terminal: false,
        terminal_principal: {
          terminal: false,
          resolved_type: "unknown",
          address: null,
          status: "multi_plane",
          controllers: ["0x1", "0x2"],
          planes: [
            { controller: "0x1", terminal_record: { terminal: true, resolved_type: "safe", address: "0xsafe", status: "terminated" } },
            { controller: "0x2", terminal_record: { terminal: false, resolved_type: "unknown", address: null, status: "unknown_unfetched" } },
          ],
        },
      },
    });
    expect(note.kind).toBe("multi_plane");
    expect(note.planes).toEqual([
      { controller: "0x1", outcome: { resolved: true, address: "0xsafe", resolvedType: "safe" } },
      { controller: "0x2", outcome: { resolved: false, status: "unknown_unfetched" } },
    ]);
  });

  it("degrades a multi_plane record with no usable planes array to the flat ambiguous render", () => {
    const note = terminalControllerNote({
      resolvedType: "contract",
      details: {
        terminal: false,
        terminal_principal: {
          terminal: false, resolved_type: "unknown", address: null,
          status: "multi_plane", controllers: ["0x1", "0x2"],
        },
      },
    });
    expect(note.kind).toBe("ambiguous");
    expect(note.planes).toEqual(["0x1", "0x2"]);
  });

  it("renders a nested ambiguous_controllers fork as the flat 'no single settled key'", () => {
    const note = terminalControllerNote({
      resolvedType: "contract",
      details: {
        terminal: false,
        terminal_principal: { terminal: false, resolved_type: "unknown", address: null, status: "ambiguous_controllers", controllers: ["0x1", "0x2", "0x3"] },
      },
    });
    expect(note.kind).toBe("ambiguous");
    expect(note.planes).toEqual(["0x1", "0x2", "0x3"]);
  });

  it("treats cycle / depth_exceeded / unfetched as honestly unresolved", () => {
    for (const status of ["cycle", "depth_exceeded", "unknown_unfetched"]) {
      const note = terminalControllerNote({
        resolvedType: "contract",
        details: { terminal: false, terminal_principal: { terminal: false, resolved_type: "unknown", address: null, status } },
      });
      expect(note).toEqual({ kind: "unresolved", status });
    }
  });

  it("renders canonical-getter silence as unresolved with the true status carried", () => {
    // controllers_not_determined = the probes were silent, NOT "no controller
    // exists". The payload carries the basis (probes_silent / undetermined_at)
    // and the note must keep the state distinguishable, never fold it into a
    // settled key or a proven absence.
    const note = terminalControllerNote({
      resolvedType: "contract",
      details: {
        terminal: false,
        terminal_principal: {
          terminal: false,
          resolved_type: "unknown",
          address: null,
          status: "controllers_not_determined",
          probes_silent: ["owner", "authority", "admin"],
          undetermined_at: "0x" + "ec".repeat(20),
          chain: ["0x" + "dc".repeat(20), "0x" + "ec".repeat(20)],
        },
      },
    });
    expect(note).toEqual({ kind: "unresolved", status: "controllers_not_determined" });
  });

  it("keeps legacy persisted no_controller rows unresolved (never a settled key)", () => {
    const note = terminalControllerNote({
      resolvedType: "contract",
      details: {
        terminal: false,
        terminal_principal: { terminal: false, resolved_type: "unknown", address: null, status: "no_controller" },
      },
    });
    expect(note).toEqual({ kind: "unresolved", status: "no_controller" });
  });
});

describe("signerOverlapNote — attribution context, not org identity", () => {
  it("surfaces the strongest subset relation", () => {
    const principal = {
      resolvedType: "safe",
      details: {
        signer_overlap: {
          provenance: "onchain_owner_read",
          self_owner_count: 5,
          overlaps: [
            { address: "0x2aca", other_owner_count: 7, shared_count: 5, shared_owners: [], subset: true, superset: false, equal: false, jaccard: 0.71 },
            { address: "0xdead", other_owner_count: 3, shared_count: 1, shared_owners: [], subset: false, superset: false, equal: false, jaccard: 0.14 },
          ],
        },
      },
    };
    const note = signerOverlapNote(principal);
    expect(note.selfOwnerCount).toBe(5);
    expect(note.strongest.address).toBe("0x2aca");
    expect(note.strongest.subset).toBe(true);
  });

  it("emits null when the fact is absent or has no shared signers", () => {
    expect(signerOverlapNote({ resolvedType: "safe", details: {} })).toBeNull();
    const disjoint = {
      resolvedType: "safe",
      details: { signer_overlap: { self_owner_count: 3, overlaps: [{ address: "0x1", shared_count: 0, jaccard: 0 }] } },
    };
    expect(signerOverlapNote(disjoint)).toEqual({ selfOwnerCount: 3, strongest: null });
  });
});

describe("sharedDeployerNote — heuristic hint, never an org-identity claim", () => {
  it("counts the OTHER addresses in the deployer group and carries the heuristic hedge", () => {
    const note = sharedDeployerNote({
      address: "0xself",
      details: {
        shared_deployer: {
          provenance: "deployer_read", heuristic: true, deployer: "0xdep",
          addresses: ["0xself", "0xaaa", "0xbbb"],
        },
      },
    });
    expect(note).toEqual({ deployer: "0xdep", otherCount: 2, heuristic: true });
  });

  it("counts case-insensitively and excludes the principal itself", () => {
    const note = sharedDeployerNote({
      address: "0xSELF",
      details: { shared_deployer: { deployer: "0xdep", addresses: ["0xself", "0xaaa"] } },
    });
    expect(note.otherCount).toBe(1);
  });

  it("emits null when the fact is absent (no hint from absence)", () => {
    expect(sharedDeployerNote({ address: "0xself", details: {} })).toBeNull();
    expect(sharedDeployerNote({ details: {} })).toBeNull();
    expect(sharedDeployerNote({})).toBeNull();
  });

  it("emits null for a singleton group (no OTHER address to share with)", () => {
    const note = sharedDeployerNote({
      address: "0xself",
      details: { shared_deployer: { deployer: "0xdep", addresses: ["0xself"] } },
    });
    expect(note).toBeNull();
  });
});
