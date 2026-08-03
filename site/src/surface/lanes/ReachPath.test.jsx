import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ReachPath } from "./ReachPath.jsx";

const QUEUE = "0x7c12c550fe8857380b8f5a9e55d9145a0d7a7198";
const SOLVER = "0x989468982b08aefa46e37cd0086142a86fa466d7";
const TELLER = "0xa55a34d31af7e1bddface2966d51526eccf4f76e";
const VAULT = "0xeda663610638e6557c27e2f4e973d3393e844e70";

// The real etherfi row-0 route, hop for hop.
const PATH = {
  host: QUEUE,
  hostName: "AtomicQueue",
  hostNames: ["AtomicQueue"],
  hops: [
    {
      from: QUEUE,
      to: SOLVER,
      fromName: "AtomicQueue",
      toName: "AtomicSolverV3",
      type: "principal",
      claims: [{ relation: "role_principal", label: "roles 77" }],
    },
    {
      from: SOLVER,
      to: TELLER,
      fromName: "AtomicSolverV3",
      toName: "TellerWithMultiAssetSupport",
      type: "principal",
      claims: [{ relation: "role_principal", label: "roles 12" }],
    },
    {
      from: TELLER,
      to: VAULT,
      fromName: "TellerWithMultiAssetSupport",
      toName: "BoringVault",
      type: "controller",
      claims: [
        { relation: "controller_value", label: "hook" },
        { relation: "role_principal", label: "roles 2,3" },
      ],
    },
  ],
};

describe("ReachPath", () => {
  it("names the host the reach started at", () => {
    const { container } = render(<ReachPath reachPath={PATH} />);
    expect(container.querySelector(".ps-reach-hdr").textContent).toBe("Reached from AtomicQueue via:");
  });

  it("renders one row per hop, in walk order", () => {
    const { container } = render(<ReachPath reachPath={PATH} />);
    const hops = [...container.querySelectorAll(".ps-reach-hop")];
    expect(hops).toHaveLength(3);
    expect(hops.map((h) => h.querySelector(".ps-reach-pair").textContent)).toEqual([
      "AtomicQueue→AtomicSolverV3",
      "AtomicSolverV3→TellerWithMultiAssetSupport",
      "TellerWithMultiAssetSupport→BoringVault",
    ]);
  });

  it("names each hop with its flow type and every witnessed role label", () => {
    const { container } = render(<ReachPath reachPath={PATH} />);
    const kinds = [...container.querySelectorAll(".ps-reach-kind")].map((k) => k.textContent);
    expect(kinds[0]).toBe("principal · role_principal roles 77");
    expect(kinds[1]).toBe("principal · role_principal roles 12");
    // Both claims on the pair, neither dropped for the other.
    expect(kinds[2]).toContain(" · controller_value hook");
    expect(kinds[2]).toContain(" · role_principal roles 2,3");
  });

  it("shows an unwitnessed hop as its flow type alone", () => {
    const bare = {
      ...PATH,
      hops: [{ ...PATH.hops[0], claims: [] }],
    };
    const { container } = render(<ReachPath reachPath={bare} />);
    expect(container.querySelector(".ps-reach-kind").textContent).toBe("principal");
    expect(container.querySelector(".ps-reach-claim")).toBeNull();
  });

  it("says the path is not carried rather than drawing one", () => {
    render(<ReachPath reachPath={{ host: null, hostName: null, hostNames: ["AtomicQueue"], hops: null }} />);
    expect(screen.getByText("path not carried by this graph")).toBeInTheDocument();
    expect(document.querySelector(".ps-reach-hops")).toBeNull();
    // The origin is still named — the click DID come from somewhere.
    expect(document.querySelector(".ps-reach-hdr").textContent).toBe("Reached from AtomicQueue via:");
  });

  it("renders nothing at all without a route", () => {
    const { container } = render(<ReachPath reachPath={null} />);
    expect(container.innerHTML).toBe("");
  });
});
