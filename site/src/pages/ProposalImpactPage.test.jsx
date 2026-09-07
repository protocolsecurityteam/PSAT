import React from "react";
import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import ProposalImpactPage from "./ProposalImpactPage.jsx";
import { setFetchHandler } from "../test/fetchMock.js";

const DATA = {
  company: "etherfi",
  data_origin: "synthetic_fixture",
  changes: [
    {
      job_id: "job-1",
      run_name: "Timelock",
      context_id: "context:one",
      step: 1,
      subject: "0x1111111111111111111111111111111111111111",
      parameter: "minimum_delay",
      before: "172800",
      after: "21600",
      unit: "seconds",
      claim_id: "claim:scenario",
      evidence: ["evidence:fork"],
      prerequisites: ["claim:baseline"],
      baseline: { block_number: "100", block_hash: "0x" + "10".repeat(32) },
      actions: [{ kind: "call" }],
      assumptions: [],
      downstream: [],
      proof: { claim: { id: "claim:scenario", scope: { kind: "scenario", step: 1 }, proposition: { parameter: "minimum_delay", value: "21600" } }, evidence: [], prerequisites: [] },
    },
  ],
  proposals: [
    {
      claim_id: "claim:state",
      run_name: "Governor",
      subject: "7",
      kind: "proposal_state",
      proposition: { kind: "proposal_state", state: "active" },
      scope: { kind: "point", at: { block_number: "120" } },
      evidence: ["evidence:state"],
      prerequisites: [],
      proof: { claim: { id: "claim:state", scope: { kind: "point", at: { block_number: "120" } }, proposition: { state: "active" } }, evidence: [], prerequisites: [] },
    },
  ],
  limitations: [],
};

describe("ProposalImpactPage", () => {
  beforeEach(() => {
    setFetchHandler(
      (url) => url.pathname === "/api/company/etherfi/proposal-impact",
      () => DATA,
    );
  });

  it("separates hypothetical changes from observed proposal facts", async () => {
    render(<ProposalImpactPage companyName="etherfi" />);
    expect(await screen.findByRole("heading", { name: "Proposal impact" })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("21600 seconds")).toBeInTheDocument());
    expect(screen.getByText("172800 seconds")).toBeInTheDocument();
    expect(screen.getAllByText("Scenario · step 1").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Observed · block 120").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Inspect proof")).toHaveLength(2);
    expect(screen.getByText("Synthetic fixture data")).toBeInTheDocument();
  });

  it("never renders an empty result when the API state is unknown", async () => {
    setFetchHandler(
      (url) => url.pathname === "/api/company/etherfi/proposal-impact",
      () => { throw new Error("storage unavailable"); },
    );
    render(<ProposalImpactPage companyName="etherfi" />);
    expect(await screen.findByRole("alert")).toHaveTextContent("could not be loaded");
    expect(screen.queryByText("No scenario has been evaluated")).not.toBeInTheDocument();
  });
});
