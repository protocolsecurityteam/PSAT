import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";

import ProposalImpactPage from "./ProposalImpactPage.jsx";
import { api } from "../api/client.js";

vi.mock("../api/client.js", () => ({ api: vi.fn() }));

beforeEach(() => api.mockReset());

it("shows transitive prerequisite payload and incomplete proof reason", async () => {
  api.mockResolvedValue({
    data_origin: "canonical_assessment", changes: [], limitations: [],
    proposals: [{
      job_id: "job-1", claim_id: "root", subject: "0xabc", kind: "proposal_state", proposition: { state: "queued" },
      scope: { kind: "point", at: { block_number: "100" } },
      proof: {
        claim: { id: "root", scope: { kind: "point", at: { block_number: "100" } }, proposition: { state: "queued" } },
        evidence: [], complete: false, issues: ["Prerequisite absent is unavailable or correction-ineligible"],
        prerequisites: [{
          id: "middle", kind: "applied_configuration", scope: { kind: "point", at: { block_number: "90" } },
          proposition: { phase: "schedule" }, evidence: [], prerequisites: [{
            id: "leaf", kind: "configuration", scope: { kind: "point", at: { block_number: "80" } },
            proposition: { value: "172800" }, prerequisites: [{ id: "absent", unavailable: "not eligible in publication" }],
            evidence: [{ id: "reading", kind: "chain_read", source: { method: "getMinDelay" }, block_number: "80", payload: { id: "payload:one", data: { value: "172800" } } }],
          }],
        }],
      },
    }],
  });
  const { container } = render(<ProposalImpactPage companyName="example" />);
  await screen.findByText("Observed proposal record");
  fireEvent.click(screen.getByText("Inspect proof"));
  expect(screen.getByText("Proof incomplete")).toBeInTheDocument();
  expect(screen.getByText(/correction-ineligible/)).toBeInTheDocument();
  expect(container.querySelectorAll(".proposal-proof-item")).toHaveLength(3);
  expect(screen.getByText("getMinDelay")).toBeInTheDocument();
  expect(screen.getAllByText("172800").length).toBeGreaterThan(0);
  expect(screen.getByRole("link", { name: "Download exact payload" }).getAttribute("href"))
    .toBe("/api/analyses/job-1/assessment-payload/payload%3Aone");
});

it("queues a scenario with the admin API body", async () => {
  const proposalId = (2n ** 200n + 7n).toString();
  api.mockImplementation((path) => path === "/api/analyze"
    ? Promise.resolve({ job_id: "job-1" })
    : Promise.resolve({ data_origin: "canonical_assessment", changes: [], proposals: [], limitations: [] }));
  render(<ProposalImpactPage companyName="example" />);
  await screen.findByText("Evaluate a proposal");
  fireEvent.change(screen.getByLabelText("Governor address"), { target: { value: `0x${"a".repeat(40)}` } });
  fireEvent.change(screen.getByLabelText("Proposal ID"), { target: { value: proposalId } });
  fireEvent.change(screen.getByLabelText("ProposalCreated transaction hash"), { target: { value: `0x${"b".repeat(64)}` } });
  fireEvent.change(screen.getByLabelText("Execution sender"), { target: { value: `0x${"c".repeat(40)}` } });
  fireEvent.click(screen.getByText("Evaluate scenario"));
  await waitFor(() => expect(api).toHaveBeenCalledWith("/api/analyze", expect.objectContaining({ method: "POST" })));
  const body = JSON.parse(api.mock.calls.find(([path]) => path === "/api/analyze")[1].body);
  expect(body.scenario_proposal_id).toBe(proposalId);
  expect(body.company).toBe("example");
  expect(body.scenario_sender).toBe(`0x${"c".repeat(40)}`);
  expect(await screen.findByText(/job-1/)).toBeInTheDocument();
});
