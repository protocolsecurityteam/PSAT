import fs from "node:fs";
import path from "node:path";

import { expect, test } from "@playwright/test";

function proof(id, kind, scope, proposition, evidence = [], prerequisites = []) {
  return { claim: { id, kind, scope, proposition }, evidence, prerequisites };
}

const impact = {
  company: "etherfi",
  data_origin: "synthetic_fixture",
  changes: [
    {
      job_id: "job-1",
      run_name: "ProtocolTimelock",
      context_id: "context:proposal-42",
      step: 1,
      subject: "0x1111111111111111111111111111111111111111",
      parameter: "minimum_delay",
      before: "172800",
      after: "21600",
      unit: "seconds",
      claim_id: "claim:scenario-delay",
      evidence: ["evidence:fork-execution"],
      prerequisites: ["claim:observed-delay"],
      baseline: { block_number: "22400000", block_hash: "0x" + "10".repeat(32) },
      actions: [{ kind: "call" }],
      assumptions: [],
      downstream: [{ id: "claim:authority", kind: "function_authority", proposition: { function: "execute()" }, scope: { kind: "scenario", step: 1 } }],
      proof: proof(
        "claim:scenario-delay",
        "configuration",
        { kind: "scenario", step: 1 },
        { parameter: "minimum_delay", value: "21600" },
        [{ id: "evidence:fork-execution", kind: "execution", block_number: null, source: { environment: "fork" } }],
        [{ id: "claim:observed-delay", kind: "configuration", scope: { kind: "point", at: { block_number: "22400000" } }, proposition: { parameter: "minimum_delay", value: "172800" } }],
      ),
    },
    {
      job_id: "job-2",
      run_name: "Governor",
      context_id: "context:proposal-42",
      step: 2,
      subject: "0x2222222222222222222222222222222222222222",
      parameter: "proposal_threshold",
      before: "1000000000000000000000",
      after: "250000000000000000000",
      unit: "count",
      claim_id: "claim:scenario-threshold",
      evidence: ["evidence:fork-execution-2"],
      prerequisites: ["claim:observed-threshold"],
      baseline: { block_number: "22400000", block_hash: "0x" + "10".repeat(32) },
      actions: [{ kind: "call" }, { kind: "call" }],
      assumptions: [],
      downstream: [],
      proof: proof("claim:scenario-threshold", "configuration", { kind: "scenario", step: 2 }, { parameter: "proposal_threshold", value: "250000000000000000000" }),
    },
  ],
  proposals: [
    {
      claim_id: "claim:proposal-state",
      run_name: "Governor",
      subject: "42",
      kind: "proposal_state",
      proposition: { kind: "proposal_state", state: "active" },
      scope: { kind: "point", at: { block_number: "22400000" } },
      evidence: ["evidence:state"],
      prerequisites: [],
      proof: proof("claim:proposal-state", "proposal_state", { kind: "point", at: { block_number: "22400000" } }, { state: "active" }),
    },
    {
      claim_id: "claim:proposal-deadline",
      run_name: "Governor",
      subject: "42",
      kind: "proposal_timing",
      proposition: { kind: "proposal_timing", field: "deadline", value: "22445818", clock: "block_number" },
      scope: { kind: "point", at: { block_number: "22400000" } },
      evidence: ["evidence:deadline"],
      prerequisites: [],
      proof: proof("claim:proposal-deadline", "proposal_timing", { kind: "point", at: { block_number: "22400000" } }, { field: "deadline", value: "22445818" }),
    },
  ],
  limitations: [
    { job_id: "job-3", code: "unsupported_clock", message: "Custom governor clock semantics were not assessed." },
  ],
};

async function installRoutes(page) {
  await page.route("**/api/analyses", (route) => route.fulfill({ json: [] }));
  await page.route("**/api/company/etherfi/proposal-impact", (route) => route.fulfill({ json: impact }));
}

test("proposal impact separates scenarios, observed facts, and limitations", async ({ page }) => {
  await installRoutes(page);
  await page.goto("/company/etherfi/proposals");
  await expect(page.getByRole("heading", { name: "Proposal impact" })).toBeVisible();
  await expect(page.getByText("21600 seconds")).toBeVisible();
  await expect(page.locator(".proposal-section").nth(1).locator(".proposal-scope.observed").first()).toBeVisible();
  await expect(page.getByRole("heading", { name: "Coverage limitations" })).toBeVisible();
  await page.getByText("Inspect proof").first().click();
  await expect(page.getByText("claim:scenario-delay")).toBeVisible();

  if (process.env.IMPECCABLE_CAPTURE === "1") {
    const review = path.resolve("..", ".impeccable", "review");
    fs.mkdirSync(review, { recursive: true });
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.screenshot({ path: path.join(review, "desktop.png"), fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: path.join(review, "mobile.png"), fullPage: true });
  }
});
