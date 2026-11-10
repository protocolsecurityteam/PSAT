import { describe, expect, it } from "vitest";

import { analysisProvenanceLine, inventoryAnalysisChip, provenanceDate } from "./analysisProvenance.js";

const PASS = "2026-11-03T14:02:00+00:00";
const job = (over = {}) => ({
  job_id: "0f1e2d3c-aaaa-bbbb-cccc-000000000001",
  state: "current_analyzer",
  static_analyzer_version: 12,
  static_reused_from_job_id: null,
  started_at: "2026-11-03T13:00:00+00:00",
  last_pipeline_pass_at: PASS,
  ...over,
});
const ND_JOB = job({
  state: "not_determined",
  static_analyzer_version: "not_determined",
  static_reused_from_job_id: "not_determined",
  started_at: "not_determined",
  last_pipeline_pass_at: "not_determined",
});
const line = (j, impl = null) => analysisProvenanceLine({ analysis_provenance: { job: j, impl_job: impl } });
const date = provenanceDate(PASS);

describe("analysisProvenanceLine", () => {
  it("names the analyzer version and the last pipeline pass, never an analysis time", () => {
    const out = line(job());
    expect(out.text).toBe(`analyzer v12 · last pipeline pass ${date}`);
    expect(out.text).not.toMatch(/analyzed at/i);
    expect(out.title).toContain("job 0f1e2d3c-aaaa-bbbb-cccc-000000000001");
    expect(out.title).toContain("started ");
  });

  it("names the donor job when the static stage was reused", () => {
    const out = line(job({ static_reused_from_job_id: "99887766-0000-0000-0000-000000000000" }));
    expect(out.text).toBe(`analyzer v12 · reused from job 99887766 · last pipeline pass ${date}`);
    expect(out.title).toContain("static analysis reused from job 99887766-0000-0000-0000-000000000000");
  });

  it("flags an older analyzer", () => {
    expect(line(job({ state: "older_analyzer", static_analyzer_version: 11 })).text).toBe(
      `older analyzer v11 · last pipeline pass ${date}`,
    );
  });

  it("keeps not_determined fields visible", () => {
    expect(line(ND_JOB).text).toBe("analysis provenance not determined");
    expect(line(job({ state: "not_determined", static_analyzer_version: "not_determined" })).text).toBe(
      `analyzer version not determined · analyzer state not determined · last pipeline pass ${date}`,
    );
    expect(line(job({ last_pipeline_pass_at: "not_determined" })).text).toBe(
      "analyzer v12 · last pipeline pass not determined",
    );
    expect(line(job({ static_reused_from_job_id: "not_determined" })).text).toContain("static reuse not determined");
  });

  it("renders an unknown state token raw", () => {
    expect(line(job({ state: "newer_analyzer" })).text).toBe(`analyzer v12 · newer_analyzer · last pipeline pass ${date}`);
  });

  it("appends the implementation's job compactly for a proxy", () => {
    const out = line(job(), job({ job_id: "impl-job", static_analyzer_version: 11, state: "older_analyzer" }));
    expect(out.text).toBe(`analyzer v12 · last pipeline pass ${date} · impl: older analyzer v11 · last pass ${date}`);
    expect(out.title).toContain("implementation job impl-job");
    expect(line(job(), ND_JOB).text).toBe(`analyzer v12 · last pipeline pass ${date} · impl: not determined`);
  });

  it("is null without provenance", () => {
    expect(analysisProvenanceLine({})).toBeNull();
    expect(analysisProvenanceLine({ analysis_provenance: { job: null, impl_job: null } })).toBeNull();
  });
});

describe("inventoryAnalysisChip", () => {
  it("words each analysis_state token", () => {
    expect(inventoryAnalysisChip({ analysis_state: "current_analyzer" })).toMatchObject({ text: "analyzed", tone: "ok" });
    expect(inventoryAnalysisChip({ analysis_state: "older_analyzer", stale_analysis_version: 11 })).toEqual({
      text: "analyzed · older analyzer",
      tone: "ok",
      title: "static analyzer v11",
    });
    expect(inventoryAnalysisChip({ analysis_state: "analysis_failed" })).toMatchObject({ text: "analysis failed", tone: "err" });
    expect(inventoryAnalysisChip({ analysis_state: "analysis_not_completed" })).toMatchObject({ text: "discovered", tone: "pending" });
  });

  it("renders an unknown token raw", () => {
    expect(inventoryAnalysisChip({ analysis_state: "analysis_queued" })).toMatchObject({ text: "analysis_queued", tone: "pending" });
  });

  it("falls back to the analyzed flag on a row with no state", () => {
    expect(inventoryAnalysisChip({ analyzed: true }).text).toBe("analyzed");
    expect(inventoryAnalysisChip({ analyzed: false }).text).toBe("discovered");
  });
});
