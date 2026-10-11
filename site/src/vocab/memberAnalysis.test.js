import { describe, expect, it } from "vitest";

import { memberAnalysisNote } from "./memberAnalysis.js";

describe("memberAnalysisNote", () => {
  it("counts unread members by token and keeps unknown tokens raw", () => {
    const note = memberAnalysisNote({
      member_analysis: {
        members: 9,
        analyzed: 6,
        not_determined: 3,
        by_state: { analysis_not_completed: 1, analysis_failed: 1, analysis_brand_new: 1 },
      },
    });
    expect(note).toEqual({
      members: 9,
      notDetermined: 3,
      states: [
        { token: "analysis_brand_new", word: "analysis_brand_new", count: 1 },
        { token: "analysis_failed", word: "analysis failed", count: 1 },
        { token: "analysis_not_completed", word: "analysis not completed", count: 1 },
      ],
    });
  });

  it("is null when every member is analyzed or the block is absent", () => {
    expect(
      memberAnalysisNote({
        member_analysis: { members: 2, analyzed: 2, not_determined: 0, by_state: { analysis_failed: 0 } },
      }),
    ).toBeNull();
    expect(memberAnalysisNote({})).toBeNull();
    expect(memberAnalysisNote(null)).toBeNull();
  });
});
