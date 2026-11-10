// Overview `member_analysis.by_state` tokens. An unlisted token renders raw,
// never as a guessed word.
const ANALYSIS_STATE_WORD = {
  analysis_failed: "analysis failed",
  analysis_not_completed: "analysis not completed",
};

// Member contracts with no completed analysis, which are not_determined rather
// than absent, and members analyzed only by an older analyzer, which count as
// analyzed but are flagged. Null when every member is analyzed by the current
// analyzer or the block is missing. Shape: {members, notDetermined,
// states: [{token, word, count}], olderAnalyzer, olderVersions}.
export function memberAnalysisNote(companyData) {
  const block = companyData && companyData.member_analysis;
  if (!block) return null;
  const older = Array.isArray(block.analyzed_at_older_version) ? block.analyzed_at_older_version : [];
  const notDetermined = Number(block.not_determined) > 0 ? Number(block.not_determined) : 0;
  if (!notDetermined && !older.length) return null;
  const states = Object.entries(block.by_state || {})
    .filter(([, count]) => Number(count) > 0)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([token, count]) => ({ token, word: ANALYSIS_STATE_WORD[token] || token, count: Number(count) }));
  const olderVersions = [...new Set(older.map((m) => m && m.stale_analysis_version).filter((v) => typeof v === "number"))]
    .sort((a, b) => b - a);
  return { members: Number(block.members), notDetermined, states, olderAnalyzer: older.length, olderVersions };
}
