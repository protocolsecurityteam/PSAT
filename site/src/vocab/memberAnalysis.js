// Overview `member_analysis.by_state` tokens. An unlisted token renders raw,
// never as a guessed word.
const ANALYSIS_STATE_WORD = {
  analysis_failed: "analysis failed",
  analysis_not_completed: "analysis not completed",
};

// Member contracts with no completed analysis, which are not_determined rather
// than absent. Null when every member is analyzed or the block is missing.
// Shape: {members, notDetermined, states: [{token, word, count}]}.
export function memberAnalysisNote(companyData) {
  const block = companyData && companyData.member_analysis;
  if (!block || !(Number(block.not_determined) > 0)) return null;
  const states = Object.entries(block.by_state || {})
    .filter(([, count]) => Number(count) > 0)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([token, count]) => ({ token, word: ANALYSIS_STATE_WORD[token] || token, count: Number(count) }));
  return { members: Number(block.members), notDetermined: Number(block.not_determined), states };
}
