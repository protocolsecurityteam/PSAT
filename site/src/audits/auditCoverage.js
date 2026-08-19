export function isBytecodeVerifiedAudit(audit) {
  const status = String(audit?.equivalence_status || "").toLowerCase();
  const matchType = String(audit?.match_type || "").toLowerCase();
  const proofKind = String(audit?.proof_kind || "").toLowerCase();

  return (
    status === "proven" &&
    matchType === "reviewed_commit" &&
    proofKind !== "cited_only" &&
    audit?.bytecode_drift !== true
  );
}

export function bytecodeVerifiedAudits(audits) {
  return Array.isArray(audits) ? audits.filter(isBytecodeVerifiedAudit) : [];
}
