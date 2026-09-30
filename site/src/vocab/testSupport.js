// Payload builders for the vocab tests.

export function claim(claim_id, tier = "standard_exact") {
  return { claim_id, tier, witness: {} };
}

const FREE = { state: "unconstrained_proven" };

export function flowOut(
  targetKind,
  { amountKind = null, tier = "standard_exact", targetKinds = null, amountKinds = null, constraint } = {},
) {
  const flow = { kind: "low_level_value_call", selector: null, from_is_self: true };
  if (targetKind) flow.target_kind = targetKind;
  // Mirrors the producer (`flows.py:_flow_entry`): only scalar params get a
  // verdict, never a `several` fold.
  const scalarParam = targetKind?.kind === "param";
  const foldParam = Array.isArray(targetKinds) && targetKinds.some((k) => k?.kind === "param");
  const verdict = constraint === undefined ? (scalarParam ? FREE : null) : constraint;
  if ((scalarParam || foldParam) && verdict) flow.target_constraint = verdict;
  if (amountKind) flow.amount_kind = amountKind;
  if (targetKinds) flow.target_kinds = targetKinds;
  if (amountKinds) flow.amount_kinds = amountKinds;
  return {
    claim_id: "flow.out",
    tier,
    witness: { kind: "value_flow", direction: "out", flows: [flow], sink_ids: [] },
  };
}

export function observedClaim(claim_id, observed) {
  return {
    claim_id,
    tier: "behavioral_observed",
    witness: { effect_verdict_id: 1, effect_class: "x", observed },
  };
}
