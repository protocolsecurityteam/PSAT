// One-shot initializer disposition, shared by the guard renderer and the
// protocol score. A function whose capability carries a `one_shot` condition is
// an initializer-family one-shot; the resolver's on-chain latch read annotates
// that condition with `latch_state`:
//
//   "consumed" — the global latch is set; the function is INERT (nobody can
//                call it again), even though it projects as a public path.
//   "live"     — the latch is unset on a confirmed proxy; anyone can call it
//                once — a critical, currently-exploitable opening.
//   undefined  — unread / indeterminate (no reachable RPC, an unconfirmed
//                address, or a structural candidate the read couldn't confirm):
//                treat conservatively as a plain open, neither inert nor critical.
//
// Pure — no React. Reads the persisted `conditions` array the API serializes
// onto each effective function.

export function oneShotState(fn) {
  const conditions = Array.isArray(fn?.conditions) ? fn.conditions : [];
  let seen = null;
  for (const condition of conditions) {
    if (!condition || condition.kind !== "one_shot") continue;
    const state = condition.latch_state;
    if (state === "live") return "live"; // live dominates — most severe
    if (state === "consumed") seen = "consumed";
    else if (seen === null) seen = "indeterminate";
  }
  return seen;
}

export function isInertOneShot(fn) {
  return oneShotState(fn) === "consumed";
}

export function isLiveOneShot(fn) {
  return oneShotState(fn) === "live";
}
