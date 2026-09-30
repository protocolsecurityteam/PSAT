// One-shot initializer state from the `one_shot` condition's `latch_state`:
//
// "consumed" — latch set; inert despite projecting public.
// "live" — latch unset on a confirmed proxy; anyone can call it once.
// undefined — unread or unconfirmed; treated as a plain open.

export function oneShotState(fn) {
  const conditions = Array.isArray(fn?.conditions) ? fn.conditions : [];
  let seen = null;
  for (const condition of conditions) {
    if (!condition || condition.kind !== "one_shot") continue;
    const state = condition.latch_state;
    if (state === "live") return "live";
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
