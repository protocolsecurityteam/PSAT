import { useEffect, useSyncExternalStore } from "react";

import { api } from "./client.js";

// One /api/me read shared by every consumer; `refreshSession()` after sign-in
// or sign-out re-reads it. "unknown" until the first read settles so gated UI
// doesn't flash a sign-in prompt at a signed-in user.
let state = { status: "unknown", user: null };
let inflight = null;
const listeners = new Set();

function emit(next) {
  state = next;
  for (const fn of listeners) fn();
}

export function refreshSession() {
  inflight ??= api("/api/me", { silent: true })
    .then((user) => emit(user?.email ? { status: "signed_in", user } : { status: "signed_out", user: null }))
    .catch(() => emit({ status: "signed_out", user: null }))
    .finally(() => { inflight = null; });
  return inflight;
}

export async function signOut() {
  try {
    await api("/api/auth/logout", { method: "POST", silent: true });
  } finally {
    await refreshSession();
  }
}

// Any component may ask for sign-in (e.g. "Sign in to get alerts"); App owns
// the modal.
export function requestSignIn() {
  window.dispatchEvent(new Event("psat:auth-required"));
}

function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function useSession() {
  const snapshot = useSyncExternalStore(subscribe, () => state, () => state);
  useEffect(() => {
    if (state.status === "unknown") refreshSession();
  }, []);
  return snapshot;
}

// Test-only: module state otherwise leaks between vitest cases.
export function resetSessionForTests() {
  state = { status: "unknown", user: null };
  inflight = null;
}
