import { api } from "./client.js";
import { refreshSession } from "./session.js";

// Neon Auth (managed Better Auth) through our same-origin proxy, so its cookies
// are first-party. After any sign-in, /api/auth/session turns the Neon session
// into ours; the rest of the app only ever sees `psat_session`.
export const VERIFIER_PARAM = "neon_auth_session_verifier";

let clientPromise = null;

// Lazy: the SDK only loads when someone actually signs in.
function authClient() {
  clientPromise ??= import("@neondatabase/auth").then(({ createAuthClient }) =>
    createAuthClient(`${window.location.origin}/api/auth/neon`));
  return clientPromise;
}

// Better Auth answers `{ data, error }` and the Neon wrapper can also throw;
// either way callers get one Error with a readable message.
export async function neonAuth(fn) {
  let result;
  try {
    result = await fn(await authClient());
  } catch (err) {
    throw Object.assign(new Error(err?.message || "Sign-in failed"), { code: err?.code, status: err?.status });
  }
  if (result?.error) {
    const { message, statusText, code, status } = result.error;
    throw Object.assign(new Error(message || statusText || "Sign-in failed"), { code, status });
  }
  return result?.data;
}

export async function establishSession(verifier = null) {
  const query = verifier ? `?${VERIFIER_PARAM}=${encodeURIComponent(verifier)}` : "";
  await api(`/api/auth/session${query}`, { method: "POST", silent: true });
  await refreshSession();
}

// GitHub/Google return to the page they started on with a one-time verifier.
// Returns an error message to show, or null.
export async function finishSocialSignIn() {
  const url = new URL(window.location.href);
  const verifier = url.searchParams.get(VERIFIER_PARAM);
  if (!verifier) return null;
  url.searchParams.delete(VERIFIER_PARAM);
  window.history.replaceState(window.history.state, "", url);
  try {
    await establishSession(verifier);
    return null;
  } catch (err) {
    return err.message || "Sign-in failed";
  }
}

export function sitePath(path) {
  return `${window.location.origin}${path}`;
}

// Test-only.
export function resetNeonAuthForTests() {
  clientPromise = null;
}
