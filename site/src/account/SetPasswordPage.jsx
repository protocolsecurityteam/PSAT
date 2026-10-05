import { useEffect, useState } from "react";

import { api } from "../api/client.js";
import { refreshSession, requestSignIn } from "../api/session.js";
import { NewPasswordForm } from "./PasswordFields.jsx";

// Landing page for the emailed sign-up / reset link (/set-password?token=…).
export default function SetPasswordPage({ onDone }) {
  const [token] = useState(() => new URLSearchParams(window.location.search).get("token") || "");

  // Keep the single-use token out of history and shared screenshots once read.
  useEffect(() => {
    if (token) window.history.replaceState(window.history.state, "", "/set-password");
  }, [token]);

  async function save(password) {
    await api("/api/auth/password/set", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, password }),
      silent: true,
    });
    await refreshSession();
    onDone?.();
  }

  return (
    <main className="page account-page account-narrow">
      <p className="eyebrow">Account</p>
      <h1>Choose a password</h1>
      {token ? (
        <>
          <p className="muted">This also confirms your email address and signs you in.</p>
          <NewPasswordForm submitLabel="Set password" onSubmit={save} />
        </>
      ) : (
        <>
          <p className="account-error" role="alert">This link is missing its token. Request a new one.</p>
          <button type="button" className="btn" onClick={requestSignIn}>Sign in or request a link</button>
        </>
      )}
    </main>
  );
}
