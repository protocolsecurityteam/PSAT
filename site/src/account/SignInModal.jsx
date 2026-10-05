import { useEffect, useState } from "react";

import { api, setAdminKey } from "../api/client.js";
import { refreshSession } from "../api/session.js";
import { Modal, ModalTitle } from "../shared/Modal.jsx";

function returnPath() {
  return window.location.pathname + window.location.search;
}

function postJson(path, body) {
  return api(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    silent: true,
  });
}

// "signin" → email+password; "register" / "forgot" → email only, then "sent".
// Sign-up never takes a password: the emailed link is where it's chosen.
function PasswordForms({ onSignedIn }) {
  const [mode, setMode] = useState("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (mode === "signin") {
        await postJson("/api/auth/password/login", { email: email.trim(), password });
        await refreshSession();
        onSignedIn();
        return;
      }
      await postJson(mode === "register" ? "/api/auth/register" : "/api/auth/password/forgot", { email: email.trim() });
      setMode("sent");
    } catch (err) {
      setError(err.status === 422 ? "Enter a valid email address." : err.message);
    } finally {
      setBusy(false);
    }
  }

  function switchTo(next) {
    setMode(next);
    setError(null);
  }

  if (mode === "sent") {
    return (
      <div className="account-password-sent" role="status">
        <p>Check <strong>{email.trim()}</strong> for a link to set your password. It may take a minute to arrive.</p>
        <button type="button" className="account-link-btn" onClick={() => switchTo("signin")}>Back to sign in</button>
      </div>
    );
  }

  const label = { signin: "Sign in", register: "Email me a sign-up link", forgot: "Email me a reset link" }[mode];
  return (
    <form className="account-password-form" onSubmit={submit}>
      <input
        type="email"
        autoComplete="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="you@example.com"
        aria-label="Email"
        required
      />
      {mode === "signin" && (
        <input
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Password"
          aria-label="Password"
          required
        />
      )}
      <button type="submit" className="btn" disabled={busy}>{busy ? "…" : label}</button>
      {error && <p className="account-error" role="alert">{error}</p>}
      <div className="account-password-links">
        {mode === "signin" ? (
          <>
            <button type="button" className="account-link-btn" onClick={() => switchTo("register")}>Create an account</button>
            <button type="button" className="account-link-btn" onClick={() => switchTo("forgot")}>Forgot password?</button>
          </>
        ) : (
          <button type="button" className="account-link-btn" onClick={() => switchTo("signin")}>I have a password</button>
        )}
      </div>
    </form>
  );
}

export default function SignInModal({ onClose }) {
  const [config, setConfig] = useState(null);
  const [devEmail, setDevEmail] = useState("");
  const [error, setError] = useState(null);

  useEffect(() => {
    api("/api/auth/providers", { silent: true })
      .then((data) => setConfig({
        providers: data?.providers || [],
        devLogin: Boolean(data?.dev_login),
        password: Boolean(data?.password),
      }))
      .catch(() => setConfig({ providers: [], devLogin: false, password: false }));
  }, []);

  async function devSignIn(event) {
    event.preventDefault();
    setError(null);
    try {
      await postJson("/api/auth/dev-login", { email: devEmail.trim() });
      await refreshSession();
      onClose();
    } catch (err) {
      setError(err.message);
    }
  }

  function enterAdminKey() {
    const entered = window.prompt("Paste your PSAT admin key:");
    if (entered) {
      setAdminKey(entered);
      onClose();
    }
  }

  const next = encodeURIComponent(returnPath());
  const nothingConfigured = config && !config.providers.length && !config.devLogin && !config.password;
  return (
    <Modal className="ps-audit-modal--read account-signin" onClose={onClose} portal header={<ModalTitle eyebrow="Account">Sign in</ModalTitle>}>
      <div className="account-signin-body">
        <p className="muted">Sign in to save Discord webhooks and get alerts when a protocol&apos;s control surface changes.</p>
        {config === null && <p className="muted">Loading…</p>}
        {config?.providers.length > 0 && (
          <div className="account-signin-providers">
            {config.providers.map((p) => (
              <a key={p.name} className="btn account-provider-btn" href={`/api/auth/${p.name}/login?next=${next}`}>
                Continue with {p.label}
              </a>
            ))}
          </div>
        )}
        {config?.providers.length > 0 && config.password && <div className="account-divider"><span>or</span></div>}
        {config?.password && <PasswordForms onSignedIn={onClose} />}
        {nothingConfigured && <p className="muted">Sign-in isn&apos;t configured on this server.</p>}
        {config?.devLogin && (
          <form className="account-inline-form" onSubmit={devSignIn}>
            <input
              type="email"
              value={devEmail}
              onChange={(e) => setDevEmail(e.target.value)}
              placeholder="you@example.com"
              aria-label="Dev login email"
              required
            />
            <button type="submit" className="ghost">Dev sign-in</button>
          </form>
        )}
        {error && <p className="account-error" role="alert">{error}</p>}
        <button type="button" className="account-link-btn" onClick={enterAdminKey}>Use an admin key instead</button>
      </div>
    </Modal>
  );
}
