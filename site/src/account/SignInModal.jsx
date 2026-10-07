import { useEffect, useState } from "react";

import { loadAuthConfig } from "../api/authConfig.js";
import { api, setAdminKey } from "../api/client.js";
import { establishSession, neonAuth, sitePath } from "../api/neonAuth.js";
import { refreshSession } from "../api/session.js";
import { Modal, ModalTitle } from "../shared/Modal.jsx";
import { MIN_PASSWORD_LENGTH } from "./PasswordFields.jsx";

const PROVIDER_LABELS = { github: "GitHub", google: "Google" };

// "signin" → email+password; "register" → name, email, password, then "verify";
// "forgot" → email, then "sent".
function PasswordForms({ onSignedIn }) {
  const [mode, setMode] = useState("signin");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    const address = email.trim();
    try {
      if (mode === "signin") {
        await neonAuth((c) => c.signIn.email({ email: address, password }));
        await establishSession();
        onSignedIn();
      } else if (mode === "register") {
        await neonAuth((c) => c.signUp.email({
          email: address,
          password,
          name: name.trim() || address.split("@")[0],
          callbackURL: sitePath("/account"),
        }));
        setMode("verify");
      } else {
        await neonAuth((c) => c.requestPasswordReset({ email: address, redirectTo: sitePath("/reset-password") }));
        setMode("sent");
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  function switchTo(next) {
    setMode(next);
    setError(null);
  }

  if (mode === "verify" || mode === "sent") {
    return (
      <div className="account-password-sent" role="status">
        <p>
          {mode === "verify"
            ? <>Check <strong>{email.trim()}</strong> to verify your address, then sign in.</>
            : <>If <strong>{email.trim()}</strong> has an account, a reset link is on its way.</>}
          {" "}It may take a minute to arrive.
        </p>
        <button type="button" className="account-link-btn" onClick={() => switchTo("signin")}>Back to sign in</button>
      </div>
    );
  }

  const label = { signin: "Sign in", register: "Create account", forgot: "Email me a reset link" }[mode];
  return (
    <form className="account-password-form" onSubmit={submit}>
      {mode === "register" && (
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Name (optional)" aria-label="Name" autoComplete="name" />
      )}
      <input
        type="email"
        autoComplete="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="you@example.com"
        aria-label="Email"
        required
      />
      {mode !== "forgot" && (
        <input
          type="password"
          autoComplete={mode === "register" ? "new-password" : "current-password"}
          minLength={mode === "register" ? MIN_PASSWORD_LENGTH : undefined}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder={mode === "register" ? `Password (${MIN_PASSWORD_LENGTH}+ characters)` : "Password"}
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
          <button type="button" className="account-link-btn" onClick={() => switchTo("signin")}>I have an account</button>
        )}
      </div>
    </form>
  );
}

export default function SignInModal({ onClose, initialError = null }) {
  const [config, setConfig] = useState(null);
  const [devEmail, setDevEmail] = useState("");
  const [error, setError] = useState(initialError);

  useEffect(() => {
    loadAuthConfig()
      .then((loaded) => setConfig({ ...loaded, providers: loaded.providers.filter((p) => PROVIDER_LABELS[p]) }))
      .catch(() => setConfig({ enabled: false, providers: [], devLogin: false, adminKey: false }));
  }, []);

  async function socialSignIn(provider) {
    setError(null);
    try {
      // Redirects away; Neon brings the browser back here with a verifier (see finishSocialSignIn).
      await neonAuth((c) => c.signIn.social({ provider, callbackURL: window.location.href }));
    } catch (err) {
      setError(err.message);
    }
  }

  async function devSignIn(event) {
    event.preventDefault();
    setError(null);
    try {
      await api("/api/auth/dev-login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: devEmail.trim() }),
        silent: true,
      });
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

  return (
    <Modal className="ps-audit-modal--read account-signin" onClose={onClose} portal header={<ModalTitle eyebrow="Account">Sign in</ModalTitle>}>
      <div className="account-signin-body">
        <p className="muted">Sign in to save Discord webhooks and get alerts when a protocol&apos;s control surface changes.</p>
        {config === null && <p className="muted">Loading…</p>}
        {config?.enabled && config.providers.length > 0 && (
          <div className="account-signin-providers">
            {config.providers.map((p) => (
              <button key={p} type="button" className="btn account-provider-btn" onClick={() => socialSignIn(p)}>
                Continue with {PROVIDER_LABELS[p]}
              </button>
            ))}
          </div>
        )}
        {config?.enabled && config.providers.length > 0 && <div className="account-divider"><span>or</span></div>}
        {config?.enabled && <PasswordForms onSignedIn={onClose} />}
        {config && !config.enabled && !config.devLogin && <p className="muted">Sign-in isn&apos;t configured on this server.</p>}
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
        {config?.adminKey && (
          <button type="button" className="account-link-btn" onClick={enterAdminKey}>Use an admin key instead</button>
        )}
      </div>
    </Modal>
  );
}
