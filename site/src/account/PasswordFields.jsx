import { useState } from "react";

// Mirrors services/auth/passwords.MIN_PASSWORD_LENGTH; the server enforces it.
export const MIN_PASSWORD_LENGTH = 10;

// New-password + confirm pair. `onSubmit(password)` runs only once both match
// and meet the minimum, so callers don't repeat the checks.
export function NewPasswordForm({ submitLabel, onSubmit, extraFields = null }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setError(null);
    if (password.length < MIN_PASSWORD_LENGTH) {
      setError(`Use at least ${MIN_PASSWORD_LENGTH} characters.`);
      return;
    }
    if (password !== confirm) {
      setError("The passwords don't match.");
      return;
    }
    setBusy(true);
    try {
      await onSubmit(password);
      setPassword("");
      setConfirm("");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="account-password-form" onSubmit={submit}>
      {extraFields}
      <input
        type="password"
        autoComplete="new-password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder={`New password (${MIN_PASSWORD_LENGTH}+ characters)`}
        aria-label="New password"
        required
      />
      <input
        type="password"
        autoComplete="new-password"
        value={confirm}
        onChange={(e) => setConfirm(e.target.value)}
        placeholder="Confirm new password"
        aria-label="Confirm new password"
        required
      />
      <button type="submit" className="btn" disabled={busy}>{busy ? "Saving…" : submitLabel}</button>
      {error && <p className="account-error" role="alert">{error}</p>}
    </form>
  );
}
