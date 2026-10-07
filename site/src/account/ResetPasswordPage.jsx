import { useEffect, useState } from "react";

import { neonAuth } from "../api/neonAuth.js";
import { requestSignIn } from "../api/session.js";
import { NewPasswordForm } from "./PasswordFields.jsx";

// Landing page for the emailed reset link: Neon Auth sends the browser here
// with ?token=… (or ?error=INVALID_TOKEN once the link is used or expired).
export default function ResetPasswordPage() {
  const [{ token, linkError }] = useState(() => {
    const params = new URLSearchParams(window.location.search);
    return { token: params.get("token") || "", linkError: params.get("error") };
  });
  const [done, setDone] = useState(false);

  // Keep the single-use token out of history and shared screenshots once read.
  useEffect(() => {
    if (token || linkError) window.history.replaceState(window.history.state, "", "/reset-password");
  }, [token, linkError]);

  async function save(newPassword) {
    await neonAuth((c) => c.resetPassword({ newPassword, token }));
    setDone(true);
  }

  let body;
  if (done) {
    body = (
      <>
        <p className="muted" role="status">Password updated. Sign in with your new password.</p>
        <button type="button" className="btn" onClick={requestSignIn}>Sign in</button>
      </>
    );
  } else if (!token || linkError) {
    body = (
      <>
        <p className="account-error" role="alert">This link is invalid or has expired. Request a new one.</p>
        <button type="button" className="btn" onClick={requestSignIn}>Sign in or request a link</button>
      </>
    );
  } else {
    body = <NewPasswordForm submitLabel="Set password" onSubmit={save} />;
  }

  return (
    <main className="page account-page account-narrow">
      <p className="eyebrow">Account</p>
      <h1>Choose a new password</h1>
      {body}
    </main>
  );
}
