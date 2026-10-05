import { useCallback, useEffect, useState } from "react";

import { api } from "../api/client.js";
import { refreshSession, requestSignIn, signOut, useSession } from "../api/session.js";
import { NewPasswordForm } from "./PasswordFields.jsx";

function WebhookRow({ hook, onChanged }) {
  const [status, setStatus] = useState(null);

  async function sendTest() {
    setStatus("sending…");
    try {
      const res = await api(`/api/me/webhooks/${hook.id}/test`, { method: "POST" });
      setStatus(res?.delivered ? "delivered ✓" : "Discord rejected it");
    } catch (err) {
      setStatus(err.message);
    }
  }

  async function remove() {
    if (!window.confirm("Delete this webhook? Its subscriptions are removed too.")) return;
    await api(`/api/me/webhooks/${hook.id}`, { method: "DELETE" }).catch(() => null);
    onChanged();
  }

  return (
    <li className="account-row">
      <div className="account-row-main">
        <span className="account-row-title">{hook.label || "Discord webhook"}</span>
        <span className="account-row-sub tag-mono">{hook.discord_webhook_url}</span>
      </div>
      <div className="account-row-actions">
        {status && <span className="muted account-row-status">{status}</span>}
        <button type="button" className="ghost" onClick={sendTest}>Send test</button>
        <button type="button" className="ghost" onClick={remove}>Delete</button>
      </div>
    </li>
  );
}

export function AddWebhookForm({ onSaved, compact = false }) {
  const [url, setUrl] = useState("");
  const [label, setLabel] = useState("");
  const [error, setError] = useState(null);
  const [saving, setSaving] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setSaving(true);
    setError(null);
    try {
      const hook = await api("/api/me/webhooks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ discord_webhook_url: url.trim(), label: label.trim() || null }),
      });
      setUrl("");
      setLabel("");
      onSaved(hook);
    } catch (err) {
      setError(err.status === 422 ? "That isn't a Discord webhook URL (https://discord.com/api/webhooks/…)." : err.message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <form className={`account-inline-form${compact ? " compact" : ""}`} onSubmit={submit}>
      <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="Discord webhook URL" aria-label="Discord webhook URL" required />
      <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Label (optional)" aria-label="Webhook label" />
      <button type="submit" className="btn" disabled={saving || !url.trim()}>{saving ? "Saving…" : "Save webhook"}</button>
      {error && <p className="account-error" role="alert">{error}</p>}
    </form>
  );
}

function PasswordSection({ hasPassword }) {
  const [current, setCurrent] = useState("");
  const [saved, setSaved] = useState(false);

  async function save(password) {
    setSaved(false);
    await api("/api/me/password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ current_password: hasPassword ? current : null, new_password: password }),
      silent: true,
    });
    setCurrent("");
    setSaved(true);
    await refreshSession();
  }

  return (
    <section className="panel account-section">
      <h2>Password</h2>
      <p className="muted">
        {hasPassword
          ? "Changing it signs you out everywhere else."
          : "Add a password to also sign in with your email address."}
      </p>
      <NewPasswordForm
        submitLabel={hasPassword ? "Change password" : "Add password"}
        onSubmit={save}
        extraFields={hasPassword ? (
          <input
            type="password"
            autoComplete="current-password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            placeholder="Current password"
            aria-label="Current password"
            required
          />
        ) : null}
      />
      {saved && <p className="muted" role="status">Password saved.</p>}
    </section>
  );
}

export default function AccountPage({ onOpenCompany }) {
  const { status, user } = useSession();
  const [webhooks, setWebhooks] = useState([]);
  const [subscriptions, setSubscriptions] = useState([]);
  const authError = new URLSearchParams(window.location.search).get("auth_error");

  const load = useCallback(async () => {
    const [hooks, subs] = await Promise.all([
      api("/api/me/webhooks", { silent: true }).catch(() => []),
      api("/api/me/subscriptions", { silent: true }).catch(() => []),
    ]);
    setWebhooks(Array.isArray(hooks) ? hooks : []);
    setSubscriptions(Array.isArray(subs) ? subs : []);
  }, []);

  useEffect(() => {
    if (status === "signed_in") load();
  }, [status, load]);

  async function unsubscribe(sub) {
    await api(`/api/me/subscriptions/${sub.id}`, { method: "DELETE" }).catch(() => null);
    load();
  }

  if (status === "unknown") return <main className="page account-page"><p className="muted">Loading…</p></main>;

  if (status === "signed_out") {
    return (
      <main className="page account-page">
        <p className="eyebrow">Account</p>
        <h1>Sign in to manage alerts</h1>
        {authError && <p className="account-error" role="alert">{authError}</p>}
        <p className="lede">Save Discord webhooks to your account, then subscribe them to any protocol from its Activity panel.</p>
        <button type="button" className="btn" onClick={requestSignIn}>Sign in</button>
      </main>
    );
  }

  const hookLabel = new Map(webhooks.map((h) => [h.id, h.label || h.discord_webhook_url]));

  return (
    <main className="page account-page">
      <header className="account-header">
        {user.avatar_url && <img className="account-avatar" src={user.avatar_url} alt="" />}
        <div>
          <p className="eyebrow">Account{user.is_admin ? " · admin" : ""}</p>
          <h1>{user.display_name || user.email}</h1>
          <p className="muted">{user.email}</p>
        </div>
        <button type="button" className="ghost account-signout" onClick={signOut}>Sign out</button>
      </header>

      <section className="panel account-section">
        <h2>Discord webhooks</h2>
        {webhooks.length ? (
          <ul className="account-list">
            {webhooks.map((h) => <WebhookRow key={h.id} hook={h} onChanged={load} />)}
          </ul>
        ) : (
          <p className="muted">No webhooks yet. In Discord: Channel settings → Integrations → Webhooks → Copy URL.</p>
        )}
        <AddWebhookForm onSaved={load} />
      </section>

      <section className="panel account-section">
        <h2>Protocol alerts</h2>
        {subscriptions.length ? (
          <ul className="account-list">
            {subscriptions.map((s) => (
              <li key={s.id} className="account-row">
                <div className="account-row-main">
                  <button type="button" className="account-link-btn account-row-title" onClick={() => onOpenCompany?.(s.protocol_name)}>
                    {s.protocol_name}
                  </button>
                  <span className="account-row-sub">
                    → {hookLabel.get(s.webhook_id) || "webhook"}
                    {s.event_filter?.event_types ? ` · ${s.event_filter.event_types.length} event types` : " · all events"}
                  </span>
                </div>
                <div className="account-row-actions">
                  <button type="button" className="ghost" onClick={() => unsubscribe(s)}>Unsubscribe</button>
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted">Not subscribed to any protocol. Open a protocol&apos;s surface, select a contract, and use Alerts → Subscribe.</p>
        )}
      </section>

      <PasswordSection hasPassword={Boolean(user.has_password)} />
    </main>
  );
}
