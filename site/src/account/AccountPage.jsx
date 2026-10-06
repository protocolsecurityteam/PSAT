import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { api } from "../api/client.js";
import { refreshSession, requestSignIn, signOut, useSession } from "../api/session.js";
import { MONITOR_ALERT_GROUPS } from "../surface/meta.js";
import { eventTypesFromGroupKeys } from "../surface/sidebar/activity/helpers.js";
import { NewPasswordForm } from "./PasswordFields.jsx";

const TABS = [
  { key: "alerts", label: "Alerts" },
  { key: "webhooks", label: "Webhooks" },
  { key: "settings", label: "Settings" },
];
const NEW_WEBHOOK = "__new__";

function initialTab() {
  const tab = new URLSearchParams(window.location.search).get("tab");
  return TABS.some((t) => t.key === tab) ? tab : "alerts";
}

function rememberTab(tab) {
  const url = new URL(window.location.href);
  if (tab === "alerts") url.searchParams.delete("tab");
  else url.searchParams.set("tab", tab);
  window.history.replaceState(window.history.state, "", url);
}

function webhookError(err) {
  return err.status === 422 ? "That isn't a Discord webhook URL (https://discord.com/api/webhooks/…)." : err.message;
}

async function saveWebhook(url, label) {
  return api("/api/me/webhooks", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ discord_webhook_url: url.trim(), label: label.trim() || null }),
  });
}

// Subscriptions made here or from a contract's Alerts panel store the chosen groups; older ones only event types.
function subscriptionGroupLabels(sub) {
  const filter = sub.event_filter;
  if (!filter?.event_types?.length) return null;
  if (Array.isArray(filter.groups) && filter.groups.length) {
    return MONITOR_ALERT_GROUPS.filter((g) => filter.groups.includes(g.key)).map((g) => g.label);
  }
  const types = new Set(filter.event_types);
  return MONITOR_ALERT_GROUPS.filter((g) => g.eventTypes.some((t) => types.has(t))).map((g) => g.label);
}

// Only groups this protocol's monitored contracts actually watch, each with how many contracts enable it.
function availableGroups(protocol) {
  const watching = protocol?.watching || {};
  return MONITOR_ALERT_GROUPS
    .map((group) => ({
      group,
      contracts: Math.max(0, ...[...group.flags, ...(group.planKeys || [])].map((k) => watching[k] || 0)),
    }))
    .filter((g) => g.contracts > 0);
}

function WebhookHelp() {
  return (
    <details className="account-help">
      <summary>Where do I get a Discord webhook URL?</summary>
      <ol>
        <li>In Discord, open the channel&apos;s settings (the gear next to its name).</li>
        <li>Go to <strong>Integrations → Webhooks → New Webhook</strong>.</li>
        <li>Click <strong>Copy Webhook URL</strong> and paste it here.</li>
      </ol>
    </details>
  );
}

function AddAlertForm({ webhooks, existing, onAdded }) {
  const [protocols, setProtocols] = useState(null);
  const [protocolId, setProtocolId] = useState("");
  const [webhookId, setWebhookId] = useState(webhooks[0]?.id ?? NEW_WEBHOOK);
  const [newUrl, setNewUrl] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [groups, setGroups] = useState([]);
  const [error, setError] = useState(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api("/api/me/protocols", { silent: true })
      // A protocol can watch only things no alert group covers yet; offering it would leave nothing to pick.
      .then((rows) => setProtocols((Array.isArray(rows) ? rows : []).filter((p) => availableGroups(p).length)))
      .catch(() => setProtocols([]));
  }, []);

  // Webhooks usually arrive after mount; default to the first saved one unless the user already chose.
  const chose = useRef(false);
  // Runs on list changes only, so a just-saved webhook isn't reset before the refreshed list includes it.
  useEffect(() => {
    setWebhookId((current) => {
      const stale = current !== NEW_WEBHOOK && !webhooks.some((h) => h.id === current);
      if (stale || (!chose.current && current === NEW_WEBHOOK && webhooks.length)) return webhooks[0]?.id ?? NEW_WEBHOOK;
      return current;
    });
  }, [webhooks]);

  const protocol = (protocols || []).find((p) => String(p.id) === protocolId);
  const offered = availableGroups(protocol);
  const offeredKeys = offered.map((g) => g.group.key);
  const allSelected = offered.length > 0 && groups.length === offered.length;

  function chooseProtocol(id) {
    setProtocolId(id);
    setGroups(availableGroups((protocols || []).find((p) => String(p.id) === id)).map((g) => g.group.key));
  }

  const creatingWebhook = webhookId === NEW_WEBHOOK;
  const duplicate = !creatingWebhook && existing.some(
    (s) => String(s.protocol_id) === protocolId && s.webhook_id === webhookId,
  );

  function toggleGroup(key) {
    setGroups((current) => (current.includes(key) ? current.filter((k) => k !== key) : [...current, key]));
  }

  async function submit(event) {
    event.preventDefault();
    setSaving(true);
    setError(null);
    let savedWebhook = false;
    try {
      let targetId = webhookId;
      if (creatingWebhook) {
        try {
          targetId = (await saveWebhook(newUrl, newLabel)).id;
        } catch (err) {
          setError(webhookError(err));
          return;
        }
        savedWebhook = true;
        setNewUrl("");
        setNewLabel("");
        setWebhookId(targetId);
      }
      await api("/api/me/subscriptions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          protocol_id: Number(protocolId),
          webhook_id: targetId,
          event_filter: allSelected ? null : { event_types: eventTypesFromGroupKeys(groups), groups },
        }),
      });
      setProtocolId("");
      setGroups([]);
      onAdded();
    } catch (err) {
      setError(err.message);
      // The new webhook was saved even though the alert wasn't; list it so a retry can pick it.
      if (savedWebhook) onAdded();
    } finally {
      setSaving(false);
    }
  }

  const noProtocols = protocols !== null && protocols.length === 0;
  const canSubmit = protocolId && groups.length && (!creatingWebhook || newUrl.trim()) && !duplicate && !saving;

  return (
    <form className="panel account-card account-add-alert" onSubmit={submit}>
      <h2>Add an alert</h2>
      <div className="account-field-grid">
        <label className="account-field">
          <span>Protocol</span>
          <select value={protocolId} onChange={(e) => chooseProtocol(e.target.value)} disabled={!protocols?.length} required>
            <option value="">{protocols === null ? "Loading…" : noProtocols ? "No monitored protocols yet" : "Choose a protocol"}</option>
            {(protocols || []).map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} · {p.monitored_contracts} contract{p.monitored_contracts === 1 ? "" : "s"}
              </option>
            ))}
          </select>
        </label>
        <label className="account-field">
          <span>Send to</span>
          <select value={webhookId} onChange={(e) => { chose.current = true; setWebhookId(e.target.value); }}>
            {webhooks.map((h) => (
              <option key={h.id} value={h.id}>{h.label || h.discord_webhook_url}</option>
            ))}
            <option value={NEW_WEBHOOK}>+ New Discord webhook…</option>
          </select>
        </label>
      </div>

      {creatingWebhook && (
        <div className="account-field-grid">
          <label className="account-field">
            <span>Discord webhook URL</span>
            <input value={newUrl} onChange={(e) => setNewUrl(e.target.value)} placeholder="https://discord.com/api/webhooks/…" required />
          </label>
          <label className="account-field">
            <span>Name it (optional)</span>
            <input value={newLabel} onChange={(e) => setNewLabel(e.target.value)} placeholder="e.g. #security-alerts" />
          </label>
          <WebhookHelp />
        </div>
      )}

      {protocol && (
        <fieldset className="account-field account-groups">
          <legend>
            Notify me about
            {offered.length > 1 && (
              <button type="button" className="account-link-btn" onClick={() => setGroups(allSelected ? [] : offeredKeys)}>
                {allSelected ? "Clear" : "Select all"}
              </button>
            )}
          </legend>
          <div className="account-chips">
            {offered.map(({ group, contracts }) => (
              <label key={group.key} className={`account-chip${groups.includes(group.key) ? " on" : ""}`}>
                <input type="checkbox" checked={groups.includes(group.key)} onChange={() => toggleGroup(group.key)} />
                {group.label}
                <span className="account-chip-count">{contracts}</span>
              </label>
            ))}
          </div>
          <p className="muted account-groups-note">
            What {protocol.name}&apos;s monitored contracts watch; numbers are how many contracts each covers.
          </p>
        </fieldset>
      )}

      <div className="account-form-footer">
        {duplicate && <span className="muted">You already get this protocol&apos;s alerts on that webhook.</span>}
        {error && <span className="account-error" role="alert">{error}</span>}
        <button type="submit" className="btn" disabled={!canSubmit}>{saving ? "Adding…" : "Add alert"}</button>
      </div>
    </form>
  );
}

function AlertsTab({ subscriptions, webhooks, onChanged, onOpenCompany }) {
  const hookLabel = new Map(webhooks.map((h) => [h.id, h.label || "Discord webhook"]));

  async function remove(sub) {
    await api(`/api/me/subscriptions/${sub.id}`, { method: "DELETE" }).catch(() => null);
    onChanged();
  }

  return (
    <>
      <AddAlertForm webhooks={webhooks} existing={subscriptions} onAdded={onChanged} />
      <section className="panel account-card">
        <h2>Your alerts <span className="account-count">{subscriptions.length}</span></h2>
        {subscriptions.length ? (
          <ul className="account-list">
            {subscriptions.map((s) => {
              const labels = subscriptionGroupLabels(s);
              return (
                <li key={s.id} className="account-row">
                  <div className="account-row-main">
                    <button type="button" className="account-link-btn account-row-title" onClick={() => onOpenCompany?.(s.protocol_name)}>
                      {s.protocol_name}
                    </button>
                    <span className="account-row-sub">→ {hookLabel.get(s.webhook_id) || s.webhook_label || "webhook"}</span>
                    <div className="account-chips small">
                      {labels
                        ? labels.map((l) => <span key={l} className="account-chip on static">{l}</span>)
                        : <span className="account-chip on static">All events</span>}
                    </div>
                  </div>
                  <div className="account-row-actions">
                    <button type="button" className="ghost" onClick={() => remove(s)}>Remove</button>
                  </div>
                </li>
              );
            })}
          </ul>
        ) : (
          <p className="muted account-empty">No alerts yet. Pick a protocol above, or use Alerts on any contract in a protocol&apos;s surface.</p>
        )}
      </section>
    </>
  );
}

function WebhookRow({ hook, uses, onChanged }) {
  const [status, setStatus] = useState(null);

  async function sendTest() {
    setStatus("Sending…");
    try {
      const res = await api(`/api/me/webhooks/${hook.id}/test`, { method: "POST" });
      setStatus(res?.delivered ? "Delivered ✓" : "Discord rejected it");
    } catch (err) {
      setStatus(err.message);
    }
  }

  async function remove() {
    const warning = uses ? ` Its ${uses} alert${uses === 1 ? " is" : "s are"} removed too.` : "";
    if (!window.confirm(`Delete this webhook?${warning}`)) return;
    await api(`/api/me/webhooks/${hook.id}`, { method: "DELETE" }).catch(() => null);
    onChanged();
  }

  return (
    <li className="account-row">
      <div className="account-row-main">
        <span className="account-row-title">{hook.label || "Discord webhook"}</span>
        <span className="account-row-sub tag-mono">{hook.discord_webhook_url}</span>
        <span className="account-row-sub">{uses ? `${uses} alert${uses === 1 ? "" : "s"}` : "Not used by any alert"}</span>
      </div>
      <div className="account-row-actions">
        {status && <span className="muted account-row-status">{status}</span>}
        <button type="button" className="ghost" onClick={sendTest}>Send test</button>
        <button type="button" className="ghost" onClick={remove}>Delete</button>
      </div>
    </li>
  );
}

export function AddWebhookForm({ onSaved }) {
  const [url, setUrl] = useState("");
  const [label, setLabel] = useState("");
  const [error, setError] = useState(null);
  const [saving, setSaving] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setSaving(true);
    setError(null);
    try {
      const hook = await saveWebhook(url, label);
      setUrl("");
      setLabel("");
      onSaved(hook);
    } catch (err) {
      setError(webhookError(err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <form className="account-inline-form" onSubmit={submit}>
      <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="Discord webhook URL" aria-label="Discord webhook URL" required />
      <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Label (optional)" aria-label="Webhook label" />
      <button type="submit" className="btn" disabled={saving || !url.trim()}>{saving ? "Saving…" : "Save webhook"}</button>
      {error && <p className="account-error" role="alert">{error}</p>}
    </form>
  );
}

function WebhooksTab({ webhooks, subscriptions, onChanged }) {
  const uses = new Map();
  for (const s of subscriptions) uses.set(s.webhook_id, (uses.get(s.webhook_id) || 0) + 1);
  return (
    <section className="panel account-card">
      <h2>Discord webhooks <span className="account-count">{webhooks.length}</span></h2>
      <p className="muted">Each webhook posts into one Discord channel. Save one per channel you want alerts in.</p>
      {webhooks.length ? (
        <ul className="account-list">
          {webhooks.map((h) => <WebhookRow key={h.id} hook={h} uses={uses.get(h.id) || 0} onChanged={onChanged} />)}
        </ul>
      ) : null}
      <AddWebhookForm onSaved={onChanged} />
      <WebhookHelp />
    </section>
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
    <section className="panel account-card">
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

function SettingsTab({ user }) {
  return (
    <>
      <section className="panel account-card">
        <h2>Profile</h2>
        <dl className="account-facts">
          <dt>Email</dt>
          <dd>{user.email}</dd>
          {user.display_name && (<><dt>Name</dt><dd>{user.display_name}</dd></>)}
          <dt>Role</dt>
          <dd>{user.is_admin ? "Admin" : "Member"}</dd>
        </dl>
      </section>
      <PasswordSection hasPassword={Boolean(user.has_password)} />
      <section className="panel account-card">
        <h2>Sign out</h2>
        <p className="muted">Signs out this browser. Changing your password signs out every other device.</p>
        <button type="button" className="ghost account-signout" onClick={signOut}>Sign out</button>
      </section>
    </>
  );
}

export default function AccountPage({ onOpenCompany }) {
  const { status, user } = useSession();
  const [tab, setTab] = useState(initialTab);
  const [webhooks, setWebhooks] = useState([]);
  const [subscriptions, setSubscriptions] = useState([]);
  const authError = useMemo(() => new URLSearchParams(window.location.search).get("auth_error"), []);

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

  function selectTab(next) {
    setTab(next);
    rememberTab(next);
  }

  if (status === "unknown") return <main className="page account-page"><p className="muted">Loading…</p></main>;

  if (status === "signed_out") {
    return (
      <main className="page account-page">
        <p className="eyebrow">Account</p>
        <h1>Sign in to manage alerts</h1>
        {authError && <p className="account-error" role="alert">{authError}</p>}
        <p className="lede">Save Discord webhooks to your account and get alerts when a protocol&apos;s contracts are upgraded, paused, or change hands.</p>
        <button type="button" className="btn" onClick={requestSignIn}>Sign in</button>
      </main>
    );
  }

  const counts = { alerts: subscriptions.length, webhooks: webhooks.length };

  return (
    <main className="page account-page">
      <header className="account-header">
        {user.avatar_url
          ? <img className="account-avatar" src={user.avatar_url} alt="" referrerPolicy="no-referrer" />
          : <span className="account-avatar account-avatar-initial" aria-hidden="true">{(user.display_name || user.email)[0].toUpperCase()}</span>}
        <div>
          <p className="eyebrow">Account{user.is_admin ? " · admin" : ""}</p>
          <h1>{user.display_name || user.email}</h1>
          {user.display_name && <p className="muted">{user.email}</p>}
        </div>
      </header>

      <div className="account-tabs" role="tablist" aria-label="Account sections">
        {TABS.map((t) => (
          <button
            key={t.key}
            type="button"
            role="tab"
            id={`account-tab-${t.key}`}
            aria-selected={tab === t.key}
            aria-controls={`account-panel-${t.key}`}
            className={`account-tab${tab === t.key ? " active" : ""}`}
            onClick={() => selectTab(t.key)}
          >
            {t.label}
            {counts[t.key] ? <span className="account-count">{counts[t.key]}</span> : null}
          </button>
        ))}
      </div>

      <div className="account-panel" role="tabpanel" id={`account-panel-${tab}`} aria-labelledby={`account-tab-${tab}`}>
        {tab === "alerts" && (
          <AlertsTab subscriptions={subscriptions} webhooks={webhooks} onChanged={load} onOpenCompany={onOpenCompany} />
        )}
        {tab === "webhooks" && <WebhooksTab webhooks={webhooks} subscriptions={subscriptions} onChanged={load} />}
        {tab === "settings" && <SettingsTab user={user} />}
      </div>
    </main>
  );
}
