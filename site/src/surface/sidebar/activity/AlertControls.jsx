import { useEffect, useState } from "react";

import { api } from "../../../api/client.js";
import { requestSignIn, useSession } from "../../../api/session.js";
import { maskWebhook } from "../../format.js";
import { MONITOR_ALERT_GROUPS } from "../../meta.js";
import {
  eventTypesFromGroupKeys,
  groupKeysFromConfig,
  subscriptionEventTypeSet,
} from "./helpers.js";

// A webhook with no filter matches everything.
function matchingSubscriptions(groupKeys, subscriptions) {
  const eventTypes = eventTypesFromGroupKeys(groupKeys).map((t) => t.toLowerCase());
  return (subscriptions || []).filter((sub) => {
    const allowed = subscriptionEventTypeSet(sub);
    if (!allowed) return true;
    return eventTypes.some((t) => allowed.has(t));
  });
}

const NEW_WEBHOOK = "__new__";

// Signed-in users pick one of their saved webhooks (or save a new one inline).
function AccountWebhookForm({ saving, onSubscribe, onCancel }) {
  const [webhooks, setWebhooks] = useState(null);
  const [choice, setChoice] = useState("");
  const [url, setUrl] = useState("");
  const [label, setLabel] = useState("");
  const [error, setError] = useState(null);

  useEffect(() => {
    api("/api/me/webhooks", { silent: true })
      .then((hooks) => {
        const list = Array.isArray(hooks) ? hooks : [];
        setWebhooks(list);
        setChoice(list[0]?.id || NEW_WEBHOOK);
      })
      .catch(() => { setWebhooks([]); setChoice(NEW_WEBHOOK); });
  }, []);

  async function submit(event) {
    event.preventDefault();
    setError(null);
    let webhookId = choice;
    if (choice === NEW_WEBHOOK) {
      try {
        const hook = await api("/api/me/webhooks", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ discord_webhook_url: url.trim(), label: label.trim() || null }),
        });
        webhookId = hook.id;
      } catch (err) {
        setError(err.status === 422 ? "Not a Discord webhook URL" : err.message);
        return;
      }
    }
    onSubscribe(webhookId);
  }

  if (webhooks === null) return <div className="ps-activity-webhook-row">loading webhooks…</div>;

  const creating = choice === NEW_WEBHOOK;
  return (
    <form className="ps-activity-webhook-form" onSubmit={submit}>
      <select
        className="ps-activity-webhook-input"
        value={choice}
        onChange={(e) => setChoice(e.target.value)}
        aria-label="Deliver to"
      >
        {webhooks.map((h) => (
          <option key={h.id} value={h.id}>{h.label || h.discord_webhook_url}</option>
        ))}
        <option value={NEW_WEBHOOK}>+ new Discord webhook…</option>
      </select>
      {creating && (
        <>
          <input
            className="ps-activity-webhook-input"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Discord webhook URL"
            aria-label="Discord webhook URL"
          />
          <input
            className="ps-activity-webhook-input"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="Label (optional)"
            aria-label="Webhook label"
          />
        </>
      )}
      {error && <div className="ps-activity-webhook-error" role="alert">{error}</div>}
      <div className="ps-activity-webhook-actions">
        <button type="submit" className="ps-activity-link-btn" disabled={saving || (creating && !url.trim())}>subscribe</button>
        <button type="button" className="ps-activity-link-btn" onClick={onCancel}>cancel</button>
      </div>
    </form>
  );
}

// Operators with only the shared admin key attach a raw URL to the protocol.
function AdminKeyWebhookForm({ saving, onAttach, onCancel }) {
  const [url, setUrl] = useState("");
  const [label, setLabel] = useState("");

  function submit(event) {
    event.preventDefault();
    if (!url.trim()) return;
    onAttach({ url: url.trim(), label: label.trim() || null });
  }

  return (
    <form className="ps-activity-webhook-form" onSubmit={submit}>
      <input
        className="ps-activity-webhook-input"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        placeholder="Discord webhook URL"
        aria-label="Discord webhook URL"
      />
      <input
        className="ps-activity-webhook-input"
        value={label}
        onChange={(e) => setLabel(e.target.value)}
        placeholder="Label (optional)"
        aria-label="Webhook label"
      />
      <div className="ps-activity-webhook-actions">
        <button type="submit" className="ps-activity-link-btn" disabled={saving || !url.trim()}>save</button>
        <button type="button" className="ps-activity-link-btn" onClick={onCancel}>cancel</button>
      </div>
    </form>
  );
}

// Read-only summary of what's watched (derived at enrollment from type and
// capabilities) plus where its alerts are delivered.
export function AlertControls({ contract, subscriptions, isAdmin, saving, onAttachWebhook }) {
  const { status } = useSession();
  const groupKeys = groupKeysFromConfig(contract?.monitoring_config || {});
  const watched = MONITOR_ALERT_GROUPS.filter((g) => groupKeys.includes(g.key));
  const matches = matchingSubscriptions(groupKeys, subscriptions);
  const [attaching, setAttaching] = useState(false);

  function attach(target) {
    onAttachWebhook(target, groupKeys);
    setAttaching(false);
  }

  const signedIn = status === "signed_in";
  let delivery;
  if (attaching && signedIn) {
    delivery = (
      <AccountWebhookForm saving={saving} onSubscribe={(webhookId) => attach({ webhookId })} onCancel={() => setAttaching(false)} />
    );
  } else if (attaching && isAdmin) {
    delivery = <AdminKeyWebhookForm saving={saving} onAttach={attach} onCancel={() => setAttaching(false)} />;
  } else if (signedIn || isAdmin) {
    delivery = (
      <div className="ps-activity-webhook-row">
        {matches.length ? (
          matches.map((sub) => (
            <span key={sub.id} className="tag tag-md tag-mono ps-activity-webhook-chip">
              {sub.label || sub.webhook_label || maskWebhook(sub.discord_webhook_url)}
            </span>
          ))
        ) : (
          <span className="tag tag-md tag-mono ps-activity-webhook-chip none">no webhook</span>
        )}
        <button type="button" className="ps-activity-link-btn" onClick={() => setAttaching(true)}>
          {matches.length ? "attach another" : "attach Discord"}
        </button>
      </div>
    );
  } else if (status === "signed_out") {
    delivery = (
      <div className="ps-activity-webhook-row">
        <button type="button" className="ps-activity-link-btn" onClick={requestSignIn}>sign in to get alerts</button>
      </div>
    );
  }

  return (
    <div className="ps-activity-watch">
      <div className="ps-activity-watch-top">
        <div className="ps-activity-sect-title">Alerts</div>
        <span className={`ps-activity-status${contract?.is_active ? " on" : ""}`}>
          {contract?.is_active ? "● watching" : "○ off"}
        </span>
      </div>

      <div className="ps-activity-watched">
        {watched.length ? (
          watched.map((g) => (
            <span key={g.key} className="ps-activity-watch-chip">{g.label}</span>
          ))
        ) : (
          <span className="ps-activity-watch-chip none">nothing watched</span>
        )}
      </div>

      {delivery ?? null}
    </div>
  );
}
