import { useState } from "react";

import { maskWebhook } from "../../format.js";
import { MONITOR_ALERT_GROUPS } from "../../meta.js";
import {
  eventTypesFromGroupKeys,
  groupKeysFromConfig,
  subscriptionEventTypeSet,
} from "./helpers.js";

// Which protocol subscriptions would fire for this contract's watch config (a
// webhook with no event filter matches everything).
function matchingSubscriptions(groupKeys, subscriptions) {
  const eventTypes = eventTypesFromGroupKeys(groupKeys).map((t) => t.toLowerCase());
  return (subscriptions || []).filter((sub) => {
    const allowed = subscriptionEventTypeSet(sub);
    if (!allowed) return true;
    return eventTypes.some((t) => allowed.has(t));
  });
}

// Alerts: a READ-ONLY summary of what this contract is watched for + the Discord
// delivery target. The watch set is NOT user-editable — it's derived at
// enrollment from the contract's type and detected capabilities (a proxy watches
// upgrades, a safe watches signer/threshold changes, a pausable contract watches
// pause). Toggling flags for event kinds a contract can't emit would do nothing,
// so we show the enrolled set rather than pretend it's configurable. The one real
// operator control is the webhook — where alerts get delivered — gated on admin.
export function AlertControls({ contract, subscriptions, isAdmin, saving, onAttachWebhook }) {
  const groupKeys = groupKeysFromConfig(contract?.monitoring_config || {});
  const watched = MONITOR_ALERT_GROUPS.filter((g) => groupKeys.includes(g.key));
  const matches = matchingSubscriptions(groupKeys, subscriptions);

  const [attaching, setAttaching] = useState(false);
  const [url, setUrl] = useState("");
  const [label, setLabel] = useState("");

  function submitWebhook(event) {
    event.preventDefault();
    if (!url.trim()) return;
    onAttachWebhook(url.trim(), label.trim() || null, groupKeys);
    setUrl("");
    setLabel("");
    setAttaching(false);
  }

  return (
    <div className="ps-activity-watch">
      <div className="ps-activity-watch-top">
        <div className="ps-activity-sect-title">Alerts</div>
        <span className={`ps-activity-status${contract?.is_active ? " on" : ""}`}>
          {contract?.is_active ? "● watching" : "○ off"}
        </span>
      </div>

      {/* Read-only: what this contract is watched for, from its type + capabilities. */}
      <div className="ps-activity-watched">
        {watched.length ? (
          watched.map((g) => (
            <span key={g.key} className="ps-activity-watch-chip">{g.label}</span>
          ))
        ) : (
          <span className="ps-activity-watch-chip none">nothing watched</span>
        )}
      </div>

      {/* The one real operator control: where alerts are delivered. Admin-only. */}
      {isAdmin ? (
        attaching ? (
          <form className="ps-activity-webhook-form" onSubmit={submitWebhook}>
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
              <button type="button" className="ps-activity-link-btn" onClick={() => setAttaching(false)}>cancel</button>
            </div>
          </form>
        ) : (
          <div className="ps-activity-webhook-row">
            {matches.length ? (
              matches.map((sub) => (
                <span key={sub.id} className="ps-activity-webhook-chip">
                  {sub.label || maskWebhook(sub.discord_webhook_url)}
                </span>
              ))
            ) : (
              <span className="ps-activity-webhook-chip none">no webhook</span>
            )}
            <button type="button" className="ps-activity-link-btn" onClick={() => setAttaching(true)}>
              {matches.length ? "attach another" : "attach Discord"}
            </button>
          </div>
        )
      ) : null}
    </div>
  );
}
