import { useState } from "react";

import { maskWebhook, shortAddr } from "../../format.js";
import { MONITOR_ALERT_GROUPS } from "../../meta.js";
import { groupKeysFromConfig } from "./helpers.js";

export function MonitorAlertEditor({
  sessionKey,
  subscriptions,
  initialMachine,
  initialContract,
  saving,
  onMinimize,
  onClose,
  onSave,
}) {
  const address = initialMachine?.address || initialContract?.address || "";
  const initialGroups = initialContract
    ? groupKeysFromConfig(initialContract.monitoring_config)
    : ["upgrades", "ownership", "pause"];
  const [groupKeys, setGroupKeys] = useState(initialGroups.length ? initialGroups : ["upgrades"]);
  const [webhookMode, setWebhookMode] = useState(subscriptions.length ? "existing" : "new");
  const [webhookUrl, setWebhookUrl] = useState("");
  const [webhookLabel, setWebhookLabel] = useState("");

  function toggleGroup(key) {
    setGroupKeys((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next.size ? [...next] : [key];
    });
  }

  const selectedContract = initialContract || null;
  const selectedMachine = initialMachine || null;
  const contractLabel = selectedMachine?.name || shortAddr(address);
  const targetChainId = selectedContract?.chain_id ?? selectedMachine?.chain_id ?? null;

  return (
    <div className="ps-monitor-editor" role="dialog" aria-modal="false">
      <form
        className="ps-monitor-editor-form"
        onSubmit={(event) => {
          event.preventDefault();
          onSave({
            key: sessionKey,
            address,
            chain_id: targetChainId,
            groupKeys,
            webhookMode,
            webhookUrl,
            webhookLabel,
          });
        }}
      >
        <div className="ps-monitor-modal-header">
          <div>
            <div className="ps-monitor-title">{initialContract ? "Edit alert" : "Add alert"}</div>
            <div className="ps-monitor-subtitle">{contractLabel}</div>
          </div>
          <div className="ps-monitor-modal-header-actions">
            <button type="button" className="ps-monitor-icon-btn" onClick={onMinimize} aria-label="Minimize alert editor">-</button>
            <button type="button" className="ps-modal-close" onClick={onClose}>×</button>
          </div>
        </div>

        <div className="ps-monitor-target-card">
          <span>{contractLabel}</span>
          <strong title={address}>{shortAddr(address)}</strong>
        </div>

        <div className="ps-monitor-field">
          <span>Watch</span>
          <div className="ps-monitor-alert-grid">
            {MONITOR_ALERT_GROUPS.map((group) => {
              const selected = groupKeys.includes(group.key);
              return (
                <button
                  key={group.key}
                  type="button"
                  className={`ps-monitor-alert-choice${selected ? " active" : ""}`}
                  onClick={() => toggleGroup(group.key)}
                >
                  {group.label}
                </button>
              );
            })}
          </div>
        </div>

        <div className="ps-monitor-field">
          <span>Webhook</span>
          <div className="ps-monitor-webhook-choice">
            {subscriptions.length ? (
              <button
                type="button"
                className={`ps-monitor-alert-choice${webhookMode === "existing" ? " active" : ""}`}
                onClick={() => setWebhookMode("existing")}
              >
                Existing ({subscriptions.length})
              </button>
            ) : null}
            <button
              type="button"
              className={`ps-monitor-alert-choice${webhookMode === "new" ? " active" : ""}`}
              onClick={() => setWebhookMode("new")}
            >
              New webhook
            </button>
          </div>
          {webhookMode === "new" ? (
            <>
              <input
                className="ps-monitor-input"
                value={webhookUrl}
                onChange={(event) => setWebhookUrl(event.target.value)}
                placeholder="Discord webhook URL"
              />
              <input
                className="ps-monitor-input"
                value={webhookLabel}
                onChange={(event) => setWebhookLabel(event.target.value)}
                placeholder="Label"
              />
            </>
          ) : (
            <div className="ps-monitor-selected-webhooks">
              {subscriptions.map((sub) => (
                <span key={sub.id} className="ps-monitor-chip">
                  {sub.label || maskWebhook(sub.discord_webhook_url)}
                </span>
              ))}
            </div>
          )}
        </div>

        <div className="ps-monitor-modal-actions">
          <button type="button" className="ps-monitor-btn" onClick={onClose}>Cancel</button>
          <button
            type="submit"
            className="ps-monitor-btn ps-monitor-btn-primary"
            disabled={saving || !address}
          >
            {saving ? "Saving" : "Save alert"}
          </button>
        </div>
      </form>
    </div>
  );
}
