import { shortAddr } from "../../format.js";
import { matchingWebhookCountForConfig } from "./helpers.js";
import { MonitorEventIcons, MonitorWebhookIndicator } from "./icons.jsx";

function identityKey(address, chainId) {
  const addr = String(address || "").toLowerCase();
  const parsedChainId = Number.parseInt(chainId, 10);
  if (!addr || !Number.isInteger(parsedChainId) || parsedChainId <= 0) return null;
  return `${parsedChainId}:${addr}`;
}

export function AlertsTable({
  alerts,
  machineByIdentity,
  subscriptions,
  busyId,
  emptyLabel = "No active alerts.",
  onEdit,
  onSetActive,
}) {
  if (!alerts.length) {
    return <div className="ps-inspector-empty">{emptyLabel}</div>;
  }

  return (
    <div className="ps-monitor-alert-table">
      {alerts.map((contract) => {
        const machine = machineByIdentity.get(identityKey(contract.address, contract.chain_id));
        const webhookCount = matchingWebhookCountForConfig(contract.monitoring_config || {}, subscriptions);
        return (
          <div
            key={contract.id}
            className={`ps-monitor-table-row${contract.is_active ? "" : " inactive"}`}
            role="button"
            tabIndex={0}
            title={contract.address}
            onClick={() => onEdit(contract)}
            onKeyDown={(event) => {
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                onEdit(contract);
              }
            }}
          >
            <div className="ps-monitor-table-main">
              <div className="ps-monitor-table-name">{machine?.name || shortAddr(contract.address)}</div>
              <div className="ps-monitor-table-addr">{contract.address}</div>
            </div>
            <MonitorEventIcons config={contract.monitoring_config || {}} />
            <MonitorWebhookIndicator count={webhookCount} />
            <button
              type="button"
              className={`ps-monitor-link ps-monitor-status-toggle${contract.is_active ? " active" : ""}`}
              disabled={busyId === contract.id}
              title={contract.is_active ? "Monitoring is on. Click to turn off." : "Monitoring is off. Click to turn on."}
              onClick={(event) => {
                event.stopPropagation();
                onSetActive(contract, !contract.is_active);
              }}
            >
              {contract.is_active ? "On" : "Off"}
            </button>
          </div>
        );
      })}
    </div>
  );
}
