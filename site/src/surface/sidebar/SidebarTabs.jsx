export function SidebarTabs({ mode, onSetMode, auditCount, showDetail = true, isAdmin = false }) {
  return (
    <div className="ps-sidebar-tabs">
      {/* showDetail is on by default in both embedded and fullscreen
          modes — clicking a contract anywhere is expected to surface the
          function-lane view. Kept as an opt-out prop so a future caller
          that needs a chrome-only sidebar can still suppress the tab. */}
      {showDetail && (
        <button
          className={`ps-sidebar-tab ${mode === "detail" ? "active" : ""}`}
          onClick={() => onSetMode("detail")}
        >
          Detail
        </button>
      )}
      {isAdmin && (
        <button
          className={`ps-sidebar-tab ${mode === "agent" ? "active" : ""}`}
          onClick={() => onSetMode("agent")}
        >
          Agent
        </button>
      )}
      <button
        className={`ps-sidebar-tab ${mode === "audits" ? "active" : ""}`}
        onClick={() => onSetMode("audits")}
      >
        Audits{auditCount != null ? `(${auditCount})` : ""}
      </button>
      {isAdmin && (
        <button
          className={`ps-sidebar-tab ${mode === "monitoring" ? "active" : ""}`}
          onClick={() => onSetMode("monitoring")}
        >
          Monitor
        </button>
      )}
      <button
        className={`ps-sidebar-tab ${mode === "upgrades" ? "active" : ""}`}
        onClick={() => onSetMode("upgrades")}
      >
        Upgrades
      </button>
    </div>
  );
}
