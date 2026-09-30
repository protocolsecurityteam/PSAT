export function SidebarTabs({ mode, onSetMode, showDetail = true, isAdmin = false }) {
  return (
    <div className="ps-sidebar-tabs">
      {/* Opt-out prop for a future chrome-only sidebar. */}
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
        Audits
      </button>
      {/* Reading is public; write controls gate on isAdmin inside the panel. */}
      <button
        className={`ps-sidebar-tab ${mode === "activity" ? "active" : ""}`}
        onClick={() => onSetMode("activity")}
      >
        Activity
      </button>
    </div>
  );
}
