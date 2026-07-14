export function SidebarTabs({ mode, onSetMode, showDetail = true, isAdmin = false }) {
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
        Audits
      </button>
      {/* Activity folds the old Monitor + Upgrades tabs into one read-first
          timeline. Reading (timeline / state / protocol feed) is public; the
          write controls (alert toggles, webhook attach) gate on isAdmin
          inside the panel — so the tab itself is visible to everyone. */}
      <button
        className={`ps-sidebar-tab ${mode === "activity" ? "active" : ""}`}
        onClick={() => onSetMode("activity")}
      >
        Activity
      </button>
    </div>
  );
}
