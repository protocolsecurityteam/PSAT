export default function HamburgerMenu({ onClose, viewMode, companyName, companyTab, onNavigate, onNavigateCompanyTab }) {
  return (
    <>
      <div className="hamburger-backdrop" onClick={onClose} />
      <aside className="hamburger-drawer">
        <div className="hamburger-header">
          <span className="hamburger-brand">PSAT</span>
          <button className="hamburger-close" onClick={onClose}>&times;</button>
        </div>
        <nav className="hamburger-nav">
          <div className="hamburger-section-label">Navigation</div>
          <button className={`hamburger-link ${viewMode === "default" ? "active" : ""}`} onClick={() => { onNavigate("/", "default"); onClose(); }}>Runs</button>
          <button className={`hamburger-link ${viewMode === "monitor" ? "active" : ""}`} onClick={() => { onNavigate("/monitor", "monitor"); onClose(); }}>Monitor</button>
        </nav>
        {companyName && (
          <nav className="hamburger-nav hamburger-company-section">
            <div className="hamburger-section-label">{companyName}</div>
            <button className={`hamburger-link ${viewMode === "company" && companyTab === "overview" ? "active" : ""}`} onClick={() => { onNavigateCompanyTab("overview"); onClose(); }}>Overview</button>
            <button className={`hamburger-link ${viewMode === "company" && companyTab === "surface" ? "active" : ""}`} onClick={() => { onNavigateCompanyTab("surface"); onClose(); }}>Surface</button>
            <button className={`hamburger-link ${viewMode === "company" && companyTab === "graph" ? "active" : ""}`} onClick={() => { onNavigateCompanyTab("graph"); onClose(); }}>Ownership</button>
            <button className={`hamburger-link ${viewMode === "company" && companyTab === "risk" ? "active" : ""}`} onClick={() => { onNavigateCompanyTab("risk"); onClose(); }}>Risk Matrix</button>
            <button className={`hamburger-link ${viewMode === "company" && companyTab === "audits" ? "active" : ""}`} onClick={() => { onNavigateCompanyTab("audits"); onClose(); }}>Audits</button>
            <button className={`hamburger-link ${viewMode === "company" && companyTab === "monitoring" ? "active" : ""}`} onClick={() => { onNavigateCompanyTab("monitoring"); onClose(); }}>Monitoring</button>
          </nav>
        )}
      </aside>
    </>
  );
}
