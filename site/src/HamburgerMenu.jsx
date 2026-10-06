import { setAdminKey } from "./api/client.js";
import { requestSignIn, signOut, useSession } from "./api/session.js";
import { useHasAdminKey } from "./api/useIsAdmin.js";

export default function HamburgerMenu({ onClose, viewMode, companyName, companyTab, isAdmin, onNavigate, onNavigateCompanyTab }) {
  const { status, user } = useSession();
  const hasAdminKey = useHasAdminKey();
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
          {isAdmin && (
            <button className={`hamburger-link ${viewMode === "monitor" ? "active" : ""}`} onClick={() => { onNavigate("/monitor", "monitor"); onClose(); }}>Monitor</button>
          )}
        </nav>
        {companyName && (
          <nav className="hamburger-nav hamburger-company-section">
            <div className="hamburger-section-label">{companyName}</div>
            <button className={`hamburger-link ${viewMode === "company" && companyTab === "overview" ? "active" : ""}`} onClick={() => { onNavigateCompanyTab("overview"); onClose(); }}>Overview</button>
            <button className={`hamburger-link ${viewMode === "company" && companyTab === "surface" ? "active" : ""}`} onClick={() => { onNavigateCompanyTab("surface"); onClose(); }}>Surface</button>
          </nav>
        )}
        <nav className="hamburger-nav hamburger-account-section">
          <div className="hamburger-section-label">{user ? user.email : "Account"}</div>
          {status === "signed_in" ? (
            <>
              <button className={`hamburger-link ${viewMode === "account" ? "active" : ""}`} onClick={() => { onNavigate("/account", "account"); onClose(); }}>Alerts &amp; webhooks</button>
              <button className="hamburger-link" onClick={() => { signOut(); onClose(); }}>Sign out</button>
            </>
          ) : (
            <button className="hamburger-link" onClick={() => { requestSignIn(); onClose(); }}>Sign in</button>
          )}
        </nav>
        {hasAdminKey && (
          <nav className="hamburger-nav hamburger-admin-section">
            <div className="hamburger-section-label">Admin key</div>
            <button className="hamburger-link" onClick={() => { setAdminKey(""); onClose(); }}>Forget admin key</button>
          </nav>
        )}
      </aside>
    </>
  );
}
