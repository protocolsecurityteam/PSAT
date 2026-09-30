import { useEffect } from "react";
import { createPortal } from "react-dom";

export function useEscape(onEscape) {
  useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onEscape?.(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onEscape]);
}

// `portal` escapes an ancestor that is a containing block for position:fixed
// (the surface sidebar's backdrop-filter).
export function Modal({ className = "", header, actions = null, onClose, portal = false, children }) {
  useEscape(onClose);
  const dialog = (
    <div className="ps-audit-modal-backdrop" onClick={onClose}>
      <div className={`ps-audit-modal ${className}`} onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="ps-audit-modal-header">
          {header}
          <div className="ps-audit-modal-actions">
            {actions}
            <button type="button" className="ps-audit-modal-btn" onClick={onClose} title="Close" aria-label="Close">
              ✕
            </button>
          </div>
        </div>
        {children}
      </div>
    </div>
  );
  return portal ? createPortal(dialog, document.body) : dialog;
}

export function ModalTitle({ eyebrow, subtitle, extra = null, children }) {
  return (
    <div>
      <p className="eyebrow" style={{ margin: 0 }}>{eyebrow}</p>
      <h2 style={{ margin: "4px 0 0", fontSize: 18 }}>
        {children}
        <span style={{ color: "#94a3b8", fontWeight: 400, marginLeft: 8 }}>{subtitle}</span>
        {extra}
      </h2>
    </div>
  );
}
