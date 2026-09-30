import { useState } from "react";

import { clickable } from "../shared/clickable.js";
import { shortAddr } from "./format.js";
import { GotoArrow } from "./GotoArrow.jsx";

// One row per referenced contract: the name/address previews it on the canvas,
// the arrow commits to its card, and `summary` (when given) toggles `children`.
export function EntityRef({ address, name, tag = null, value = null, summary = null, onPreview, onNavigate, children }) {
  const [open, setOpen] = useState(false);
  const label = name || shortAddr(address);
  const expandable = summary != null && children != null;
  return (
    <div className={`ref-row${open ? " open" : ""}`}>
      <div className="ref-head">
        <span className="ref-link" {...clickable(() => onPreview?.(address))}>
          <span className="ref-name">
            {label}
            {tag ? <span className="ref-tag"> ({tag})</span> : null}
          </span>
          <span className="ref-addr">{shortAddr(address)}</span>
        </span>
        {value ? <span className="ref-value">{value}</span> : null}
        {expandable && (
          <button type="button" className="ref-toggle" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
            {summary}
            <span className="ref-caret">{open ? "▾" : "▸"}</span>
          </button>
        )}
        {onNavigate && (
          <GotoArrow onCommit={() => onNavigate({ type: "contract", address, label })} label={`Go to ${label}`} />
        )}
      </div>
      {open && expandable && <div className="ref-body">{children}</div>}
    </div>
  );
}
