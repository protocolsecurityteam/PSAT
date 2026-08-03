import { useEffect, useRef } from "react";

import { GuardGlyph } from "../../ui/GuardGlyph.jsx";
import { GotoArrow } from "../GotoArrow.jsx";

// Body click = preview the caller on the canvas (light peek, no selection
// change); the trailing arrow commits to its card. Same peek/commit split as
// Governs rows and the Guard Inspector's principal cards.
function CallerButton({ principal, onPreview, onNavigate }) {
  const d = principal.display || {};
  const accent = d.accent || "#94a3b8";
  const preview = () => onPreview && onPreview(principal.address);
  return (
    <div
      className="ps-caller-btn"
      role="button"
      tabIndex={0}
      title={`Preview ${d.name}${d.sub ? ` ${d.sub}` : ""}`}
      onClick={(e) => {
        e.stopPropagation();
        preview();
      }}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          preview();
        }
      }}
    >
      <span className="ps-caller-ic" style={{ color: accent }}>
        <GuardGlyph kind={d.kind} accent={accent} title={d.name} />
      </span>
      <span className="ps-caller-name">{d.name}</span>
      {d.sub && <span className="ps-caller-sub">{d.sub}</span>}
      {onNavigate && (
        <GotoArrow
          onCommit={() =>
            onNavigate({
              type: principal.resolvedType,
              address: principal.address,
              label: principal.label,
              details: principal.details,
            })
          }
          label={`Go to ${d.name}`}
        />
      )}
    </div>
  );
}

export function FunctionPort({ fnView, onSelect, onNavigate, onPreview, orientation, highlighted }) {
  const guard = fnView.guard || {};
  const callers = guard.principals || [];
  const nodeRef = useRef(null);
  // The sidebar scrolls, so a highlighted row can land below its fold — a ring
  // the user has to go hunting for marks nothing. ``nearest`` keeps it to the
  // minimum movement needed and is a no-op when the row is already visible.
  useEffect(() => {
    if (!highlighted) return;
    nodeRef.current?.scrollIntoView?.({ block: "nearest" });
  }, [highlighted]);
  return (
    <div
      ref={nodeRef}
      className={`ps-port ps-port-${orientation}${highlighted ? " ps-port-score-highlight" : ""}`}
      style={{ "--port-accent": fnView.tone }}
    >
      <div className="ps-port-copy" onClick={() => onSelect(fnView)} style={{ cursor: "pointer" }}>
        <div className="ps-port-name">{fnView.name}</div>
        {fnView.action && <div className="ps-port-action">{fnView.action}</div>}
      </div>
      {callers.length > 0 ? (
        <div className="ps-callers">
          {callers.length > 1 && <div className="ps-callers-label">callable by</div>}
          <div className="ps-callers-row">
            {callers.map((p) => (
              <CallerButton key={p.address} principal={p} onPreview={onPreview} onNavigate={onNavigate} />
            ))}
          </div>
        </div>
      ) : (
        <button
          type="button"
          className="ps-caller-status"
          onClick={() => onSelect(fnView)}
          title={`Inspect ${fnView.name}`}
        >
          <span className="ps-caller-ic" style={{ color: guard.accent }}>
            <GuardGlyph kind={guard.kind} accent={guard.accent} title={guard.label} />
          </span>
          <span className="ps-caller-name" style={{ color: guard.accent }}>{guard.label}</span>
          {guard.sublabel && <span className="ps-caller-sub">{guard.sublabel}</span>}
        </button>
      )}
    </div>
  );
}
