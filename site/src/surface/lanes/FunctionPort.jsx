import { GuardGlyph } from "../../ui/GuardGlyph.jsx";

function CallerButton({ principal, onNavigate }) {
  const d = principal.display || {};
  const accent = d.accent || "#94a3b8";
  return (
    <button
      type="button"
      className="ps-caller-btn"
      title={`Go to ${d.name}${d.sub ? ` ${d.sub}` : ""}`}
      onClick={(e) => {
        e.stopPropagation();
        onNavigate &&
          onNavigate({
            type: principal.resolvedType,
            address: principal.address,
            label: principal.label,
            details: principal.details,
          });
      }}
    >
      <span className="ps-caller-ic" style={{ color: accent }}>
        <GuardGlyph kind={d.kind} accent={accent} title={d.name} />
      </span>
      <span className="ps-caller-name">{d.name}</span>
      {d.sub && <span className="ps-caller-sub">{d.sub}</span>}
    </button>
  );
}

export function FunctionPort({ fnView, onSelect, onNavigate, orientation, highlighted }) {
  const guard = fnView.guard || {};
  const callers = guard.principals || [];
  return (
    <div
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
              <CallerButton key={p.address} principal={p} onNavigate={onNavigate} />
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
