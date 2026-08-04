import { SEARCH_MODES } from "../../meta.js";

export function SearchModesBar({ mode, setMode }) {
  return (
    <div className="ps-search-modes">
      {SEARCH_MODES.map((m) => (
        <button
          key={m.key}
          className={`ps-search-mode${mode === m.key ? " active" : ""}`}
          style={{ "--mode-accent": m.accent }}
          onClick={() => setMode(m.key)}
          title={m.label}
        >
          <span className="ps-search-mode-label">{m.label}</span>
        </button>
      ))}
    </div>
  );
}
