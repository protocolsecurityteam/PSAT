import { chainColor, chainLabel } from "../chainMeta.js";

// Chain pill row for the Surface filter panel. Renders one pill per chain the
// protocol actually has contracts on (derived from the loaded payload, never a
// static list), each showing its contract count. Selecting a pill scopes the
// whole Surface page to that chain (the parent filters contracts + writes
// ?chain=).
//
// Unobtrusive by construction: single-chain protocols — the overwhelmingly
// common case — pass one chain, so this renders nothing and the panel looks
// exactly as it did before multichain.
export function ChainSwitcher({ chains = [], active, onSelect }) {
  if (!chains || chains.length <= 1) return null;
  return (
    <div className="ps-filter-row">
      <span className="ps-filter-gutter">Chain</span>
      <div className="ps-chain-bar">
        {chains.map(({ name, count }) => {
          const on = name === active;
          return (
            <button
              key={name}
              type="button"
              className={`ps-chain-chip${on ? " ps-chain-chip-on" : ""}`}
              style={{ "--chain-color": chainColor(name) }}
              aria-pressed={on}
              onClick={() => onSelect(name)}
            >
              <span className="ps-chain-dot" />
              {chainLabel(name)}
              {count != null && <span className="ps-chain-count">{count}</span>}
            </button>
          );
        })}
      </div>
    </div>
  );
}
