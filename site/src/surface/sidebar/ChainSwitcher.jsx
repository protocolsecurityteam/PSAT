import { chainColor, chainLabel } from "../chainMeta.js";

// One pill per chain the protocol has contracts on. Single-chain protocols
// render nothing.
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
