import { useState } from "react";

import { chainColor, chainLabel } from "./chainMeta.js";
import { ChainSwitcher } from "./sidebar/ChainSwitcher.jsx";
import { SearchModesBar } from "./sidebar/search/SearchModesBar.jsx";
import { SearchNavigator } from "./sidebar/search/SearchNavigator.jsx";

// Top-left filter panel, collapsed to a pill by default (it competes with the
// legend on narrow embeds). Collapsed, the pill shows the active chain so scope
// is never hidden. Nothing here hides nodes, so collapsing conceals no state.
// Search mode lives here so its pill bar can render in the Type row.
export function SurfaceFilterPanel({
  machines,
  principals,
  availableChains,
  activeChain,
  isMultichain,
  onSelectChain,
  onPreview,
  onCommit,
}) {
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [searchMode, setSearchMode] = useState("contracts");

  return (
    <div className={`ps-filter-overlay${filtersOpen ? "" : " ps-filter-overlay--collapsed"}`}>
      <button
        type="button"
        className="ps-filter-pill"
        onClick={() => {
          if (filtersOpen) {
            // Unmounting skips the navigator's preview cleanup.
            onPreview(null);
          }
          setFiltersOpen((was) => !was);
        }}
        aria-expanded={filtersOpen}
        aria-label={filtersOpen ? "Collapse filters" : "Open search and filters"}
      >
        Filters <span className="ps-filter-chev" aria-hidden="true">{filtersOpen ? "▴" : "▾"}</span>
        {!filtersOpen && isMultichain && (
          <span className="ps-filter-chain">
            <span className="ps-chain-dot" style={{ "--chain-color": chainColor(activeChain) }} />
            {chainLabel(activeChain)}
          </span>
        )}
      </button>
      {filtersOpen && (
      <SearchNavigator
        machines={machines}
        principals={principals}
        mode={searchMode}
        onPreview={onPreview}
        onCommit={onCommit}
      >
        {/* Multichain only (inv. 13). */}
        <ChainSwitcher chains={availableChains} active={activeChain} onSelect={onSelectChain} />
        <div className="ps-filter-row">
          <span className="ps-filter-gutter">Type</span>
          <SearchModesBar mode={searchMode} setMode={setSearchMode} />
        </div>
      </SearchNavigator>
      )}
    </div>
  );
}
