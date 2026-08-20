import { useState } from "react";

import { chainColor, chainLabel } from "./chainMeta.js";
import { ChainSwitcher } from "./sidebar/ChainSwitcher.jsx";
import { SearchModesBar } from "./sidebar/search/SearchModesBar.jsx";
import { SearchNavigator } from "./sidebar/search/SearchNavigator.jsx";

// Unified filter panel — top-left. Search + sort + browse nav, then the
// Type filter and Role visibility rows (injected as children), then the
// browse preview. Collapsed to a pill by default — the full panel is
// large and competes with the selection legend on narrow embeds. The
// pill IS the toggle and sits in the same top-left spot in both states;
// collapsed, it wears the active chain (multichain pages — chain scope
// must not be silently hidden behind an unopened panel).
//
// The panel starts collapsed — it is large, and at first glance the
// canvas matters more. Nothing in it hides nodes (the Type modes only scope
// the search), so collapsing it conceals no active state. Search mode lives
// here (not inside SearchNavigator) so the mode-pill bar can render in the
// Type row while the rest of SearchNavigator stays in the centre overlay.
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
            // Unmounting the navigator skips its preview cleanup — drop any
            // lingering browse marker along with the panel.
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
        {/* Chain row renders only for multi-chain protocols (inv. 13);
            single-chain pages show no chain UI at all. */}
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
