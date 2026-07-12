import { useEffect, useMemo, useState } from "react";

import { formatDelay, formatUsd, shortAddr } from "../../format.js";
import { buildSearchResults } from "../../layout/search.js";
import { SORT_OPTIONS } from "../../meta.js";

// The unified filter panel's body: search controls (row 1), then whatever
// filter rows the caller injects as `children` (Type + Roles), then the browse
// preview (rendered only while a result is in focus). Owns the search/sort/
// browse state; the injected rows own their own state.
export function SearchNavigator({ machines, principals, onPreview, onCommit, mode, children }) {
  const [sortKey, setSortKey] = useState("value");
  const [query, setQuery] = useState("");
  const [index, setIndex] = useState(0);

  const results = useMemo(
    () => buildSearchResults(machines, principals, mode, sortKey, query),
    [machines, principals, mode, sortKey, query]
  );

  // Reset index when results change. Typing/re-sorting only refilters the
  // preview — it never previews or commits a selection. The null preview
  // drops any lingering browse marker (gold ring) from the previous result
  // set; the committed selection is unaffected.
  useEffect(() => { setIndex(0); onPreview(null); }, [results.length, mode, sortKey, query, onPreview]);

  const move = (target) => {
    if (results.length === 0) return;
    setIndex(target);
    if (results[target]) onPreview(results[target]);
  };
  const prev = () => move(index > 0 ? index - 1 : results.length - 1);
  const next = () => move(index < results.length - 1 ? index + 1 : 0);

  const current = results[index];
  const commit = () => { if (current) onCommit(current); };

  return (
    <div className="ps-filter-bar">
      {/* Row 1: search + sort + browse nav. Type and Roles rows are injected as
          `children` between here and the preview; both live in one panel now. */}
      <div className="ps-search-controls">
        <div className="ps-search-field">
          <span className="ps-search-field-ic" aria-hidden="true">🔍</span>
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") { e.preventDefault(); commit(); }
              else if (e.key === "ArrowUp") { e.preventDefault(); prev(); }
              else if (e.key === "ArrowDown") { e.preventDefault(); next(); }
            }}
            placeholder="Search... (e.g. 'min value 3M')"
            className="ps-search-input"
          />
        </div>
        <select
          value={sortKey}
          onChange={(e) => setSortKey(e.target.value)}
          className="ps-search-sort"
        >
          {SORT_OPTIONS.map((o) => <option key={o.key} value={o.key}>{o.label}</option>)}
        </select>
        <div className="ps-search-arrows">
          <button onClick={prev} disabled={results.length === 0} title="Previous">▲</button>
          <span className="ps-search-counter">
            {results.length > 0 ? `${index + 1} / ${results.length}` : "0"}
          </span>
          <button onClick={next} disabled={results.length === 0} title="Next">▼</button>
        </div>
      </div>

      {/* Injected filter rows (Type + Roles). */}
      {children}

      {current && (
        <div
          className="ps-search-preview"
          role="button"
          tabIndex={0}
          title="Select (Enter)"
          onClick={commit}
          onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); commit(); } }}
        >
          <div className="ps-search-preview-info">
            <span className="ps-search-preview-name">{current.name || shortAddr(current.address)}</span>
            <span className="ps-search-preview-type">{current.type}</span>
            {/* When the display name already fell back to the short address
                (a label-less principal), don't repeat it in the addr slot. */}
            {current.name !== shortAddr(current.address) && (
              <span className="ps-search-preview-addr">{shortAddr(current.address)}</span>
            )}
            {current.value > 0 && <span className="ps-search-preview-value">{formatUsd(current.value)}</span>}
            {current.kind === "principal" && current.type === "safe" && current.signers > 0 && (
              <span className="ps-search-preview-meta">{current.signers}/{current.ownersCount || "?"} signers</span>
            )}
            {current.kind === "principal" && current.type === "timelock" && current.delay > 0 && (
              <span className="ps-search-preview-meta">{formatDelay(current.delay)} delay</span>
            )}
            {current.kind === "principal" && (
              <span className="ps-search-preview-meta">controls {current.functions} contracts</span>
            )}
            {current.kind === "contract" && (
              <span className="ps-search-preview-meta">{current.functions} fns</span>
            )}
          </div>
          <span className="ps-search-preview-hint">↵ select</span>
        </div>
      )}
    </div>
  );
}
