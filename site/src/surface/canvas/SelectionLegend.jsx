// Explains the chip colours while something is selected (warm = selection acts
// outward, cool = acts on it). The reach row only appears when the selection
// has reach.
export function SelectionLegend({ onClear, hasReach = false }) {
  return (
    <div className="ps-selection-legend">
      <div className="ps-selection-legend-row">
        <span className="ps-selection-legend-swatch ps-selection-legend-swatch--out" />
        <span>selected acts on this contract</span>
      </div>
      <div className="ps-selection-legend-row">
        <span className="ps-selection-legend-swatch ps-selection-legend-swatch--in" />
        <span>this contract acts on selected</span>
      </div>
      {hasReach && (
        <div className="ps-selection-legend-row">
          <span className="ps-selection-legend-swatch ps-selection-legend-swatch--reach" />
          <span>selected reaches this contract</span>
        </div>
      )}
      {/* The pane-click clear is invisible; this makes it discoverable. */}
      <button className="ps-selection-clear" onClick={onClear} title="Clear selection (Esc)">
        <kbd>esc</kbd> deselect
      </button>
    </div>
  );
}
