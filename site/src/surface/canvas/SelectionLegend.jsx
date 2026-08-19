// Selection-time legend. Renders only while a contract is selected so
// the chip-color convention (warm = selected acts outward, cool =
// other acts on selected) doesn't have to be memorised — the legend
// is right there with the chips it explains. Uses "acts on" because
// the edges represent any directed relationship (controls / calls /
// sends value / owns / proxies-to); the chip text spells out which
// specifically.
//
// The reach row appears only when the selection HAS transitive reach: a legend
// entry for a chip nothing on the canvas is wearing would name a relationship
// this selection does not have.
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
      {/* Explicit deselect — the pane-click clear exists but is invisible;
          this makes it discoverable and teaches the Esc shortcut. */}
      <button className="ps-selection-clear" onClick={onClear} title="Clear selection (Esc)">
        <kbd>esc</kbd> deselect
      </button>
    </div>
  );
}
