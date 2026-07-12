import { useMemo } from "react";

import { categorizeOps } from "../lane.js";
import { OpsCategory } from "./OpsCategory.jsx";

export function OpsLane({ items, onSelect, onNavigate, onPreview, highlightedFunctionKey }) {
  const categories = useMemo(() => categorizeOps(items), [items]);
  return (
    <section className="ps-lane ps-lane-ops">
      <div className="ps-lane-header">
        <span className="ps-lane-title"><span>Operations</span></span>
        <span>{items.length}</span>
      </div>
      <div className="ps-lane-body ps-ops-groups">
        {categories.length ? (
          categories.map((cat) => (
            <OpsCategory
              key={cat.key}
              category={cat}
              onSelect={onSelect}
              onNavigate={onNavigate}
              onPreview={onPreview}
              highlightedFunctionKey={highlightedFunctionKey}
            />
          ))
        ) : (
          <div className="ps-lane-empty">No mapped functions</div>
        )}
      </div>
    </section>
  );
}
