import { useEffect, useState } from "react";

import { FunctionPort } from "./FunctionPort.jsx";

export function OpsCategory({
  category,
  onSelect,
  onNavigate,
  onPreview,
  highlightedFunctionKey,
  highlightedCaller = null,
}) {
  const [expanded, setExpanded] = useState(false);
  const containsHighlight = category.items.some((fnView) => fnView.key === highlightedFunctionKey);
  useEffect(() => {
    if (containsHighlight) setExpanded(true);
  }, [containsHighlight]);
  return (
    <div className="ps-ops-category">
      <button
        type="button"
        className="ps-ops-category-header"
        onClick={() => setExpanded(!expanded)}
      >
        <span className={`ps-ops-chevron${expanded ? " ps-ops-chevron-open" : ""}`}>&#9656;</span>
        <span className="ps-ops-category-label">{category.label}</span>
        <span className="ps-ops-category-count">{category.items.length}</span>
      </button>
      {expanded && (
        <div className="ps-ops-category-body">
          {category.items.map((fnView) => (
            <FunctionPort
              key={fnView.key}
              fnView={fnView}
              orientation="ops"
              onSelect={onSelect}
              onNavigate={onNavigate}
              onPreview={onPreview}
              highlighted={fnView.key === highlightedFunctionKey}
              highlightedCaller={highlightedCaller}
            />
          ))}
        </div>
      )}
    </div>
  );
}
