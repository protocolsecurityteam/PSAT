import { FunctionPort } from "./FunctionPort.jsx";

export function LaneColumn({
  title,
  laneKey,
  items,
  onSelect,
  onNavigate,
  onPreview,
  highlightedFunctionKey,
  highlightedCaller = null,
}) {
  return (
    <section className={`ps-lane ps-lane-${laneKey}`}>
      <div className="ps-lane-header">
        <span className="ps-lane-title">
          <span>{title}</span>
        </span>
        <span>{items.length}</span>
      </div>
      <div className="ps-lane-body">
        {items.length ? (
          items.map((fnView) => (
            <FunctionPort
              key={fnView.key}
              fnView={fnView}
              orientation={laneKey}
              onSelect={onSelect}
              onNavigate={onNavigate}
              onPreview={onPreview}
              highlighted={fnView.key === highlightedFunctionKey}
              highlightedCaller={highlightedCaller}
            />
          ))
        ) : (
          <div className="ps-lane-empty">No mapped functions</div>
        )}
      </div>
    </section>
  );
}
