import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";

import { letterFor } from "./gradeBands.js";

// Callout labels are absolutely positioned at the midpoint of the span they
// name, so two adjacent groups can overlap at some widths. Measure the rendered
// boxes and drop the smaller-sum label into the row's tooltip rather than
// letting two labels sit on top of each other.
function useCalloutCollisions(callouts) {
  const refs = useRef(new Map());
  const [hidden, setHidden] = useState(() => new Set());
  const ids = callouts.map((c) => c.id).join("|");

  useEffect(() => {
    setHidden((was) => (was.size ? new Set() : was));
  }, [ids]);

  const measure = useCallback(() => {
    const boxes = callouts
      .filter((c) => !hidden.has(c.id))
      .map((c) => ({ id: c.id, sum: c.sum, rect: refs.current.get(c.id)?.getBoundingClientRect() }))
      .filter((b) => b.rect && b.rect.width > 0);
    if (boxes.length < 2) return;
    boxes.sort((a, b) => a.rect.left - b.rect.left);
    for (let i = 1; i < boxes.length; i++) {
      const previous = boxes[i - 1];
      const current = boxes[i];
      if (current.rect.left < previous.rect.right + 6) {
        const drop = previous.sum <= current.sum ? previous.id : current.id;
        setHidden((was) => new Set(was).add(drop));
        return;
      }
    }
  }, [callouts, hidden]);

  useLayoutEffect(measure);

  useEffect(() => {
    window.addEventListener("resize", measure);
    return () => window.removeEventListener("resize", measure);
  }, [measure]);

  const register = (id) => (el) => {
    if (el) refs.current.set(id, el);
    else refs.current.delete(id);
  };
  return { hidden, register };
}

export default function GradeHeader({ doc, view, open, onToggle }) {
  const { lambda, ledger, callouts } = view;
  const { letter, tone, calibrated } = letterFor(doc.model_version, lambda);
  const confidence = doc.confidence_pct;
  const { hidden, register } = useCalloutCollisions(callouts);
  const droppedTitle = callouts
    .filter((c) => hidden.has(c.id))
    .map((c) => `−${c.sum.toFixed(1)} ${c.text}`)
    .join(" · ");
  const subsumed = doc?.provenance?.population?.subsumed_rows;
  const exposure = doc.grade_exposure;
  // λ can be absent outside the withheld state too — the fold refuses to
  // reconstruct one over an unwitnessed raw. With no λ there is no number to
  // print and no bar to lay out: "0.0 kept" would be a fabricated reading.
  const hasLambda = typeof lambda === "number" && Number.isFinite(lambda);

  return (
    <>
      <div className="sc-grade-inner">
      <div className="sc-grade-left">
        {letter && <div className={`sc-grade-letter sc-tone-${tone}`}>{letter}</div>}
        <div className="sc-grade-nums">
          {hasLambda ? (
            <div className="sc-num">{lambda.toFixed(1)}</div>
          ) : (
            <div className="sc-num sc-nd">not determined</div>
          )}
          <div className="sc-of">λ / 100</div>
          {!calibrated && (
            <div className="sc-uncal">bands uncalibrated for this model version</div>
          )}
          {typeof confidence === "number" && confidence < 50 && (
            <div className="sc-badge">⚠ provisional · confidence {confidence.toFixed(1)}%</div>
          )}
        </div>
      </div>

      <div className="sc-grade-mid">
        {hasLambda && (
          <>
            <div className="sc-ledger-bar">
              <div className="sc-ledger-seg sc-kept" style={{ flexBasis: `${ledger.kept}%` }}>
                <span className="sc-inlbl">{ledger.kept.toFixed(1)} kept</span>
              </div>
              {ledger.segments.map((segment, i) => (
                <div
                  key={segment.id}
                  className={`sc-ledger-seg sc-ded${i === ledger.segments.length - 1 ? " sc-last" : ""}`}
                  style={{ flexBasis: `${segment.basis}%` }}
                  title={segment.title}
                />
              ))}
            </div>
            <div className="sc-ledger-callouts" title={droppedTitle || undefined}>
              {callouts.map((callout) =>
                hidden.has(callout.id) ? null : (
                  <span
                    key={callout.id}
                    ref={register(callout.id)}
                    className="sc-callout"
                    style={{ left: `${callout.centerPct}%` }}
                  >
                    <span className="sc-tick" />
                    <b>−{callout.sum.toFixed(1)}</b> {callout.text}
                  </span>
                ),
              )}
            </div>
            <div className="sc-ledger-foot">
              <span className="sc-key"><span className="sc-dot sc-dot-kept" /> kept</span>
              <span className="sc-key"><span className="sc-dot sc-dot-ded" /> deductions, worst-first</span>
            </div>
          </>
        )}
      </div>

      <div className="sc-grade-stats">
        <div className="sc-gstat">
          <div className="sc-v">{typeof exposure === "number" ? exposure.toFixed(1) : <span className="sc-nd">not determined</span>}</div>
          <div className="sc-l">exposure grade</div>
          <div className="sc-s">severity-weighted</div>
        </div>
        <div className="sc-gstat">
          <div className="sc-v">{(doc.findings || []).length}</div>
          <div className="sc-l">findings</div>
          <div className="sc-s">
            {typeof subsumed === "number" ? `+${subsumed} subsumed` : "subsumed rows not determined"}
          </div>
        </div>
      </div>
      </div>

      <div className="sc-expand-row">
        <button type="button" className={`sc-expand-btn${open ? " sc-open" : ""}`} onClick={onToggle}>
          <span>Full score breakdown</span> <span className="sc-chev">▼</span>
        </button>
      </div>
    </>
  );
}
