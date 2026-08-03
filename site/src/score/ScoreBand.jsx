import { useEffect, useMemo, useRef, useState } from "react";

import ConfidenceStrip from "./ConfidenceStrip.jsx";
import Deductions from "./Deductions.jsx";
import GradeHeader from "./GradeHeader.jsx";
import Protections from "./Protections.jsx";
import { projectScore } from "./derive.js";
import { usdCompact } from "./format.js";

function Shell({ children, bandRef = null }) {
  return (
    <section className="score-band" ref={bandRef}>
      <div className="sc-band-inner">{children}</div>
    </section>
  );
}

function Notice({ title, detail }) {
  return (
    <Shell>
      <p className="sc-eyebrow">Protocol score</p>
      <p className="sc-notice">{title}</p>
      {detail && <p className="sc-notice-sub">{detail}</p>}
    </Shell>
  );
}

// The API's two 404s are different facts and get different copy. They are told
// apart by the pinned detail strings, not by the status alone — collapsing them
// would tell a user with an unscored protocol that their protocol is unknown.
function errorNotice(error) {
  const message = String(error?.message || "");
  if (error?.status === 404 && message.includes("No score has been computed")) {
    return {
      title: "No score has been computed for this protocol yet.",
      detail: "The scorer runs after an analysis completes; the control surface below is unaffected.",
    };
  }
  if (error?.status === 404) {
    return {
      title: "This protocol is not in the scorer's registry.",
      detail: "Nothing has been scored under this name.",
    };
  }
  if (error?.status === 503 || message.includes("Score document could not be read")) {
    return {
      title: "The score exists but could not be loaded — try again.",
      detail: "The stored document was unreadable. This is not an absent score.",
    };
  }
  return { title: "The score could not be loaded.", detail: null };
}

function WithheldBanner({ doc }) {
  const withheld = doc?.provenance?.grade_withheld;
  return (
    <div className="sc-withheld">
      <p className="sc-withheld-title">The grade is withheld.</p>
      <p className="sc-withheld-reason">
        {withheld?.reason || "The document publishes no grade for this protocol."}
      </p>
      {withheld && (
        <div className="sc-withheld-figs">
          {typeof withheld.grade_lambda_computed === "number" && (
            <span>λ computed <b>{withheld.grade_lambda_computed.toFixed(2)}</b></span>
          )}
          {typeof withheld.confidence_pct_computed === "number" && (
            <span>confidence computed <b>{withheld.confidence_pct_computed.toFixed(1)}%</b></span>
          )}
          {typeof withheld.exposure_usd_computed === "number" && (
            <span>exposure computed <b>{usdCompact(withheld.exposure_usd_computed)}</b></span>
          )}
        </div>
      )}
    </div>
  );
}

export default function ScoreBand({ companyName, contracts, score, error, onSelectEntity }) {
  const [open, setOpen] = useState(false);
  const bandRef = useRef(null);
  // Branch on grade_state before any grade field is read: in the withheld state
  // grade_lambda / grade_exposure / confidence_pct are null and the findings do
  // not carry net_points_lambda at all.
  const state = error ? "error" : !score ? "loading" : score.grade_state || "absent";
  const view = useMemo(
    () => (score && score.findings ? projectScore(score, contracts) : null),
    [score, contracts],
  );

  // A `#score` hash is a request to land ON the breakdown, open — the surface
  // sidebar's "Full score breakdown →" sets it, whether that click navigated
  // here or happened further down this very page. Consumed (and cleared) only
  // once the band is actually renderable, so a click that raced the score
  // fetch still opens when the document arrives. The pushState-based router
  // never fires `hashchange` on its own, so the manual PopStateEvent the link
  // dispatches is the signal; hashchange covers direct hash edits.
  const ready = state !== "loading";
  useEffect(() => {
    function maybeOpen() {
      if (window.location.hash !== "#score" || !ready) return;
      setOpen(true);
      requestAnimationFrame(() => {
        bandRef.current?.scrollIntoView?.({ behavior: "smooth", block: "start" });
      });
      window.history.replaceState(
        window.history.state,
        "",
        window.location.pathname + window.location.search,
      );
    }
    maybeOpen();
    window.addEventListener("popstate", maybeOpen);
    window.addEventListener("hashchange", maybeOpen);
    return () => {
      window.removeEventListener("popstate", maybeOpen);
      window.removeEventListener("hashchange", maybeOpen);
    };
  }, [ready]);

  if (state === "loading") {
    return <Notice title="Loading the protocol score…" />;
  }
  if (state === "error") {
    const notice = errorNotice(error);
    return <Notice title={notice.title} detail={notice.detail} />;
  }
  if (state === "absent" || !view) {
    return <Notice title="No score has been computed for this protocol yet." />;
  }

  const withheld = state === "not_determined";
  // projectScore computes both unconditionally, withheld or not.
  const channels = view.confidence;
  const posture = view.posture;

  return (
    <>
      <Shell bandRef={bandRef}>
        {withheld ? (
          <>
            <WithheldBanner doc={score} />
            <div className="sc-expand-row">
              <button
                type="button"
                className={`sc-expand-btn${open ? " sc-open" : ""}`}
                onClick={() => setOpen((was) => !was)}
              >
                <span>Full score breakdown</span> <span className="sc-chev">▼</span>
              </button>
            </div>
          </>
        ) : (
          <GradeHeader doc={score} view={view} open={open} onToggle={() => setOpen((was) => !was)} />
        )}
      </Shell>

      {open && (
        <section className="score-breakdown" data-company={companyName}>
          <div className="sc-band-inner">
            <div className="sc-cols">
              <Deductions view={view} onSelect={onSelectEntity} />
              {withheld ? (
                <Protections
                  doc={{ ...score, grade_exposure: null }}
                  view={{ ...view, protections: [], posture }}
                  note="Modeled protection credit is a grade quantity; with the grade withheld it is not published."
                  onSelect={onSelectEntity}
                />
              ) : (
                <Protections doc={score} view={view} onSelect={onSelectEntity} />
              )}
            </div>
            <ConfidenceStrip channels={channels} />
          </div>
        </section>
      )}
    </>
  );
}
