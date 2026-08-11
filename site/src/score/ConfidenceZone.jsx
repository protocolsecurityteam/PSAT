import { Fragment, useState } from "react";

import CapabilityTag from "./CapabilityTag.jsx";
import HelpTag from "./HelpTag.jsx";
import TailToggle from "./TailToggle.jsx";
import { principalChip, timelockProposer } from "./derive.js";
import { categoryById, confidenceZone } from "./confidenceZone.js";
import { ceilingText, countWord, pointsText } from "./format.js";
import { ActorLine, TargetList } from "./rowAnatomy.jsx";

function ConfidenceMeter({ channel }) {
  return (
    <div className="sc-channel">
      <div className="sc-row1">
        <span className="sc-nm">{channel.name}</span>
        {channel.isMin && <span className="sc-hd">min</span>}
        <span className="sc-pv">
          {channel.pct === null ? (
            <span className="sc-nd">not determined</span>
          ) : (
            `${channel.pct.toFixed(1)}%`
          )}
        </span>
      </div>
      <div className="sc-meter">
        {channel.pct !== null && <div className="sc-meter-fill" style={{ width: `${channel.pct}%` }} />}
      </div>
      <div className="sc-desc">{channel.desc}</div>
    </div>
  );
}

function ConfidenceColumn({ confidencePct, channels }) {
  return (
    <div>
      <h2 className="sc-band-title">Confidence</h2>
      <div className="scz-headline">
        <span className="scz-big">
          {typeof confidencePct === "number" ? (
            `${confidencePct.toFixed(1)}%`
          ) : (
            <span className="sc-nd">not determined</span>
          )}
        </span>
        <span className="scz-big-sub">
          the lowest of the {countWord(channels.length)} — how much of the protocol the grade is
          built on, not how correct it is
        </span>
      </div>
      <div className="scz-grid">
        {channels.map((channel) => (
          <ConfidenceMeter key={channel.id} channel={channel} />
        ))}
      </div>
    </div>
  );
}

// The at-most, with the ≤ attached. A ceiling nobody could bound is the louder
// state, not the quieter one — an unbounded unknown must never read as a small
// number or as a blank.
function CeilingAmount({ usd }) {
  if (usd === null) return <span className="scz-unbounded">no upper limit known</span>;
  return <span className="scz-amt">{ceilingText(usd)}</span>;
}

function StatusLine({ line }) {
  const category = categoryById(line.categoryId);
  if (!category) {
    // A basis this page has no reading for. The name is published raw rather
    // than mapped to whichever question looks closest.
    return (
      <div className="scz-missline">
        <span>
          <span className="sc-nd">not determined</span> — <code>{line.basis}</code> —{" "}
          <CeilingAmount usd={line.ceilingUsd} /> · {line.entities}{" "}
          {line.entities === 1 ? "contract" : "contracts"}
        </span>
      </div>
    );
  }
  const label = (
    <HelpTag
      className="scz-cat sc-cap-help"
      ariaLabel={`What ${category.label} means`}
      note={category.description}
    >
      <b>{category.label}</b>
    </HelpTag>
  );
  if (category.id === "reachability") {
    return (
      <div className="scz-missline">
        <span>
          {label} — <CeilingAmount usd={line.ceilingUsd} /> behind {line.entities} unconfirmed{" "}
          {line.entities === 1 ? "path" : "paths"}
        </span>
      </div>
    );
  }
  return (
    <div className="scz-missline">
      <span>
        {label} — <CeilingAmount usd={line.ceilingUsd} /> · path proven to {line.entities}{" "}
        {line.entities === 1 ? "contract" : "contracts"}
      </span>
    </div>
  );
}

function StatusCell({ status }) {
  return (
    <div className="scz-miss">
      {status.map((line) => (
        <Fragment key={line.basis}>
          <StatusLine line={line} />
          {line.unknownTokens.map((entry) => (
            <div className="scz-missline scz-sec" key={entry.token}>
              <span>
                <span className="sc-nd">not determined</span> — <code>{entry.token}</code> ×{" "}
                {entry.count}
              </span>
            </div>
          ))}
        </Fragment>
      ))}
    </div>
  );
}

function CeilingCell({ entry }) {
  const { lever, pool, refusals } = entry;
  const unbounded = lever.ceiling_usd === null || lever.ceiling_usd === undefined;
  return (
    <div className="scz-ceiling">
      {unbounded && lever.entities_total > 0 ? (
        <span className="scz-unbounded">
          no upper limit known — {lever.entities_total} contracts involved
        </span>
      ) : (
        <div className="scz-stake">{ceilingText(pool ? pool.ceilingUsd : lever.ceiling_usd)}</div>
      )}
      {pool && (
        <div>
          <span className="scz-poolchip">
            ⬡ POOL {pool.name} · {pool.contracts} contracts
          </span>
        </div>
      )}
      {refusals > 0 && (
        <div>
          <span className="scz-ref">+{refusals} not yet priced</span>
        </div>
      )}
    </div>
  );
}

function LeverRow({ entry, onSelect }) {
  const { lever, levers, row } = entry;
  const chip = principalChip(row?.finding || { principal_kind: "", principal: lever.principal });
  const proposer = row?.finding ? timelockProposer(row.finding) : null;
  const points = pointsText(lever.points_ceiling);
  return (
    <div className="scz-trow">
      <span className="scz-pc">
        {points === null ? <span className="sc-nd">not determined</span> : `up to ${points}`}
        <span className="scz-u">score points</span>
      </span>
      <div>
        <div className="sc-who">
          <span className={`sc-kchip sc-kchip-${chip.kind}`}>{chip.label}</span>
          {levers.length > 1 && <span className="scz-nprin">× {levers.length} holders</span>}
          <CapabilityTag capability={lever.capability} />
          {row ? (
            <ActorLine row={row} controllers={entry.controllers} onSelect={onSelect} />
          ) : (
            <span className="sc-addr">{entry.controllers.join(" · ")}</span>
          )}
          {proposer && !proposer.proven && <span className="scz-nd-line">proposer not determined</span>}
        </div>
        {row && <TargetList row={row} onSelect={onSelect} />}
        <div className="scz-chain">{lever.chain}</div>
      </div>
      <StatusCell status={entry.status} />
      <CeilingCell entry={entry} />
    </div>
  );
}

export default function ConfidenceZone({ doc, view, onSelect, withheld = false }) {
  const [tailOpen, setTailOpen] = useState(false);
  const zone = confidenceZone(doc, view.rows);
  return (
    <div className="scz-zone">
      <ConfidenceColumn confidencePct={doc?.confidence_pct} channels={view.confidence} />
      <div>
        <h2 className="sc-band-title">
          Possible deductions
          {/* With the grade withheld there is no λ for these rows to be outside
              of, and naming one would put the withheld quantity back on the
              page. The points ceilings themselves are severity × weakness ×
              band — the same shape as raw points, which the withheld state
              still publishes — so the queue itself stays. */}
          <span className="scz-tag">
            {withheld ? "not determined · not in the grade" : "not determined · not in λ"}
          </span>
        </h2>
        <div className="sc-fact-line scz-intro">
          Each row is a proven permission whose consequence has not been verified. Nothing here is
          charged to the score. The label names the missing verification, the dollar figure is an
          upper bound on what resolving it could put at stake, and rows sharing one pool are never
          added together.
        </div>
        {!zone.published ? (
          <p className="scz-empty sc-nd">
            not determined — this document publishes no unresolved-lever rollup
          </p>
        ) : zone.rows.length === 0 ? (
          <p className="scz-empty">
            Every admitted lever closed — a ceiling proven at $0, or an act that ranks benign.
          </p>
        ) : (
          <>
            <div className="scz-thead">
              <span className="r">could cost</span>
              <span>proven</span>
              <span>not yet verified</span>
              <span>dollar ceiling</span>
            </div>
            {zone.head.map((entry) => (
              <LeverRow key={entry.key} entry={entry} onSelect={onSelect} />
            ))}
            {tailOpen &&
              zone.tail.map((entry) => (
                <LeverRow key={entry.key} entry={entry} onSelect={onSelect} />
              ))}
            {zone.tail.length > 0 && (
              <TailToggle open={tailOpen} onToggle={() => setTailOpen((was) => !was)}>
                + {zone.remaining} more
              </TailToggle>
            )}
          </>
        )}
      </div>
    </div>
  );
}
