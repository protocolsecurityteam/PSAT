import { useState } from "react";

import BoundBadge from "./BoundBadge.jsx";
import CapabilityTag from "./CapabilityTag.jsx";
import TailToggle from "./TailToggle.jsx";
import { PROTECTION_ROWS } from "./derive.js";
import { usdCompact } from "./format.js";
import { ActorLine, KindChip, TargetList } from "./rowAnatomy.jsx";

const EXPOSURE_EXPLAINER =
  "The score weighted by value. Higher means more of the protocol's dollars sit behind safe controls.";

function Nd({ children }) {
  return <span className="sc-nd">{children || "not determined"}</span>;
}

function AuditCoverage({ posture, earnedNegatives }) {
  if (!posture) return null;
  const {
    reportsOnFile,
    contractsTotal,
    contractsCovered,
    contractsProven,
    coveredUsd,
    trackedTotalUsd,
    valueProvenPct,
    valueCoveredOnlyPct,
    contractProvenPct,
    contractCoveredOnlyPct,
  } = posture;

  return (
    <div className="sc-facts">
      <div className="sc-fact-title">
        <b>Audit coverage</b>
        <span className="sc-fact-num">
          {reportsOnFile === null ? <Nd>reports on file not determined</Nd> : `${reportsOnFile} reports on file`}
        </span>
      </div>

      <div className="sc-fact-row">
        <span className="sc-fact-lbl">by value</span>
        <div className="sc-ameter">
          {valueProvenPct !== null && <div className="sc-proven" style={{ width: `${valueProvenPct}%` }} />}
          {valueCoveredOnlyPct !== null && (
            <div className="sc-matched" style={{ width: `${valueCoveredOnlyPct}%` }} />
          )}
        </div>
      </div>
      <div className="sc-fact-line">
        {coveredUsd === null || trackedTotalUsd === null ? (
          <Nd>audited-value share not determined</Nd>
        ) : (
          <>
            <b>{usdCompact(coveredUsd)}</b> of {usdCompact(trackedTotalUsd)} priced value sits in audited
            contracts ·{" "}
            {valueProvenPct === null ? <Nd /> : <b>{valueProvenPct.toFixed(1)}%</b>} proven to run the
            audited code
          </>
        )}
      </div>

      <div className="sc-fact-row sc-fact-row-2">
        <span className="sc-fact-lbl">by contract</span>
        <div className="sc-ameter">
          {contractProvenPct !== null && (
            <div className="sc-proven" style={{ width: `${contractProvenPct}%` }} />
          )}
          {contractCoveredOnlyPct !== null && (
            <div className="sc-matched" style={{ width: `${contractCoveredOnlyPct}%` }} />
          )}
        </div>
      </div>
      <div className="sc-fact-line">
        {contractsCovered === null || contractsTotal === null ? (
          <Nd>matched contracts not determined</Nd>
        ) : (
          <>
            <b>
              {contractsCovered} / {contractsTotal}
            </b>{" "}
            contracts matched to an audit ·{" "}
            {contractsProven === null ? <Nd /> : <b>{contractsProven}</b>} proven on-chain
          </>
        )}
      </div>

      {/* posture.provablyDiffers is deliberately not rendered: the classifier's
          "provably differs" bucket is not proven to the standard the word
          claims, and a warning line is the wrong place to hedge. The figure
          stays in the payload and in the projection. */}
      {earnedNegatives.length > 0 && (
        <div className="sc-fact-line">
          <b>{earnedNegatives.length}</b> functions proven to have no reach
        </div>
      )}
    </div>
  );
}

export default function Protections({ doc, view, note, onSelect }) {
  const [tailOpen, setTailOpen] = useState(false);
  const exposure = doc.grade_exposure;
  // The pot the grade is weighted over. Published only as the number the
  // document carries — absent stays absent, never $0.
  const tracked = doc?.provenance?.value?.tracked_total_usd;
  const rows = view.protections;
  return (
    <div>
      <h2 className="sc-band-title">Protections</h2>
      {note && <p className="sc-notice-sub">{note}</p>}

      {typeof exposure === "number" && (
        <>
          <div className="sc-shield">
            <span className="sc-shield-v">
              {exposure.toFixed(1)}
              <span className="sc-shield-of"> / 100</span>
            </span>
            <span className="sc-shield-s">exposure grade</span>
            {typeof tracked === "number" && Number.isFinite(tracked) && (
              <>
                <span className="sc-shield-v sc-shield-tracked">{usdCompact(tracked)}</span>
                <span className="sc-shield-s">value tracked</span>
              </>
            )}
          </div>
          <div className="sc-split-bar">
            <div className="sc-split-a" style={{ flexBasis: `${exposure}%` }} title={`exposure grade ${exposure.toFixed(1)}`} />
            <div
              className="sc-split-b"
              style={{ flexBasis: `${100 - exposure}%` }}
              title="severity-weighted value at risk"
            />
          </div>
          <div className="sc-fact-line sc-explainer">{EXPOSURE_EXPLAINER}</div>
        </>
      )}

      {(tailOpen ? rows : rows.slice(0, PROTECTION_ROWS)).map((row) => (
        <div className="sc-prot" key={row.index}>
          <div className="sc-prot-head">
            <KindChip chip={row.chip} chain={row.chain} controller={row.address} onSelect={onSelect} />
            <span className="sc-prot-what">
              <CapabilityTag capability={row.capability} />
              {row.valueText ? ` on ${row.valueText}` : ""}
            </span>
            {/* Outside `.sc-prot-what`, which ellipsises: a chip inside it is the
                first thing a narrow row would cut, and the direction is the part
                of the band that must not be droppable. */}
            {row.value.determined ? (
              <BoundBadge direction={row.value.direction} />
            ) : row.provenNoReach ? (
              // An earned negative, printed in the row's own voice like the
              // deduction row prints it — not the unknown's italic.
              <span>proven no reach</span>
            ) : (
              <Nd>value not determined</Nd>
            )}
            <span className="sc-prot-saved">+{row.delta.toFixed(1)}</span>
          </div>
          {/* The same finding's deduction-row anatomy, through the same
              components: the protected action and the contracts it lives on
              read identically on both sides of the page. */}
          {row.anatomy && (
            <div className="sc-who">
              <ActorLine row={row.anatomy} onSelect={onSelect} />
            </div>
          )}
          <div className="sc-pbar" style={{ width: `${row.widthPct}%` }}>
            <div className="sc-avoided" style={{ flexBasis: `${row.avoidedPct}%` }} />
            <div className="sc-charged" style={{ flexBasis: `${row.chargedPct}%` }} />
          </div>
          {row.anatomy && <TargetList row={row.anatomy} onSelect={onSelect} />}
          {row.chain && <div className="sc-chain">{row.chain}</div>}
        </div>
      ))}
      {rows.length > PROTECTION_ROWS && (
        <TailToggle flush open={tailOpen} onToggle={() => setTailOpen((was) => !was)}>
          + {rows.length - PROTECTION_ROWS} more · +
          {rows
            .slice(PROTECTION_ROWS)
            .reduce((sum, r) => sum + r.delta, 0)
            .toFixed(1)}{" "}
          combined
        </TailToggle>
      )}

      {rows.length > 0 && (
        <div className="sc-ledger-foot sc-prot-foot">
          <span className="sc-key"><span className="sc-dot sc-dot-kept" /> modeled score saved (λ, not additive)</span>
          <span className="sc-key"><span className="sc-dot sc-dot-ded" /> still charged (λ)</span>
        </div>
      )}

      <AuditCoverage posture={view.posture} earnedNegatives={doc.earned_negatives || []} />
    </div>
  );
}
