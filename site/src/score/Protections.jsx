import BoundBadge from "./BoundBadge.jsx";
import CapabilityTag from "./CapabilityTag.jsx";
import EntityButton, { entityProps } from "./EntityButton.jsx";
import { shortAddress, usdCompact } from "./format.js";

const EXPOSURE_EXPLAINER =
  "How well the protocol's value is defended — each dollar weighted by how dangerous the control paths that can reach it are. Higher is better.";

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

// The caution's own sentence, with the Safe it names made selectable in place.
// The text is sliced around the token that is already in it, so the rendered
// characters are byte-identical to the plain form and the line cannot shift.
function CautionBody({ caution, onSelect }) {
  const { text, link } = caution;
  const at = link ? text.indexOf(link.token) : -1;
  if (!link || at < 0) return text;
  return (
    <>
      {text.slice(0, at)}
      <EntityButton
        onSelect={onSelect}
        target={link}
        title={`Show ${link.label} on the control surface`}
      >
        {link.token}
      </EntityButton>
      {text.slice(at + link.token.length)}
    </>
  );
}

// The kind chip IS the principal on a protection row — it is the only place the
// row names who holds the power — so the interactive props go onto the chip
// itself rather than a wrapper: a wrapper would become the flex item and
// change what this row lays out.
function ProtectionChip({ row, onSelect }) {
  const props = entityProps({
    onSelect,
    target: { chain: row.chain, address: row.address, label: row.chip.label },
    title: row.address ? `Show ${shortAddress(row.address)} on the control surface` : undefined,
  });
  return (
    <span className={`sc-kchip sc-kchip-${row.chip.kind}${props ? " sc-lnk" : ""}`} {...(props || {})}>
      {row.chip.label}
    </span>
  );
}

export default function Protections({ doc, view, note, onSelect }) {
  const exposure = doc.grade_exposure;
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

      {rows.map((row) => (
        <div className="sc-prot" key={row.index}>
          <div className="sc-prot-head">
            <ProtectionChip row={row} onSelect={onSelect} />
            {row.who && <span className="sc-prot-who">{row.who}</span>}
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
          <div className="sc-pbar" style={{ width: `${row.widthPct}%` }}>
            <div className="sc-avoided" style={{ flexBasis: `${row.avoidedPct}%` }} />
            <div className="sc-charged" style={{ flexBasis: `${row.chargedPct}%` }} />
          </div>
          {row.cautions.map((caution) => (
            <div key={caution.text} className={caution.tone === "warn" ? "sc-caut" : "sc-attr"}>
              {caution.tone === "warn" ? "⚠ " : null}
              <CautionBody caution={caution} onSelect={onSelect} />
            </div>
          ))}
        </div>
      ))}

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
