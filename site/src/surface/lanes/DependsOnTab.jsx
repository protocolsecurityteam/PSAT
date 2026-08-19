import { useEffect, useMemo, useState } from "react";

import { blockExplorerAddressUrl, blockExplorerName } from "../blockExplorer.js";
import { fnChipClass, shortAddr } from "../format.js";
import { GotoArrow } from "../GotoArrow.jsx";
import { buildDependencyView, fetchDependencyGraphViz } from "../layout/dependencies.js";

// The "Depends on" tab: the selected contract's outbound call surface. External
// integrations (off-canvas — the trust surface shown nowhere else) sit up top
// as elevated cards; internal calls collapse to one row per sibling contract.
//
// Interaction mirrors the rest of the card (same peek/commit split as Governs
// rows): clicking a name previews the contract on the canvas, the → commits to
// its card, and the count toggle expands the function chips. External rows are
// off-canvas so they have neither a node nor a card — their only action is the
// block explorer.
//
// Function chips reuse .ps-ctrl-fnchip + fnChipClass verbatim, so their size,
// font, and semantic tint match the Governs tab exactly; the read/write/
// delegatecall distinction is carried by the colored verb label, not the chip.

const VERB_TONES = {
  writes: "#d6bd8c",
  reads: "#8fd3c6",
  delegate: "#c0a0d4",
  creates: "#d0a3c6",
  referenced: "#8b93a6",
};

function VerbLine({ verb, label, fns, note }) {
  return (
    <div className="ps-depends-verb">
      <span className="ps-depends-verb-lbl" style={{ color: VERB_TONES[verb] }}>{label}</span>
      {fns ? (
        <div className="ps-depends-chips">
          {fns.map((fn) => (
            <span key={fn} className={`ps-ctrl-fnchip ${fnChipClass(fn)}`}>{fn}</span>
          ))}
        </div>
      ) : (
        <span className="ps-depends-note">{note}</span>
      )}
    </div>
  );
}

function VerbLines({ row }) {
  return (
    <>
      {row.writes.length > 0 && <VerbLine verb="writes" label="writes" fns={row.writes} />}
      {row.reads.length > 0 && <VerbLine verb="reads" label="reads" fns={row.reads} />}
      {row.delegate && <VerbLine verb="delegate" label="delegatecall" note="runs in this contract's context" />}
      {row.creates > 0 && (
        <VerbLine verb="creates" label="creates" note={`${row.creates} contract${row.creates === 1 ? "" : "s"}`} />
      )}
      {row.referenced && <VerbLine verb="referenced" label="referenced" note="in bytecode · no call decoded" />}
    </>
  );
}

function countSummary(row) {
  const parts = [];
  if (row.writes.length) parts.push(`${row.writes.length} write${row.writes.length === 1 ? "" : "s"}`);
  if (row.reads.length) parts.push(`${row.reads.length} read${row.reads.length === 1 ? "" : "s"}`);
  if (row.delegate) parts.push("delegatecall");
  if (row.creates) parts.push(`creates ${row.creates}`);
  if (row.referenced && !row.reads.length && !row.writes.length && !row.delegate && !row.creates) parts.push("referenced");
  return parts.join(" · ");
}

// Off-canvas dependency: no node to preview, no card to open, so the address
// and the trailing affordance both link to the block explorer. Dep-graph nodes
// carry no chain, so fall back to the selected contract's chain — an external
// integration is reached in the same transaction, hence the same chain.
function ExternalCard({ row, chain }) {
  const explorerChain = row.chain || chain;
  const url = blockExplorerAddressUrl(row.explorerAddress, explorerChain);
  const isLib = row.kind === "library";
  return (
    <div className={`ps-depends-ext${isLib ? " ps-depends-ext-lib" : ""}`}>
      <div className="ps-depends-ext-top">
        <span className="ps-depends-ext-dot" />
        <span className="ps-depends-ext-name">{row.name}</span>
        <span className="ps-depends-ext-tag">{isLib ? "library" : "off-protocol"}</span>
        <span className="ps-depends-spacer" />
        <a className="ps-depends-explorer" href={url} target="_blank" rel="noreferrer">{blockExplorerName(explorerChain)} ↗</a>
      </div>
      <a className="ps-depends-ext-addr" href={url} target="_blank" rel="noreferrer">{row.explorerAddress}</a>
      <VerbLines row={row} />
      <div className="ps-depends-ext-foot">
        <span className="ps-depends-prov">{row.provenance}</span>
      </div>
    </div>
  );
}

// On-canvas dependency: collapsed by default. Body (name+addr) previews on the
// canvas; the count toggle expands the chips; the → commits to its card.
function InternalRow({ row, onPreview, onNavigate }) {
  const [open, setOpen] = useState(false);
  const preview = () => onPreview && onPreview(row.onCanvasAddress);
  return (
    <div className={`ps-depends-row${open ? " open" : ""}`}>
      <div className="ps-depends-head">
        <span
          className="ps-depends-preview"
          role="button"
          tabIndex={0}
          onClick={preview}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              preview();
            }
          }}
        >
          <span className="ps-depends-name">{row.name}</span>
          <span className="ps-depends-addr">{shortAddr(row.onCanvasAddress)}</span>
        </span>
        <button
          type="button"
          className="ps-depends-toggle"
          aria-expanded={open}
          onClick={(e) => {
            e.stopPropagation();
            setOpen((v) => !v);
          }}
        >
          {countSummary(row)}
          <span className="ps-depends-caret">{open ? "▾" : "▸"}</span>
        </button>
        {onNavigate && (
          <GotoArrow
            onCommit={() => onNavigate({ type: "contract", address: row.onCanvasAddress, label: row.name })}
            label={`Go to ${row.name}`}
          />
        )}
      </div>
      {open && (
        <div className="ps-depends-body">
          <VerbLines row={row} />
        </div>
      )}
    </div>
  );
}

export function DependsOnTab({ machine, machines, onPreview, onNavigate }) {
  const [graphState, setGraphState] = useState({ loading: true, error: null, graph: null });

  useEffect(() => {
    let cancelled = false;
    setGraphState({ loading: true, error: null, graph: null });
    fetchDependencyGraphViz(machine)
      .then((graph) => {
        if (!cancelled) setGraphState({ loading: false, error: null, graph });
      })
      .catch((e) => {
        if (!cancelled) setGraphState({ loading: false, error: e?.message || String(e), graph: null });
      });
    return () => {
      cancelled = true;
    };
  }, [machine]);

  const view = useMemo(
    () =>
      graphState.graph
        ? buildDependencyView(graphState.graph, { machines, targetAddress: machine?.address })
        : null,
    [graphState.graph, machines, machine],
  );

  if (graphState.loading) return <div className="ps-lane-empty">Loading dependencies…</div>;
  if (graphState.error) return <div className="ps-lane-empty">Couldn't load dependency data</div>;
  if (!view || view.total === 0) return <div className="ps-lane-empty">No outbound calls detected</div>;

  return (
    <div className="ps-depends">
      {view.external.length > 0 && (
        <section className="ps-principal-section">
          <div className="ps-principal-section-hdr ps-depends-sec-hdr">
            <span title="Contracts outside this protocol that this one calls into — the trust surface, shown nowhere else on the canvas">
              External integrations ({view.external.length})
            </span>
            <span className="ps-depends-sec-sub">off-protocol · opens explorer ↗</span>
          </div>
          {view.external.map((row) => (
            <ExternalCard key={row.key} row={row} chain={machine?.chain} />
          ))}
        </section>
      )}

      {view.internal.length > 0 && (
        <section className="ps-principal-section">
          <div className="ps-principal-section-hdr ps-depends-sec-hdr">
            <span title="Other contracts on this protocol's canvas that this one calls, with the concrete functions it invokes on each">
              Internal calls ({view.internal.length})
            </span>
            <span className="ps-depends-sec-sub">on canvas</span>
          </div>
          {view.internal.map((row) => (
            <InternalRow key={row.key} row={row} onPreview={onPreview} onNavigate={onNavigate} />
          ))}
        </section>
      )}
    </div>
  );
}
