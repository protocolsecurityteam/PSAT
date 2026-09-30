// Detail tab's empty state: protocol at a glance. Figures reuse the score
// page's derivations and the type filter's counts; anything unwitnessed renders
// not-determined.
import { useEffect, useMemo, useState } from "react";

import { api } from "../../api/client.js";
import { projectScore } from "../../score/derive.js";
import { letterFor } from "../../score/gradeBands.js";
import { useResource } from "../../shared/useResource.js";
import { formatUsd } from "../format.js";
import { buildSearchResults } from "../layout/search.js";

// Promises cached per company so remounts and concurrent mounts share one
// request.
const scoreCache = new Map();
const monitorCache = new Map();

// Could not find out, distinct from a witnessed absence. Never cached, so a
// transient failure can't pin "no score".
const SCORE_FETCH_FAILED = Symbol("score-fetch-failed");

function fetchScoreDoc(companyName) {
  if (!scoreCache.has(companyName)) {
    scoreCache.set(
      companyName,
      api(`/api/company/${encodeURIComponent(companyName)}/score`, { silent: true })
        .then((doc) => (doc && typeof doc === "object" && doc.grade_state ? doc : null))
        .catch((e) => {
          if (e?.status === 404) return null;
          scoreCache.delete(companyName);
          return SCORE_FETCH_FAILED;
        }),
    );
  }
  return scoreCache.get(companyName);
}

function fetchMonitoring(protocolId) {
  if (!monitorCache.has(protocolId)) {
    monitorCache.set(
      protocolId,
      Promise.all([
        api(`/api/protocols/${protocolId}/monitoring`, { silent: true }).catch(() => null),
        api(`/api/protocols/${protocolId}/events?limit=1`, { silent: true }).catch(() => null),
      ]).then(([contracts, events]) => ({
        // Not determined, distinct from a proven-empty list.
        watched: Array.isArray(contracts) ? contracts.filter((c) => c?.is_active).length : null,
        lastEventAt: Array.isArray(events) ? events[0]?.detected_at || null : null,
      })),
    );
  }
  return monitorCache.get(protocolId);
}

function shortDate(iso) {
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return null;
  return new Date(ms).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function daysAgo(iso) {
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return null;
  const days = Math.floor((Date.now() - ms) / 86400000);
  if (days < 0) return null;
  return days === 0 ? "today" : `${days}d ago`;
}

// Batch upgrades land in one tx across many proxies; naming one would be an
// arbitrary pick.
export function lastUpgradeBatch(contracts) {
  let newest = null;
  for (const c of contracts || []) {
    const ts = c?.last_upgrade_timestamp;
    if (ts && (!newest || ts > newest)) newest = ts;
  }
  if (!newest) return null;
  const batch = (contracts || []).filter((c) => c?.last_upgrade_timestamp === newest);
  return {
    at: newest,
    count: batch.length,
    name: batch.length === 1 ? batch[0].name || batch[0].address : null,
  };
}

function GlanceScoreCard({ companyName, scoreDoc, scoreState, projection }) {
  // Opens ScoreBand's breakdown, whether this navigates or the surface is
  // embedded on that page.
  const scoreHref = `/company/${encodeURIComponent(companyName)}#score`;
  const goScore = (e) => {
    e.preventDefault();
    window.history.pushState({}, "", scoreHref);
    window.dispatchEvent(new PopStateEvent("popstate"));
  };

  let body = null;
  if (scoreState === "loading") {
    body = <div className="ps-glance-dim">Score loading…</div>;
  } else if (scoreState === "error") {
    body = <div className="ps-glance-dim">Score not available right now.</div>;
  } else if (!scoreDoc || !projection) {
    body = <div className="ps-glance-dim">No score published for this protocol.</div>;
  } else if (projection.withheld) {
    body = <div className="ps-glance-dim">Grade withheld — the scorer declined to publish a grade.</div>;
  } else if (typeof projection.lambda !== "number") {
    body = <div className="ps-glance-dim">Grade not determined.</div>;
  } else {
    const grade = letterFor(scoreDoc.model_version, projection.lambda);
    const findings = (scoreDoc.findings || []).length;
    const deducted = Math.round((100 - projection.lambda) * 10) / 10;
    const confidence =
      typeof scoreDoc.confidence_pct === "number" ? `confidence ${scoreDoc.confidence_pct}%` : null;
    const computed = scoreDoc.computed_at ? `computed ${shortDate(scoreDoc.computed_at)}` : null;
    const fix = projection.fix;
    body = (
      <>
        <div className="ps-glance-grade-row">
          {grade.letter ? (
            <div className={`ps-glance-letter sc-tone-${grade.tone}`}>{grade.letter}</div>
          ) : null}
          <div>
            <div className="ps-glance-lambda">
              {projection.lambda.toFixed(1)} / 100
              {!grade.calibrated && <span className="ps-glance-dim"> · uncalibrated</span>}
            </div>
            <div className="ps-glance-sub">{[confidence, computed].filter(Boolean).join(" · ")}</div>
          </div>
        </div>
        {projection.callouts.length > 0 && (
          <>
            <div className="ps-glance-ledger">
              <div className="ps-glance-seg ps-glance-seg-kept" style={{ width: `${projection.lambda}%` }} />
              {projection.callouts.map((c) => (
                <div key={c.id} className="ps-glance-seg ps-glance-seg-ded" style={{ width: `${c.sum}%` }} title={`−${c.sum.toFixed(1)} ${c.text}`} />
              ))}
            </div>
            <div className="ps-glance-ledger-key">
              <span>{projection.lambda.toFixed(1)} kept</span>
              <span>
                −{deducted.toFixed(1)} across {findings} finding{findings === 1 ? "" : "s"}
              </span>
            </div>
          </>
        )}
        {fix && (
          <div className="ps-glance-fix">
            <b>
              {fix.verb} {fix.subject}
            </b>
            {fix.remedy} — modeled <span className="ps-glance-gain">+{fix.recovery.toFixed(1)}</span>
            {typeof fix.lambdaAfter === "number" && <> (→ {fix.lambdaAfter.toFixed(1)})</>}.
          </div>
        )}
      </>
    );
  }

  return (
    <div className="ps-glance-card">
      <div className="ps-glance-title">Protocol score</div>
      {body}
      <a className="ps-glance-link" href={scoreHref} onClick={goScore}>
        Full score breakdown →
      </a>
    </div>
  );
}

export function DetailEmptyState({
  companyName,
  companyData,
  machines = [],
  principals = [],
  onSelectAddress = null,
  initialScore = undefined,
}) {
  const [scoreDoc, setScoreDoc] = useState(null);
  const [scoreState, setScoreState] = useState("loading");

  useEffect(() => {
    if (!companyName) return undefined;
    // The embedded overview owns this request; undefined means standalone.
    if (initialScore !== undefined) {
      const doc = initialScore.data;
      setScoreDoc(doc?.grade_state ? doc : null);
      setScoreState(initialScore.error
        ? (initialScore.error.status === 404 ? "absent" : "error")
        : (doc == null ? "loading" : doc.grade_state ? "ok" : "absent"));
      return undefined;
    }
    let cancelled = false;
    setScoreState("loading");
    fetchScoreDoc(companyName).then((doc) => {
      if (cancelled) return;
      if (doc === SCORE_FETCH_FAILED) {
        setScoreDoc(null);
        setScoreState("error");
        return;
      }
      setScoreDoc(doc);
      setScoreState(doc ? "ok" : "absent");
    });
    return () => {
      cancelled = true;
    };
  }, [companyName, initialScore]);

  const protocolId = companyData?.protocol_id;
  const { data: monitor } = useResource(() => fetchMonitoring(protocolId), [protocolId], {
    enabled: protocolId != null,
  });

  // Same counter as the type filter: timelocks are a union of principals and
  // contract nodes.
  const counts = useMemo(() => {
    const out = {};
    for (const mode of ["eoa", "safe", "timelock"]) {
      out[mode] = buildSearchResults(machines, principals, mode, null, "").length;
    }
    return out;
  }, [machines, principals]);

  const projection = useMemo(
    () => (scoreDoc ? projectScore(scoreDoc, companyData?.contracts || []) : null),
    [scoreDoc, companyData],
  );

  const upgrade = useMemo(() => lastUpgradeBatch(companyData?.contracts), [companyData]);

  const tops = useMemo(
    () =>
      [...(companyData?.contracts || [])]
        .filter((c) => (c.total_usd || 0) > 0)
        .sort((a, b) => (b.total_usd || 0) - (a.total_usd || 0))
        .slice(0, 3),
    [companyData],
  );

  if (!companyData) {
    return (
      <section className="ps-principal-section">
        <div className="ps-inspector-empty">Loading protocol overview…</div>
      </section>
    );
  }

  const tvl = companyData.tvl || null;
  const tvlUsd = tvl ? (tvl.total_usd ?? tvl.defillama_tvl ?? null) : null;
  const tvlSource = tvl && tvl.total_usd == null && tvl.defillama_tvl != null ? "DefiLlama" : "tracked";
  const reports = projection?.posture?.reportsOnFile ?? null;

  return (
    <section className="ps-detail-empty ps-glance">
      <div className="ps-glance-hdr">
        <span className="ps-glance-name">{companyName}</span>
        <span className="ps-glance-meta">
          {[
            companyData.contract_count != null && `${companyData.contract_count} contracts`,
            companyData.all_addresses_count != null && `${companyData.all_addresses_count} addresses`,
          ]
            .filter(Boolean)
            .join(" · ")}
        </span>
      </div>

      {companyData.analysis_pending_balance_effects?.incomplete > 0 && (
        <div className="ps-glance-card" role="status">
          {companyData.analysis_pending_balance_effects.incomplete} balance-dependent analysis checks incomplete
          {companyData.analysis_pending_balance_effects.degraded > 0
            ? ` · ${companyData.analysis_pending_balance_effects.degraded} await recovery after retries`
            : " · awaiting required observations"}
        </div>
      )}

      <GlanceScoreCard
        companyName={companyName}
        scoreDoc={scoreDoc}
        scoreState={scoreState}
        projection={projection}
      />

      <div className="ps-glance-card">
        <div className="ps-glance-title">Who holds privileged surface</div>
        <div className="ps-glance-tiles">
          <div className="ps-glance-tile">
            <div className="ps-glance-tile-n">{counts.eoa}</div>
            <div className="ps-glance-tile-k">EOA</div>
          </div>
          <div className="ps-glance-tile">
            <div className="ps-glance-tile-n">{counts.safe}</div>
            <div className="ps-glance-tile-k">SAFE</div>
          </div>
          <div className="ps-glance-tile">
            <div className="ps-glance-tile-n">{counts.timelock}</div>
            <div className="ps-glance-tile-k">TIMELOCK</div>
          </div>
        </div>
      </div>

      <div className="ps-glance-card">
        <div className="ps-glance-title">Freshness</div>
        <div className="ps-glance-rows">
          <div className="ps-glance-row">
            <span className="ps-glance-row-l">Last upgrade</span>
            {upgrade ? (
              <span className="ps-glance-row-r">
                {upgrade.name || `${upgrade.count} contracts`}
                <span className="ps-glance-row-dim">
                  {[shortDate(upgrade.at), daysAgo(upgrade.at)].filter(Boolean).join(" · ")}
                </span>
              </span>
            ) : (
              <span className="ps-glance-row-r ps-glance-dim">none witnessed</span>
            )}
          </div>
          <div className="ps-glance-row">
            <span className="ps-glance-row-l">Monitoring</span>
            {monitor && monitor.watched != null ? (
              <span className="ps-glance-row-r">
                {monitor.watched} contracts
                {monitor.lastEventAt && (
                  <span className="ps-glance-row-dim">last event {shortDate(monitor.lastEventAt)}</span>
                )}
              </span>
            ) : (
              <span className="ps-glance-row-r ps-glance-dim">not determined</span>
            )}
          </div>
          <div className="ps-glance-row">
            <span className="ps-glance-row-l">Audit reports</span>
            {reports != null ? (
              <span className="ps-glance-row-r">{reports} on file</span>
            ) : (
              <span className="ps-glance-row-r ps-glance-dim">not determined</span>
            )}
          </div>
        </div>
      </div>

      {(tvlUsd != null || tops.length > 0) && (
        <div className="ps-glance-card">
          {tvlUsd != null && (
            <div className="ps-glance-vhead">
              <span className="ps-glance-tvl">{formatUsd(tvlUsd) || "$0.00"}</span>
              <span className="ps-glance-vsrc">
                {["TVL", tvlSource,
                  tvlSource === "tracked" && tvl?.holdings_partial !== false ? "coverage partial/unknown" : null,
                  tvlSource === "tracked" && tvl?.valuation_partial !== false ? "valuation partial/unknown" : null,
                  tvlSource === "tracked"
                    ? (tvl?.holdings_observed_at ? shortDate(tvl.holdings_observed_at) : "observation time unknown")
                    : (tvl?.timestamp ? shortDate(tvl.timestamp) : null)]
                  .filter(Boolean)
                  .join(" · ")}
              </span>
            </div>
          )}
          {tops.length > 0 && (
            <>
              {/*
                Derivative claims aren't netted against TVL, so these aren't
                fractions of it.
              */}
              <div className="ps-glance-vsub">Largest tracked balances</div>
              {tops.map((c) => (
                <button
                  key={c.address}
                  type="button"
                  className="ps-glance-vrow"
                  onClick={onSelectAddress ? () => onSelectAddress(c.address) : undefined}
                  title="custodied balance at this contract — not a share of TVL"
                >
                  <span className="ps-glance-vrow-name">{c.name || c.address}</span>
                  <span className="ps-glance-vrow-usd">{formatUsd(c.total_usd)}</span>
                </button>
              ))}
            </>
          )}
        </div>
      )}

      <div className="ps-detail-empty-hint">Click a contract or principal on the canvas for its detail.</div>
    </section>
  );
}
