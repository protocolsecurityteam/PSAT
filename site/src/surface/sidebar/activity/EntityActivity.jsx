import { useEffect, useMemo, useState } from "react";

import { api } from "../../../api/client.js";
import { AlertControls } from "./AlertControls.jsx";
import { proxyState } from "./helpers.js";
import { StatusStrip } from "./StatusStrip.jsx";
import { Timeline } from "./Timeline.jsx";
import { buildTimeline, filterTimelineBySalience, historyFetchErrored } from "./buildTimeline.js";

const POLL_MS = 30_000;

// The selected contract's status strip, alert controls and timeline.
export function EntityActivity({
  machine,
  contract,
  subscriptions,
  isAdmin,
  saving,
  onAttachWebhook,
  cache,
  onCache,
  now,
  minSalience = "routine",
  onHiddenCount,
  nameFor,
  onPreview,
  onNavigate,
}) {
  const [events, setEvents] = useState([]);
  // Carried with its (address, chain): this component is reused across
  // selections, so identity turns the gap into pending rather than the previous
  // contract's answer.
  const [eventsOutcome, setEventsOutcome] = useState(null);
  const [history, setHistory] = useState(null);
  // `{ jobId, state }` with state present | absent | not_determined. Pending
  // isn't stored: it's the absence of an outcome for the current job, so no
  // path can forget it. Tagged with job_id because the component is reused
  // across selections.
  const [historyOutcome, setHistoryOutcome] = useState(null);

  const address = machine?.address;
  const chain = machine?.chain || contract?.chain || "ethereum";
  // Three states: `not_determined` is a row whose proxy signals contradict (one
  // real contract has 14 upgrades). `isProxy` gates what renders as proven;
  // `mayBeProxy` gates whether to ask.
  const proxyhood = proxyState(machine);
  const isProxy = proxyhood === "proxy";
  const mayBeProxy = proxyhood !== "not_proxy";

  useEffect(() => {
    // Cleared before fetching, or the previous contract's events render under
    // the new one.
    setEvents([]);
    setEventsOutcome(null);
    if (!address) { return undefined; }
    let cancelled = false;
    const key = `${address}|${chain}`;
    const load = async () => {
      try {
        const q = `address=${encodeURIComponent(address)}&chain=${encodeURIComponent(chain)}&limit=100`;
        const evs = await api(`/api/monitored-events?${q}`);
        if (cancelled) return;
        setEvents(Array.isArray(evs) ? evs : []);
        // A non-array body isn't an answer.
        setEventsOutcome({ key, state: Array.isArray(evs) ? "present" : "not_determined" });
      } catch {
        if (cancelled) return;
        // Keep proven events: this polls every 30s and a transient 502 used to
        // blank them. Say the failure instead.
        setEventsOutcome({ key, state: "not_determined" });
      }
    };
    load();
    const t = setInterval(load, POLL_MS);
    return () => { cancelled = true; clearInterval(t); };
  }, [address, chain]);

  // Cached by job_id; names aren't resolved, so dependencies is skipped.
  useEffect(() => {
    // Both pieces of state belong to one selection; stale history would
    // attribute one proxy's timeline to another (the `proxy` memo's
    // fall-through makes that reachable). Cleared once here so no branch can
    // skip it.
    setHistoryOutcome(null);
    setHistory(null);
    if (!mayBeProxy || !machine?.job_id) { return undefined; }
    const cached = cache && cache[machine.job_id];
    if (cached?.history) {
      setHistory(cached.history);
      setHistoryOutcome({ jobId: machine.job_id, state: "present" });
      return undefined;
    }
    let cancelled = false;
    const jid = encodeURIComponent(machine.job_id);
    api(`/api/analyses/${jid}/artifact/upgrade_history`)
      .then((body) => {
        if (cancelled) return;
        const h = body && typeof body === "object" && !Array.isArray(body) ? body : null;
        setHistory(h);
        // A non-object body (`typeof [] === "object"`) isn't an answer either.
        setHistoryOutcome({ jobId: machine.job_id, state: h ? "present" : "not_determined" });
        if (onCache) onCache(machine.job_id, h, {});
      })
      .catch((e) => {
        if (cancelled) return;
        setHistory(null);
        // An empty rail reads as never upgraded, so only a 404 is silent.
        // Everything else (503, 5xx, network errors without `status`) hedges by
        // default. Never cached.
        setHistoryOutcome({
          jobId: machine.job_id,
          state: e?.status === 404 ? "absent" : "not_determined",
        });
      });
    return () => { cancelled = true; };
    // Omitted so this fetch's own cache write doesn't retrigger the effect.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [machine?.job_id, mayBeProxy]);

  // Pending is derived, not stored, so no path can forget it.
  const eventsState = useMemo(() => {
    if (!address) return "not_determined";
    return eventsOutcome?.key === `${address}|${chain}` ? eventsOutcome.state : "pending";
  }, [address, chain, eventsOutcome]);

  const historyState = useMemo(() => {
    // A proven non-proxy has no back-fill channel: an answer, not a gap.
    // Contradictory rows fall through to the read.
    if (proxyhood === "not_proxy") return "absent";
    // No job means no read was ever issued: unknown, not absent.
    if (!machine?.job_id) return "not_determined";
    // `api()` has no timeout, so this stays pending until the read settles.
    if (historyOutcome?.jobId !== machine.job_id) return "pending";
    return historyOutcome.state;
  }, [proxyhood, machine?.job_id, historyOutcome]);

  const historyUnknown = historyState === "not_determined";

  const proxy = useMemo(() => {
    if (!history?.proxies) return null;
    const target = (address || "").toLowerCase();
    return history.proxies[target] || Object.values(history.proxies)[0] || null;
  }, [history, address]);

  const enrollmentBlock = contract?.enrollment_block ?? null;
  // `mayBeProxy` so a contradictory row with history still renders its eras.
  const timeline = useMemo(
    () => buildTimeline({ events, proxy, enrollmentBlock, isProxy: mayBeProxy, nameFor }),
    [events, proxy, enrollmentBlock, mayBeProxy, nameFor],
  );

  const visible = useMemo(() => filterTimelineBySalience(timeline, minSalience), [timeline, minSalience]);
  useEffect(() => {
    if (onHiddenCount) onHiddenCount(visible.hidden);
  }, [visible.hidden, onHiddenCount]);

  // created_at of the MonitoredContract row stands in for the enrollment
  // block's timestamp.
  // TODO(activity): exact enrollment timestamp from enrollment_block.
  const boundaryDate = contract?.created_at
    || (events.length ? events[events.length - 1]?.detected_at : null);

  const newestEventAt = events[0]?.detected_at || null;

  return (
    <section className="ps-activity-entity">
      <StatusStrip
        machine={machine}
        contract={contract}
        lastEventAt={newestEventAt}
        now={now}
        // "none recorded" must not rest on a failed read.
        eventsState={eventsState}
      />

      {contract ? (
        <AlertControls
          contract={contract}
          subscriptions={subscriptions}
          isAdmin={isAdmin}
          saving={saving}
          onAttachWebhook={(target, groupKeys) => onAttachWebhook(contract, target, groupKeys)}
        />
      ) : null}

      <div className="ps-activity-sect-title" style={{ marginTop: 2 }}>Timeline</div>
      {eventsState === "not_determined" ? (
        <div className="ps-activity-unknown" role="status">
          {events.length
            ? "The last event refresh did not complete — the rows below are the last ones read, and newer events may be missing."
            : "Events were not read — this contract's captured events are unknown, not absent."}
        </div>
      ) : null}
      {historyUnknown ? (
        <div className="ps-activity-unknown" role="status">
          Upgrade history was not read — this proxy's pre-enrollment upgrades
          are unknown, not absent.
        </div>
      ) : null}
      {!historyUnknown && historyFetchErrored(proxy) ? (
        <div className="ps-activity-unknown" role="status">
          The last upgrade-history fetch did not complete — the upgrades below
          are the ones read, and others may be missing.
        </div>
      ) : null}
      <Timeline
        above={visible.above}
        below={visible.below}
        boundaryBlock={timeline.boundaryBlock}
        boundaryDate={boundaryDate}
        isProxy={mayBeProxy}
        chain={chain}
        now={now}
        // Same fact as the marker, so the panel can't hedge in one line and
        // assert absence in the next.
        historyState={historyState}
        // Lets the Timeline tell an empty section from a filtered one.
        hiddenAbove={visible.hiddenAbove}
        hiddenBelow={visible.hiddenBelow}
        onPreview={onPreview}
        onNavigate={onNavigate}
      />
    </section>
  );
}
