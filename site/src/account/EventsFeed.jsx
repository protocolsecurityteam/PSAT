import { useCallback, useEffect, useRef, useState } from "react";

import { api } from "../api/client.js";
import { shortenAddress } from "../shared/format.js";
import { blockExplorerAddressUrl, blockExplorerName, blockExplorerTxUrl } from "../surface/blockExplorer.js";
import { eventKindLabel, eventSeverity } from "../surface/sidebar/activity/eventClass.js";
import { decodeEvent, relativeTime } from "../surface/sidebar/activity/format.js";

export const PAGE_SIZE = 25;
const NO_FILTERS = { protocol: "", eventType: "", from: "", to: "" };
const SEVERITY_LABEL = { critical: "Critical", major: "Major", routine: "Routine" };

function capitalize(text) {
  return text ? text[0].toUpperCase() + text.slice(1) : text;
}

function localMidnight(day, plusDays = 0) {
  const date = new Date(`${day}T00:00`);
  date.setDate(date.getDate() + plusDays);
  return date.toISOString();
}

// Date inputs are local calendar days and both ends are inclusive; the API's
// `until` is exclusive, so it gets the following midnight.
export function feedQuery(filters, cursor) {
  const params = new URLSearchParams({ limit: String(PAGE_SIZE) });
  if (filters.protocol) params.set("protocol_id", filters.protocol);
  if (filters.eventType) params.set("event_type", filters.eventType);
  if (filters.from) params.set("since", localMidnight(filters.from));
  if (filters.to) params.set("until", localMidnight(filters.to, 1));
  if (cursor) params.set("cursor", cursor);
  return `/api/me/events?${params}`;
}

export function eventTypeLabel(eventType) {
  return capitalize(decodeEvent({ event_type: eventType }).title);
}

function EventRow({ event, onOpenCompany }) {
  const severity = eventSeverity(event);
  const { title, sub } = decodeEvent(event);
  const { contract, protocol } = event;
  const txLink = blockExplorerTxUrl(event.tx_hash, contract.chain);
  const contractLink = blockExplorerAddressUrl(contract.address, contract.chain);
  const detected = new Date(event.detected_at);
  return (
    <li className={`account-row events-row sev-${severity}`} data-event-id={event.id}>
      <span className={`events-sev sev-${severity}`}>{SEVERITY_LABEL[severity]}</span>
      <div className="account-row-main">
        <span className="account-row-title">
          <span className="events-kind">{eventKindLabel(event)}</span> {capitalize(title)}
        </span>
        <span className="account-row-sub">
          <a href={contractLink} target="_blank" rel="noreferrer noopener" title={contract.address}>
            {contract.name || shortenAddress(contract.address)}
          </a>
          {" · "}{contract.chain}{" · "}
          <button type="button" className="account-link-btn" onClick={() => onOpenCompany?.(protocol.name)}>
            {protocol.name}
          </button>
        </span>
        {sub ? <span className="account-row-sub">{sub}</span> : null}
      </div>
      <div className="events-meta">
        <time dateTime={event.detected_at} title={detected.toISOString()}>
          {detected.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}
        </time>
        <span className="muted">{relativeTime(event.detected_at)} · block {event.block_number.toLocaleString()}</span>
        {txLink ? (
          <a href={txLink} target="_blank" rel="noreferrer noopener">
            View tx on {blockExplorerName(contract.chain)} ↗
          </a>
        ) : (
          <span className="muted">Detected by state read</span>
        )}
      </div>
    </li>
  );
}

export default function EventsFeed({ onOpenCompany }) {
  const [options, setOptions] = useState(null);
  const [filters, setFilters] = useState(NO_FILTERS);
  const [events, setEvents] = useState([]);
  const [cursor, setCursor] = useState(null);
  const [status, setStatus] = useState("loading");
  const [error, setError] = useState(null);
  // A response for superseded filters, or a second request for the same
  // cursor, would splice the wrong rows into the list.
  const generation = useRef(0);
  const busy = useRef(false);
  const sentinel = useRef(null);

  useEffect(() => {
    api("/api/me/events/filters", { silent: true })
      .then((body) => setOptions(body))
      .catch(() => setOptions({ protocols: [], event_types: [] }));
  }, []);

  const load = useCallback(
    async (after) => {
      if (after && busy.current) return;
      const gen = after ? generation.current : ++generation.current;
      busy.current = true;
      setStatus(after ? "more" : "loading");
      setError(null);
      try {
        const body = await api(feedQuery(filters, after), { silent: true });
        if (gen !== generation.current) return;
        const page = Array.isArray(body?.events) ? body.events : [];
        setEvents((prev) => {
          if (!after) return page;
          const seen = new Set(prev.map((e) => e.id));
          return [...prev, ...page.filter((e) => !seen.has(e.id))];
        });
        setCursor(body?.next_cursor || null);
        setStatus("ready");
      } catch (err) {
        if (gen !== generation.current) return;
        setError(err.message);
        setStatus("error");
      } finally {
        if (gen === generation.current) busy.current = false;
      }
    },
    [filters],
  );

  useEffect(() => {
    load(null);
  }, [load]);

  useEffect(() => {
    const node = sentinel.current;
    if (!node || !cursor || status !== "ready" || typeof IntersectionObserver === "undefined") return undefined;
    const observer = new IntersectionObserver((entries) => {
      if (entries.some((e) => e.isIntersecting)) load(cursor);
    }, { rootMargin: "400px" });
    observer.observe(node);
    return () => observer.disconnect();
  }, [cursor, status, load]);

  const filtered = Object.values(filters).some(Boolean);
  const setFilter = (key) => (e) => setFilters((prev) => ({ ...prev, [key]: e.target.value }));
  const protocols = options?.protocols || [];
  const eventTypes = options?.event_types || [];

  let body;
  if (status === "loading" && !events.length) {
    body = <p className="muted account-empty">Loading events…</p>;
  } else if (status === "error" && !events.length) {
    body = (
      <p className="account-error" role="alert">
        {error} <button type="button" className="account-link-btn" onClick={() => load(null)}>Retry</button>
      </p>
    );
  } else if (!events.length && filtered) {
    body = (
      <p className="muted account-empty">
        No events match these filters.{" "}
        <button type="button" className="account-link-btn" onClick={() => setFilters(NO_FILTERS)}>Clear filters</button>
      </p>
    );
  } else if (!events.length) {
    body = (
      <div className="events-empty">
        <p className="account-row-title">No monitoring events yet</p>
        <p className="muted account-empty">
          {options && !protocols.length
            ? "Add an alert for a protocol and its ownership transfers, upgrades, role changes and pauses will show up here."
            : "Ownership transfers, upgrades, role changes and pauses on the protocols you follow will show up here."}
        </p>
      </div>
    );
  } else {
    body = (
      <>
        <ul className="account-list events-list" aria-busy={status !== "ready"}>
          {events.map((e) => <EventRow key={e.id} event={e} onOpenCompany={onOpenCompany} />)}
        </ul>
        <div ref={sentinel} className="events-footer">
          {status === "error" ? (
            <p className="account-error" role="alert">
              {error} <button type="button" className="account-link-btn" onClick={() => load(cursor)}>Retry</button>
            </p>
          ) : cursor ? (
            <button type="button" className="ghost" disabled={status !== "ready"} onClick={() => load(cursor)}>
              {status === "more" ? "Loading…" : "Load more"}
            </button>
          ) : (
            <span className="muted">{events.length === 1 ? "1 event" : `${events.length} events`} · end of history</span>
          )}
        </div>
      </>
    );
  }

  return (
    <section className="panel account-card">
      <h2>Monitoring events</h2>
      <div className="events-filters" role="search" aria-label="Filter events">
        <label className="account-field">
          <span>Protocol</span>
          <select aria-label="Protocol" value={filters.protocol} onChange={setFilter("protocol")}>
            <option value="">All protocols</option>
            {protocols.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </label>
        <label className="account-field">
          <span>Event type</span>
          <select aria-label="Event type" value={filters.eventType} onChange={setFilter("eventType")}>
            <option value="">All event types</option>
            {eventTypes.map((t) => (
              <option key={t.event_type} value={t.event_type}>{eventTypeLabel(t.event_type)} ({t.count})</option>
            ))}
          </select>
        </label>
        <label className="account-field">
          <span>From</span>
          <input type="date" aria-label="From" value={filters.from} max={filters.to || undefined} onChange={setFilter("from")} />
        </label>
        <label className="account-field">
          <span>To</span>
          <input type="date" aria-label="To" value={filters.to} min={filters.from || undefined} onChange={setFilter("to")} />
        </label>
        <button type="button" className="ghost" disabled={!filtered} onClick={() => setFilters(NO_FILTERS)}>
          Clear filters
        </button>
      </div>
      {body}
    </section>
  );
}
