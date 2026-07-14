# Handoff — build the Surface "Activity" tab; retire the Monitor + Upgrades tabs

You are implementing a new Surface sidebar panel. **Build exactly to the spec below.** The visual
source of truth is the static prototype in this folder:

- `site/prototypes/activity-tab/index.html` — open it in a browser; it is the pixel/label spec.
- `site/prototypes/activity-tab/preview.png` — rendered reference (three states side by side).

Do not redesign. Match the prototype's structure, labels, ordering, and vocabulary. Use the real
design tokens and existing CSS class idioms (see "Styling"), not the prototype's `pt-`/inline styles
verbatim — translate them into project-conventioned classes.

If something in this doc conflicts with the prototype, the prototype wins for *visuals*; this doc wins
for *data/behavior*. When genuinely blocked on a data question, prefer the simplest honest option and
leave a `// TODO(activity):` note rather than inventing UI.

---

## 1. Mission & scope

Collapse the Surface sidebar's **Monitor** tab and **Upgrades** tab into a single read-first
**"Activity"** tab: a per-entity chronological timeline that merges upgrade history with live
governance events, with alert controls folded in.

**In scope**
1. New `ActivityPanel` component (+ subcomponents) rendered for a new `sidebarMode === "activity"`.
2. Remove the **Monitor** (`"monitoring"`) and **Upgrades** (`"upgrades"`) tabs + their render blocks
   from the Surface sidebar.
3. One small backend change (expose `enrollment_block`, §6).
4. Tests + visual baselines updated (§8).

**Explicitly OUT of scope — do NOT do these**
- **Do NOT delete or unroute the standalone monitoring PAGE.** Leave `ProtocolMonitoringPage.jsx`, its
  route (`/company/{name}/monitoring` in `site/src/router.js`), its `App.jsx` wiring, and its
  `HamburgerMenu.jsx` link fully intact. It will be deleted in a later, separate step after we assert
  the new panel is correct. The page is self-contained (it imports only `monitoring/format.js`, not the
  tab components), so removing the tab components below will not break it.
- **No "Re-enroll" button** anywhere in ActivityPanel.
- **No protocol-wide webhook-count aggregate** ("N Discord webhooks active") — that is per-user/operator.
- **No audit status** in ActivityPanel (no "audited"/"no proof"/checkmarks) — audit lives on the Audits tab.

---

## 2. Visual spec (from the prototype)

ActivityPanel has two modes, driven by whether a machine/principal is selected on the canvas.

### 2a. Nothing selected → protocol-wide (absorbs the standalone page)
- Eyebrow "ACTIVITY" + protocol name (e.g. "etherfi").
- A scanner-health pill (green "scanned 2m ago" etc.) from `scannerHealth(contracts)` in
  `monitoring/format.js`.
- A summary card: "**N** contracts monitored", head block (`max(last_scanned_block)`), and
  "Live since {enrollment date} · upgrade history back to {earliest upgrade}". No buttons.
- "RECENT ACROSS PROTOCOL": compact rows of the newest events across all contracts —
  `pm-badge` type tag + friendly contract name, a kind chip + one-line decoded summary, relative time.
  Rows are clickable (select that contract → switches to entity mode).
- Closing hint: the canvas is the spatial "all contracts" view; select a node for its timeline.

### 2b. Entity selected → status strip + alerts + unified timeline
**Status strip** (monitoring state only — NOT analysis facts):
- Name + `pm-badge` type tag (`proxy`/`safe`/`timelock`/`pausable`/`role_control`/`regular`) + `● active`.
- Sub line: short address + "scanned {rel} ago".
- `pm-kv` state grid from `stateRows(contract)`, e.g. proxy → `Impl`, `Upgradable by`, `Paused`,
  `Last event`; safe → `Threshold` (`4 of 7`), `Owners`, `Last event`. Tones: ok=green, warn=amber.
  `Last event` = `relativeTime` of the newest event for this contract.

**Alerts** (the folded-in Monitor tab; admin-only controls — see §7):
- A row of kind toggles (Upgrades/Ownership/Pause/Roles/Timelock/State, and for safes
  Signers/Threshold/Safe tx). On = teal, off = dimmed. State comes from
  `groupKeysFromConfig(monitoring_config)`; toggling writes via `POST /api/protocols/{id}/monitoring`.
- A webhook chip: the Discord webhook attached to this contract's alert (or "no webhook · attach Discord").

**Timeline** (`ul`, newest first):
- Each row: severity dot on a rail (bigger dot = critical, per `eventSeverity`), a kind chip
  (colored by `eventKind`), a decoded title (`decodeEvent().title`), a mono sub line
  (`decodeEvent().sub`), and a meta line: `tx↗ · block N`.
- **Per-event impl attribution**: for a proxy, each non-upgrade ("logic") event shows
  `under impl 0x…` — the implementation that was live at that event's block (§5c).
- **Enrollment boundary**: a divider pill "◔ Monitoring started · {date}" at `enrollment_block`.
  Events at/after it are live-captured (all kinds); below it, only upgrade rows appear, dimmed and
  tagged `backfill`, running to first deployment. Note under the proxy divider: "Only upgrades are
  back-filled below this line."
- **Non-proxy empty state** below the boundary: "No activity before the line. Activity beyond upgrades
  isn't back-filled — only tracked from {date} on."

---

## 3. Files to change

**Frontend (`site/src`)**
- `surface/sidebar/SidebarTabs.jsx` — remove the **Monitor** button (`mode "monitoring"`, currently
  L16-37 admin block) and the **Upgrades** button (`mode "upgrades"`, L38-43). Add one **Activity**
  button (`mode "activity"`), visible to all users (not gated on `isAdmin` — reading is public;
  write controls gate internally).
- `ProtocolSurface.jsx`:
  - L26-27: replace imports of `UpgradesSidebarPanel` + `SurfaceMonitoringPanel` with `ActivityPanel`.
  - L103 (`sidebarMode` initial) and L107-110 (the non-admin redirect that bounces `"agent"`/
    `"monitoring"` to `"detail"`): drop `"monitoring"` from the redirect; `"activity"` is allowed for
    everyone. Consider defaulting non-admins to `"activity"` or leave `"detail"` — keep current default
    behavior unless the prototype implies otherwise.
  - L651-658 (`{isAdmin && sidebarMode === "monitoring" && <SurfaceMonitoringPanel .../>}`) and
    L659-669 (`{sidebarMode === "upgrades" && <UpgradesSidebarPanel .../>}`): replace both with a
    single `{sidebarMode === "activity" && <ActivityPanel … />}`.
  - Reuse the existing `upgradeHistoryCache` / `cacheUpgradeHistory` (L118-121) for ActivityPanel's
    per-proxy upgrade-history fetch memoization.
- New: `surface/sidebar/activity/ActivityPanel.jsx` and subcomponents
  (e.g. `Timeline.jsx`, `StatusStrip.jsx`, `AlertControls.jsx`, `ProtocolActivity.jsx`).
- New: `site/src/styles/surface/activity.css`, imported from `site/src/styles.css` next to the other
  `@import "./styles/surface/…"` lines.

**Reuse (import, don't reinvent)**
- `monitoring/format.js` — `decodeEvent`, `eventKind`, `eventKindLabel`, `eventSeverity`, `stateRows`,
  `scannerHealth`, `relativeTime`, `lastEventByContract`. This is the shared vocab; the standalone page
  uses it too. Keep it.
- `surface/meta.js` — `MONITOR_ALERT_GROUPS`, `MONITOR_FLAGS` (alert toggle definitions).
- `surface/sidebar/monitoring/helpers.js` — `groupKeysFromConfig`, `configFromGroupKeys`,
  `eventTypesFromGroupKeys`, `needsPollingFromGroupKeys`, `contractTypeForMachine`,
  `subscriptionEventTypeSet`.
- Salvage the upgrade-history fetch + timeline rendering from `surface/sidebar/UpgradesSidebarPanel.jsx`
  and `surface/inspector/UpgradesPanel.jsx`, and the alert-editor/webhook-attach logic from
  `surface/sidebar/monitoring/SurfaceMonitoringPanel.jsx` (+ `MonitorAlertEditor.jsx`).

**Delete once nothing imports them** (they were used ONLY by the two retired tabs — verify with a repo
grep before deleting): `surface/sidebar/UpgradesSidebarPanel.jsx`, `surface/inspector/UpgradesPanel.jsx`,
and the `surface/sidebar/monitoring/` components you fully absorb (`SurfaceMonitoringPanel.jsx`,
`AlertsTable.jsx`, `FocusedContractAlerts.jsx`, `MonitorAlertEditor.jsx`, `MonitorAlertFilters.jsx`,
`MinimizedAlertEditors.jsx`, `icons.jsx`). **Keep** `monitoring/helpers.js`, `meta.js`,
`monitoring/format.js`, and `auditMatching.js`/`auditCoverage.js` (shared / used elsewhere). If unsure
whether something else imports a file, keep it and leave a TODO — deletion is not the goal, a working
Activity tab is.

---

## 4. Data sources / APIs

All via the `api()` helper in `site/src/api/client.js` (injects the admin-key header).

- `GET /api/company/{name}` → `{ protocol_id, contracts:[machines], … }`. Machine fields used:
  `name`, `address`, `chain`, `is_proxy`, `proxy_type`, `upgrade_count`, `job_id`, `contract_id`,
  `last_upgrade_timestamp`.
- `GET /api/company/{name}/addresses` → friendly label map (`all_addresses[]`).
- `GET /api/protocols/{protocol_id}/monitoring` → `MonitoredContract[]`:
  `{ id, address, chain, contract_type, monitoring_config, last_known_state, last_scanned_block,
  enrollment_block, is_active, … }` (enrollment_block added in §6).
- `GET /api/protocols/{protocol_id}/events?limit=100` → protocol-wide `MonitoredEvent[]` (nothing-selected feed).
- `GET /api/monitored-events?address={addr}&chain={chain}&limit={n}` → events for one contract (entity mode).
- `GET /api/analyses/{job_id}/artifact/upgrade_history` (+ `.../artifact/dependencies` for impl names) →
  deep per-proxy upgrade history (see §5b for shape).
- Alerts write: `POST /api/protocols/{protocol_id}/monitoring` (upsert alert config for a contract),
  `PATCH /api/monitored-contracts/{id}` (toggle `is_active`).
- Webhooks: `GET /api/protocols/{protocol_id}/subscriptions`, `POST /api/protocols/{protocol_id}/subscribe`,
  `DELETE /api/protocol-subscriptions/{id}`.

**MonitoredEvent shape:** `{ id, monitored_contract_id, event_type, block_number, tx_hash, data, detected_at }`.

---

## 5. The core logic — assembling the unified timeline

### 5a. Two stores, different depth (this is the load-bearing constraint)
- **`monitored_events`** (live feed): captured **from the enrollment block forward only** — the scanner
  seeds `last_scanned_block = enrollment_block = chain head` at enroll and only moves forward. Broad:
  all event kinds (upgrade + ownership/pause/role/signer/timelock/safe/state).
- **`upgrade_history`** artifact / `upgrade_events` table: back-filled to **deployment** (Etherscan
  getLogs from block 0). Deep, but **upgrades only**.

So a proxy's timeline is: all-kinds above the enrollment line; upgrade-only below it. A non-proxy has no
back-fill at all → only what's above the line.

### 5b. `upgrade_history` artifact shape
```
{
  proxies: {
    "0xproxylower": {
      proxy_type, chain, current_implementation, upgrade_count,
      implementations: [   // OLDEST → NEWEST; reverse for display
        { address, block_introduced, block_replaced, timestamp_introduced,
          timestamp_replaced, contract_name }, …
      ]
    }
  }
}
```

### 5c. Merge algorithm (per selected proxy)
1. Fetch `monitored_events` for the contract and the `upgrade_history` artifact for its `job_id`.
2. Project upgrade-history `implementations[]` into upgrade rows (kind `upgrade`, block =
   `block_introduced`, sub = `→ {address}`, mark the `current_implementation` as `current`).
3. Merge upgrade rows with monitored events. **Dedup upgrades by `(tx_hash, log_index)`** — a
   post-enrollment upgrade appears in *both* stores.
4. Sort newest-first by `block_number` (fall back to timestamp/`detected_at`).
5. Split at `enrollment_block`: rows with `block ≥ enrollment_block` are live; rows below only render if
   they are upgrade rows (tag `backfill`, dim).
6. **Impl attribution:** for each non-upgrade event at block `B`, find the implementation era
   (`block_introduced ≤ B < block_replaced`, treating the current impl's `block_replaced` as ∞) and
   render `under impl {shortAddr}`. Skip for non-proxies.

For non-proxy entities: skip steps 1–2's upgrade fetch; render only monitored events with the boundary
and the non-proxy empty state below it.

### 5d. "Monitoring started" date
Derive from `enrollment_block`. If a block→timestamp isn't readily available client-side, approximate the
label from the earliest `detected_at` among the contract's monitored events (fallback), and leave a
`// TODO(activity): exact enrollment timestamp`.

---

## 6. Backend change (one, small)

`routers/monitored.py` → `_monitored_contract_payload` currently returns `last_scanned_block` but **not**
`enrollment_block`. Add `"enrollment_block": c.enrollment_block` to that dict so the frontend can place the
boundary. (`enrollment_block` already exists on the `MonitoredContract` model — `db/models.py:853`,
`BigInteger`, **`nullable=True`** — and is populated at enroll time.) This is additive and backward-compatible;
add/adjust a serializer test under `tests/` accordingly.

**Nullable — handle it on the frontend.** Rows enrolled before this column landed can have
`enrollment_block === null`. When null, do **not** draw the boundary at block 0 — omit the boundary line and
treat the available history as-is (or label it "monitoring start unknown"). Never crash on null.

No other backend changes. Do not add a merged endpoint — the frontend assembles from the existing ones.

---

## 7. Behavior & gating
- **Reading is public**: the timeline, status strip, and protocol-wide feed render for all users (the
  Activity tab is not `isAdmin`-gated in `SidebarTabs`).
- **Writing is admin-only**: alert toggles, webhook attach/detach, and the `is_active` toggle only render
  for `isAdmin` (mirror how `SurfaceMonitoringPanel` gated its controls). Non-admins see alert *state*
  read-only or hidden — match how the rest of Surface hides operator controls.
- **Polling**: refresh monitored events/contracts on an interval consistent with the existing panels
  (SurfaceMonitoringPanel used 15s; the page uses 30s). Pick one (~30s) and keep a "X ago" ticker.

---

## 8. Tests & verification (must pass before done)

Follow `CLAUDE.md`.

- **Frontend unit/render** (`cd site && npm test`, vitest): update `ProtocolSurface.test.jsx` (it
  asserts every sidebar mode — replace the monitoring/upgrades variants with an `activity` variant).
  Remove/retarget `surface/inspector/inspector.test.jsx`, `surface/sidebar/UpgradesSidebarPanel.principal.test.jsx`,
  and any `monitoring/` component tests you absorb. Add ActivityPanel tests covering: proxy timeline with
  boundary + impl attribution, non-proxy empty-state, protocol-wide mode, and admin vs non-admin control
  visibility. Mock fetch via `setFetchHandler()` (`src/test/fetchMock.js`).
- **Playwright visual baselines** (`site/e2e/visual-baseline.spec.js`): the sidebar changed, so update
  snapshots on Linux/WSL (must match CI's ubuntu):
  `cd site && npx playwright test e2e/visual-baseline.spec.js --update-snapshots` then
  `git add e2e/visual-baseline.spec.js-snapshots/`. Do NOT commit macOS-generated snapshots.
- **Backend offline suite** for the payload change: bring up services and run the marker-filtered offline
  suite (see `CLAUDE.md`; prefer `./run_tests_fast.sh`). Never use `-k "not live"`.
- **CI**: the checks in `.github/workflows/_ci-checks.yml` must be green (includes `ruff format --check`
  and `pyright` for the Python change, and the `frontend-test` job).
- **Self-verify in the running app**: dev server is typically on `http://127.0.0.1:5173`. With an admin
  key seeded (`localStorage psat_admin_key`), open `/company/etherfi/surface`, select a proxy
  (e.g. LiquidityPool) and a Safe, and confirm the panel matches `preview.png` (boundary present, impl
  attribution on logic events, no audit markers, no re-enroll, no webhook-count aggregate). Screenshot
  and compare.

---

## 9. Definition of done
1. Surface sidebar shows **Detail · Agent · Audits · Activity** — no Monitor, no Upgrades.
2. ActivityPanel matches the prototype in both modes for proxy, safe, and a non-proxy contract.
3. Enrollment boundary renders from real `enrollment_block`; impl attribution correct for proxies;
   upgrade dedup works.
4. No re-enroll button, no webhook-count aggregate, no audit markers.
5. The standalone monitoring **page and its route are untouched and still work.**
6. `npm test`, Playwright (with refreshed baselines), and the CI checks all pass.
