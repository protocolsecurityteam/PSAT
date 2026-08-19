// Node/group sizing for the surface canvas: group chrome constants, band
// assignment and the within-group interior layout. Split from elkLayout.js;
// the constants are one unit — they must track layout.css together.

// Group container chrome sizing. The top reservation is dynamic now: it
// holds the colored primary bar PLUS the collapsed Controllers accordion
// (one fixed-height row per controller), so the contract cards always start
// below the accordion. The side/bottom padding give breathing room between
// the colored border and the children inside. Child dimensions are sized a
// touch larger than the .ps-node CSS naturally renders so rectpacking gives
// each card its own column of slack — without this, cards on neighbouring
// rows in dense groups visually butt up against each other.
//
// groupHeaderHeight() is only the INITIAL estimate of the collapsed band —
// GroupNode measures the real rendered height (rows can grow when a capability
// summary wraps) and reports it back, after which we reserve that exact value.
// The constants just need to roughly track layout.css so the first frame is
// close; the band is clipped (overflow:hidden) until the measured value lands,
// so an off estimate is never an overlap.
const GROUP_HEADER_BAR_H = 62; // colored primary bar (badge row + count)
const GROUP_ACC_LABEL_H = 26; // "Controllers" eyebrow strip
const GROUP_ACC_ROW_H = 32; // one collapsed single-line controller row (~.ps-ctrl-head + margin)
const GROUP_ACC_PAD_BOTTOM = 10; // breathing room below the last row
export function groupHeaderHeight(numControllers) {
  return GROUP_HEADER_BAR_H + GROUP_ACC_LABEL_H + numControllers * GROUP_ACC_ROW_H + GROUP_ACC_PAD_BOTTOM;
}

const GROUP_PADDING_TOP = groupHeaderHeight(1);
const GROUP_PADDING_SIDE = 24;
const GROUP_PADDING_BOTTOM = 24;
// Floor on a group's width so the Controllers accordion row reads without
// clipping. A row's fixed parts (caret + tag + badge + short address +
// "governs N") need ~350px; this leaves room for a capability tag or two
// beside them before the summary wraps. Narrow groups (1–2 small cards) would
// otherwise be ~306px and crop the row (the band is overflow:hidden). The
// cards stay centered in the widened interior.
const GROUP_MIN_WIDTH = 440;
// Gap between the header band's bottom and the first contract card. The band
// is `position:absolute; top:0` so it sits inside the group's 2px border,
// while React Flow positions child cards relative to the group's outer edge —
// without this the first card's top tucks ~2px under the band. The rest is
// breathing room below the accordion (~on par with GROUP_PADDING_BOTTOM).
const GROUP_HEADER_GAP = 28;
// Child cell sized for the widest contract card the .ps-node CSS
// actually renders (no max-width; long names like
// "EtherFiRedemptionManager" / "AuctionManager" stretch the card to
// ~250px). Telling the grid 200px and getting a 250px card back is
// what was making adjacent cells overlap. CHILD_H stays larger than
// the actual rendered height so vertical spacing has slack for the
// occasional double-line card.
export const CHILD_W = 260;
export const CHILD_H = 130;
export const PRINCIPAL_W = 140;
export const PRINCIPAL_H = 60;

// In-group band assignment. Three bands top-to-bottom:
//   0 = control surfaces — timelocks, role admins, governance contracts.
//   1 = value-bearing — value handlers, bridges, value-moving tokens.
//   2 = interfaces & plumbing — pure tokens, factories, utility.
// Position carries meaning: a glance tells you which contracts hold
// authority vs hold value vs are interface/plumbing, regardless of which
// protocol you're looking at.
//
// We can't rely on `role` alone. The backend classifier puts any
// contract with asset_pull / asset_send into `value_handler`, which
// captures TimelockController-style admins that also execute value
// moves during their queued operations. Has-timelock and
// control_model=governance are the more reliable "this contract issues
// commands" signals, so they win over `role` when both fire.
function bandFor(m) {
  if (!m) return 2;
  // `=== true`, not truthiness: `has_timelock` is three-state on the payload
  // (bool | null) and `null` means no summary row answered. Truthiness already
  // skipped a null, but it skipped it by treating it as the proven `false`; the
  // strict test says which state is being tested for, and the fall-through below
  // is where not-determined stops sharing an outcome with proven-false.
  if (m.has_timelock === true) return 0;
  if (m.control_model === "governance") return 0;
  if (m.role === "governance") return 0;
  // Name override: the backend role classifier does not surface every contract
  // that IS itself a control surface (TimelockController, BoringGovernance,
  // etc.) — when such a contract also has asset-move side effects it ends up
  // tagged value_handler and loses to the band-1 catchall. Pattern-match the
  // name so they float to the top. The check is also the only signal left when
  // `has_timelock` is null, which is why it is not redundant with the test
  // above: since summaries.py made the flag mean "THIS CONTRACT IS A TIMELOCK",
  // a proven timelock returns 0 at the first test and this one only ever adds
  // rows the flag did not prove.
  const nameLower = (m.name || "").toLowerCase();
  if (/timelock|governance|guardian/.test(nameLower)) return 0;
  // Band 2 is a positive claim — "interfaces & plumbing": holds no authority and
  // holds no value. A `role` the backend derived with no summary evidence at all
  // (`role_evidence === "not_determined"`, the `utility` fall-through reached
  // through nothing but nulls) is not evidence for it, so it takes the neutral
  // band-1 catchall instead. Only a role earned from a positive fact places a
  // node in the plumbing band.
  if (m.role_evidence === "not_determined") return 1;
  if (m.role === "token" || m.role === "factory" || m.role === "utility") return 2;
  return 1;
}

// Spacing between children inside a group. Roomier than the obvious
// minimum because:
//   - tight gaps make the bundled edge trunks visually merge with
//     adjacent cells; ~50px of horizontal slack keeps the cabling
//     readable as it forks across the band.
//   - selecting a contract reveals capability labels on its edges; a
//     larger V_GAP gives those labels somewhere to land without
//     overlapping cards in the next row.
const CHILD_H_GAP = 50;
const CHILD_V_GAP = 70;

// Within-group child layout: bucket by role band, sort each band by
// TVL desc, pack each band into a grid centred horizontally so the
// whole group reads as control-on-top / value-in-middle / interfaces-
// at-bottom regardless of which contracts happen to be in it.
//
// Returns: { positions: Map<address, {x,y}>, width, height }
// All coords are relative to the group container's origin; React Flow
// adds the parent offset.
export function layoutGroupInterior(kids, machines, headerHeight = GROUP_PADDING_TOP) {
  if (!kids || kids.length === 0) {
    return { positions: new Map(), width: Math.max(CHILD_W + 2 * GROUP_PADDING_SIDE, GROUP_MIN_WIDTH), height: headerHeight + GROUP_PADDING_BOTTOM };
  }

  const machineByAddr = new Map();
  for (const m of machines || []) {
    if (m.address) machineByAddr.set(m.address.toLowerCase(), m);
  }

  // Bucket into bands using the multi-signal classifier (role +
  // has_timelock + control_model). See bandFor for why role alone isn't
  // enough.
  const bands = [[], [], []];
  for (const kid of kids) {
    const m = machineByAddr.get(kid.id?.toLowerCase());
    bands[bandFor(m)].push({
      id: kid.id,
      tvl: m?.total_usd || 0,
      name: m?.name || kid.id || "",
    });
  }

  // Sort each band: TVL desc → name asc. TVL surfaces money-holding
  // contracts at the front of their row; name tie-break keeps the
  // layout stable across re-renders.
  for (const list of bands) {
    list.sort((a, b) => (b.tvl - a.tvl) || a.name.localeCompare(b.name));
  }

  // Pick a column count for each band that keeps the band's aspect
  // close to the 1.6 target the outer rectpacking uses. For small
  // bands (≤4 items) prefer a single row — squashing 3 contracts into
  // 2x2 feels arbitrary.
  function chooseCols(count) {
    if (count <= 4) return count;
    return Math.max(1, Math.floor(Math.sqrt(count * 1.6)));
  }

  const bandPlans = bands.map((list) => {
    if (list.length === 0) return null;
    const cols = chooseCols(list.length);
    const rows = Math.ceil(list.length / cols);
    return {
      list,
      cols,
      rows,
      width: cols * CHILD_W + (cols - 1) * CHILD_H_GAP,
      height: rows * CHILD_H + (rows - 1) * CHILD_V_GAP,
    };
  });

  // Group interior width = widest band's width, floored so the Controllers
  // accordion row fits (see GROUP_MIN_WIDTH). Each band is centred within that
  // width so the layout looks balanced regardless of role distribution — and a
  // narrow card band sits centered in the accordion-driven width.
  const bandW = Math.max(0, ...bandPlans.filter(Boolean).map((b) => b.width));
  const interiorW = Math.max(bandW, GROUP_MIN_WIDTH - 2 * GROUP_PADDING_SIDE);
  const totalWidth = interiorW + 2 * GROUP_PADDING_SIDE;

  const positions = new Map();
  let curY = headerHeight + GROUP_HEADER_GAP;
  for (const plan of bandPlans) {
    if (!plan) continue;
    const offsetX = GROUP_PADDING_SIDE + (interiorW - plan.width) / 2;
    for (let i = 0; i < plan.list.length; i++) {
      const col = i % plan.cols;
      const row = Math.floor(i / plan.cols);
      positions.set(plan.list[i].id, {
        x: offsetX + col * (CHILD_W + CHILD_H_GAP),
        y: curY + row * (CHILD_H + CHILD_V_GAP),
      });
    }
    curY += plan.height + CHILD_V_GAP;
  }
  const totalHeight = (curY - CHILD_V_GAP) + GROUP_PADDING_BOTTOM;

  return { positions, width: totalWidth, height: totalHeight };
}
