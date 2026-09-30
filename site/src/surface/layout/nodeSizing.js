// Group chrome, band assignment and interior layout. The constants must track
// layout.css together.

// The top reservation holds the primary bar plus the collapsed accordion.
// groupHeaderHeight() is only the first-frame estimate: GroupNode reports the
// measured band (clipped until then, so a wrong estimate never overlaps).
// Children are sized slightly larger than rendered so dense rows don't touch.
const GROUP_HEADER_BAR_H = 62; // coloured primary bar (badge row + count)
const GROUP_ACC_LABEL_H = 26; // "Controllers" eyebrow strip
const GROUP_ACC_ROW_H = 32; // one collapsed controller row (~.ps-ctrl-head + margin)
const GROUP_ACC_PAD_BOTTOM = 10;
export function groupHeaderHeight(numControllers) {
  return GROUP_HEADER_BAR_H + GROUP_ACC_LABEL_H + numControllers * GROUP_ACC_ROW_H + GROUP_ACC_PAD_BOTTOM;
}

const GROUP_PADDING_TOP = groupHeaderHeight(1);
const GROUP_PADDING_SIDE = 24;
const GROUP_PADDING_BOTTOM = 24;
// A row's fixed parts need ~350px; narrow groups would crop it.
const GROUP_MIN_WIDTH = 440;
// The band sits inside the 2px border while children position from the outer
// edge.
const GROUP_HEADER_GAP = 28;
// Long names stretch cards to ~250px; a smaller cell made neighbours overlap.
export const CHILD_W = 260;
export const CHILD_H = 130;
export const PRINCIPAL_W = 140;
export const PRINCIPAL_H = 60;

// Bands: 0 = control surfaces, 1 = value-bearing, 2 = interfaces & plumbing.
// `role` alone misfiles timelock-style admins that move value, so has_timelock
// and control_model=governance win.
function bandFor(m) {
  if (!m) return 2;
  // `=== true`: the flag is three-state, and null must not share proven-false's
  // outcome.
  if (m.has_timelock === true) return 0;
  if (m.control_model === "governance") return 0;
  if (m.role === "governance") return 0;
  // Some control contracts (TimelockController, BoringGovernance) end up
  // value_handler; the name catches them, and is the only signal when
  // `has_timelock` is null.
  const nameLower = (m.name || "").toLowerCase();
  if (/timelock|governance|guardian/.test(nameLower)) return 0;
  // Band 2 is a positive claim; a role reached through nothing but nulls takes
  // the neutral band 1.
  if (m.role_evidence === "not_determined") return 1;
  if (m.role === "token" || m.role === "factory" || m.role === "utility") return 2;
  return 1;
}

// Generous so trunks stay readable and selection labels have room.
const CHILD_H_GAP = 50;
const CHILD_V_GAP = 70;

// Bands top to bottom, each sorted by TVL and centred. Returns { positions,
// width, height } relative to the group.
export function layoutGroupInterior(kids, machines, headerHeight = GROUP_PADDING_TOP) {
  if (!kids || kids.length === 0) {
    return { positions: new Map(), width: Math.max(CHILD_W + 2 * GROUP_PADDING_SIDE, GROUP_MIN_WIDTH), height: headerHeight + GROUP_PADDING_BOTTOM };
  }

  const machineByAddr = new Map();
  for (const m of machines || []) {
    if (m.address) machineByAddr.set(m.address.toLowerCase(), m);
  }

  const bands = [[], [], []];
  for (const kid of kids) {
    const m = machineByAddr.get(kid.id?.toLowerCase());
    bands[bandFor(m)].push({
      id: kid.id,
      tvl: m?.total_usd || 0,
      name: m?.name || kid.id || "",
    });
  }

  // Name tie-break keeps the layout stable.
  for (const list of bands) {
    list.sort((a, b) => (b.tvl - a.tvl) || a.name.localeCompare(b.name));
  }

  // Near the outer packing's 1.6 aspect; ≤4 items stay one row.
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

  // Floored by GROUP_MIN_WIDTH; bands centred within it.
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
