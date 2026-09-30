import React, { useEffect, useRef } from "react";

/*
 * ASCII minesweeper background that becomes playable when clicked.
 *
 * Idle: auto-clicks, flags mines, and slowly re-covers old cells so it never
 * finishes.
 * Play: left-click reveals, right-click flags; a mine resets the board and
 * auto-play resumes, as it does after 25s idle.
 */

const COLS = 200;
const ROWS = 52;
const CELL_W = 20;
const CELL_H = 26;
const MINE_DENSITY = 0.13;

const CLICK_INTERVAL_MS = 750;
const AUTO_CLICKER_COUNT = 2;
const INITIAL_BURST_COUNT = 5;
const REVEAL_STAGGER_MS = 14;

const RECOVER_MIN_AGE_MS = 14000;
const RECOVER_PROB_PER_TICK = 0.025;
const RECOVER_TICK_MS = 280;
const IDLE_TIMEOUT_MS = 25000;
const GAME_OVER_HOLD_MS = 2600;

function rng(seed) {
  let s = seed | 0;
  return () => {
    s = (s + 0x6d2b79f5) | 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function makeEmptyCells() {
  const cells = [];
  for (let y = 0; y < ROWS; y++) {
    for (let x = 0; x < COLS; x++) {
      cells.push({ x, y, mine: false, count: 0 });
    }
  }
  return cells;
}

function fillBoard(cells, seed) {
  const r = rng(seed);
  for (const c of cells) {
    c.mine = r() < MINE_DENSITY;
    c.count = 0;
  }
  const get = (x, y) =>
    x < 0 || x >= COLS || y < 0 || y >= ROWS ? null : cells[y * COLS + x];
  for (const c of cells) {
    if (c.mine) continue;
    let count = 0;
    for (let dy = -1; dy <= 1; dy++) {
      for (let dx = -1; dx <= 1; dx++) {
        if (!dx && !dy) continue;
        const nb = get(c.x + dx, c.y + dy);
        if (nb && nb.mine) count++;
      }
    }
    c.count = count;
  }
  return get;
}

function cascadeReveal(start, get) {
  if (!start || start.mine) return [];
  const order = [];
  const seen = new Set();
  const queue = [start];
  while (queue.length) {
    const c = queue.shift();
    const k = `${c.x},${c.y}`;
    if (seen.has(k) || c.mine) continue;
    seen.add(k);
    order.push(c);
    if (c.count === 0) {
      for (let dy = -1; dy <= 1; dy++) {
        for (let dx = -1; dx <= 1; dx++) {
          if (!dx && !dy) continue;
          const nb = get(c.x + dx, c.y + dy);
          if (nb) queue.push(nb);
        }
      }
    }
  }
  return order;
}

const CELL_DATA = makeEmptyCells();

export default function FractalMesh() {
  const containerRef = useRef(null);

  useEffect(() => {
    const root = containerRef.current;
    if (!root) return;

    const cellEls = Array.from(root.querySelectorAll(".ms-c"));
    let getCell = fillBoard(CELL_DATA, Math.floor(Math.random() * 1e9));

    const state = CELL_DATA.map((cell, i) => ({
      cell,
      el: cellEls[i],
      status: "covered",
      revealedAt: 0,
    }));

    const ctx = {
      mode: "idle", // "idle" | "playing" | "gameover"
      lastUserActivity: 0,
      pendingTimers: [],
    };

    function setCell(idx, status, now) {
      const s = state[idx];
      s.status = status;
      s.revealedAt = now;
      const el = s.el;
      if (status === "covered") {
        el.textContent = "0";
        el.className = "ms-c covered";
      } else if (status === "revealed") {
        if (s.cell.mine) return;
        if (s.cell.count === 0) {
          el.textContent = "·";
          el.className = "ms-c empty";
        } else {
          el.textContent = String(s.cell.count);
          el.className = `ms-c num n${s.cell.count}`;
        }
      } else if (status === "flagged") {
        el.textContent = "⚑";
        el.className = "ms-c flag";
      } else if (status === "mine-revealed") {
        el.textContent = "✸";
        el.className = "ms-c mine-revealed";
      } else if (status === "mine-explosion") {
        el.textContent = "✸";
        el.className = "ms-c mine-revealed mine-explosion";
      }
    }

    function startCascade(idx, autoFlag) {
      const cell = state[idx].cell;
      const targetEl = state[idx].el;
      targetEl.classList.add("click-pulse");
      const pulseT = setTimeout(() => targetEl.classList.remove("click-pulse"), 220);
      ctx.pendingTimers.push(pulseT);

      const order = cascadeReveal(cell, getCell);
      order.forEach((c, i) => {
        const t = setTimeout(() => {
          const idx2 = c.y * COLS + c.x;
          if (state[idx2].status === "covered") {
            setCell(idx2, "revealed", performance.now());
          }
        }, i * REVEAL_STAGGER_MS);
        ctx.pendingTimers.push(t);
      });

      if (autoFlag) {
        const flagT = setTimeout(() => {
          const revealedSet = new Set(order.map((c) => `${c.x},${c.y}`));
          for (const c of CELL_DATA) {
            if (!c.mine) continue;
            let touches = false;
            for (let dy = -1; dy <= 1 && !touches; dy++) {
              for (let dx = -1; dx <= 1 && !touches; dx++) {
                if (!dx && !dy) continue;
                const nb = getCell(c.x + dx, c.y + dy);
                if (nb && revealedSet.has(`${nb.x},${nb.y}`)) touches = true;
              }
            }
            if (touches) {
              const idx2 = c.y * COLS + c.x;
              if (state[idx2].status === "covered") {
                setCell(idx2, "flagged", performance.now());
              }
            }
          }
        }, order.length * REVEAL_STAGGER_MS + 80);
        ctx.pendingTimers.push(flagT);
      }
    }

    function autoTick() {
      if (ctx.mode !== "idle") return;
      const candidates = [];
      for (let i = 0; i < state.length; i++) {
        const s = state[i];
        if (s.status === "covered" && !s.cell.mine) candidates.push(i);
      }
      if (!candidates.length) return;
      const idx = candidates[Math.floor(Math.random() * candidates.length)];
      startCascade(idx, true);
    }

    function pickCoveredInRegion(xMin, xMax, yMin, yMax) {
      const candidates = [];
      for (let y = yMin; y < yMax; y++) {
        for (let x = xMin; x < xMax; x++) {
          const i = y * COLS + x;
          const s = state[i];
          if (s && s.status === "covered" && !s.cell.mine) candidates.push(i);
        }
      }
      if (!candidates.length) return -1;
      return candidates[Math.floor(Math.random() * candidates.length)];
    }

    function initialBurst() {
      const regions = [];
      const cols = Math.ceil(Math.sqrt(INITIAL_BURST_COUNT));
      const rows = Math.ceil(INITIAL_BURST_COUNT / cols);
      for (let ry = 0; ry < rows; ry++) {
        for (let rx = 0; rx < cols; rx++) {
          if (regions.length >= INITIAL_BURST_COUNT) break;
          regions.push({
            xMin: Math.floor((rx / cols) * COLS),
            xMax: Math.floor(((rx + 1) / cols) * COLS),
            yMin: Math.floor((ry / rows) * ROWS),
            yMax: Math.floor(((ry + 1) / rows) * ROWS),
          });
        }
      }
      regions.forEach((r) => {
        const idx = pickCoveredInRegion(r.xMin, r.xMax, r.yMin, r.yMax);
        if (idx >= 0) startCascade(idx, true);
      });
    }
    initialBurst();

    function gameOver(triggeredIdx) {
      ctx.mode = "gameover";
      const now = performance.now();
      for (let i = 0; i < state.length; i++) {
        if (state[i].cell.mine) {
          setCell(i, i === triggeredIdx ? "mine-explosion" : "mine-revealed", now);
        }
      }
      const t = setTimeout(() => {
        getCell = fillBoard(CELL_DATA, Math.floor(Math.random() * 1e9));
        const resetNow = performance.now();
        for (let i = 0; i < state.length; i++) {
          setCell(i, "covered", resetNow);
        }
        ctx.mode = "idle";
      }, GAME_OVER_HOLD_MS);
      ctx.pendingTimers.push(t);
    }

    function noteUserActivity() {
      ctx.lastUserActivity = performance.now();
      if (ctx.mode === "idle") ctx.mode = "playing";
    }

    function handleClick(e) {
      const cellEl = e.target.closest && e.target.closest(".ms-c");
      if (!cellEl) return;
      if (ctx.mode === "gameover") return;
      const idx = parseInt(cellEl.dataset.idx, 10);
      noteUserActivity();
      const s = state[idx];
      if (s.status === "flagged") return;
      if (s.status !== "covered") return;
      if (s.cell.mine) {
        gameOver(idx);
        return;
      }
      startCascade(idx, false);
    }

    function handleContextMenu(e) {
      const cellEl = e.target.closest && e.target.closest(".ms-c");
      if (!cellEl) return;
      e.preventDefault();
      if (ctx.mode === "gameover") return;
      const idx = parseInt(cellEl.dataset.idx, 10);
      noteUserActivity();
      const s = state[idx];
      const now = performance.now();
      if (s.status === "covered") setCell(idx, "flagged", now);
      else if (s.status === "flagged") setCell(idx, "covered", now);
    }

    root.addEventListener("click", handleClick);
    root.addEventListener("contextmenu", handleContextMenu);

    const autoTimers = [];
    for (let i = 0; i < AUTO_CLICKER_COUNT; i++) {
      const offset = (i * CLICK_INTERVAL_MS) / AUTO_CLICKER_COUNT;
      const t = setTimeout(() => {
        autoTick();
        const interval = setInterval(autoTick, CLICK_INTERVAL_MS);
        autoTimers.push(interval);
      }, offset);
      autoTimers.push(t);
    }

    let raf;
    let lastRecoverTick = 0;
    function tick(now) {
      if (ctx.mode === "idle" && now - lastRecoverTick > RECOVER_TICK_MS) {
        lastRecoverTick = now;
        for (let i = 0; i < state.length; i++) {
          const s = state[i];
          if (s.status === "covered" || s.status === "mine-revealed" || s.status === "mine-explosion") continue;
          const age = now - s.revealedAt;
          if (age > RECOVER_MIN_AGE_MS && Math.random() < RECOVER_PROB_PER_TICK) {
            setCell(i, "covered", now);
          }
        }
      }

      if (ctx.mode === "playing" && now - ctx.lastUserActivity > IDLE_TIMEOUT_MS) {
        ctx.mode = "idle";
      }

      raf = requestAnimationFrame(tick);
    }
    raf = requestAnimationFrame(tick);

    return () => {
      root.removeEventListener("click", handleClick);
      root.removeEventListener("contextmenu", handleContextMenu);
      autoTimers.forEach((t) => {
        clearInterval(t);
        clearTimeout(t);
      });
      cancelAnimationFrame(raf);
      ctx.pendingTimers.forEach(clearTimeout);
    };
  }, []);

  // Rendered once; JS mutates textContent/className via refs.
  const cells = [];
  for (let y = 0; y < ROWS; y++) {
    for (let x = 0; x < COLS; x++) {
      const idx = y * COLS + x;
      cells.push(
        <span
          key={idx}
          className="ms-c covered"
          data-idx={idx}
          style={{
            position: "absolute",
            left: x * CELL_W,
            top: y * CELL_H,
            width: CELL_W,
            height: CELL_H,
            lineHeight: `${CELL_H}px`,
          }}
        >
          0
        </span>
      );
    }
  }

  return (
    <div className="fractal-stage ms-stage">
      <div
        className="ms-grid"
        ref={containerRef}
        style={{
          width: `${COLS * CELL_W}px`,
          height: `${ROWS * CELL_H}px`,
        }}
      >
        {cells}
      </div>
    </div>
  );
}
