---
name: PSAT
description: A restrained dark evidence ledger for protocol authority, state, and change.
colors:
  canvas-deep: "#03050a"
  canvas: "#0b0f16"
  canvas-soft: "rgba(17, 22, 32, 0.74)"
  panel: "#111620"
  rule: "rgba(148, 163, 184, 0.10)"
  rule-strong: "rgba(148, 163, 184, 0.14)"
  ink: "#e2e8f0"
  ink-secondary: "#cbd5e1"
  muted: "#94a3b8"
  observed: "#2dd4bf"
  observed-text: "#99f6e4"
  observed-soft: "rgba(45, 212, 191, 0.12)"
  scenario: "#f59e0b"
  scenario-text: "#fcd68a"
  scenario-strong: "#fbbf24"
  scenario-soft: "rgba(245, 158, 11, 0.14)"
  success: "#22c55e"
  danger: "#ef4444"
  danger-text: "#fecaca"
  info: "#38bdf8"
  status-muted: "#64748b"
typography:
  display:
    fontFamily: "Instrument Sans, Inter, system-ui, sans-serif"
    fontSize: "2.65rem"
    fontWeight: 700
    lineHeight: 1.1
    letterSpacing: "-0.035em"
  headline:
    fontFamily: "Space Grotesk, Instrument Sans, system-ui, sans-serif"
    fontSize: "1.22rem"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "-0.02em"
  body:
    fontFamily: "Instrument Sans, Inter, system-ui, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.6
    letterSpacing: "normal"
  label:
    fontFamily: "Instrument Sans, Inter, system-ui, sans-serif"
    fontSize: "0.7rem"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "0.08em"
  mono:
    fontFamily: "JetBrains Mono, SFMono-Regular, Consolas, monospace"
    fontSize: "0.74rem"
    fontWeight: 400
    lineHeight: 1.4
    letterSpacing: "normal"
rounded:
  compact: "4px"
  label: "6px"
  control: "8px"
  nav: "10px"
  action: "12px"
  panel: "20px"
  pill: "999px"
spacing:
  xs: "4px"
  sm: "8px"
  control: "10px"
  md: "14px"
  lg: "18px"
  xl: "24px"
  section: "32px"
components:
  button-primary:
    backgroundColor: "linear-gradient(180deg, #34e4cc, #14b8a6)"
    textColor: "#06110f"
    typography: "{typography.body}"
    rounded: "{rounded.action}"
    padding: "10px 16px"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    typography: "{typography.body}"
    rounded: "{rounded.action}"
    padding: "10px 16px"
  input:
    backgroundColor: "rgba(10, 14, 20, 0.85)"
    textColor: "{colors.ink}"
    typography: "{typography.body}"
    rounded: "{rounded.action}"
    padding: "12px 14px"
  nav-active:
    backgroundColor: "{colors.observed-soft}"
    textColor: "{colors.observed}"
    typography: "{typography.body}"
    rounded: "{rounded.nav}"
    padding: "6px 14px"
  chip-observed:
    backgroundColor: "{colors.observed-soft}"
    textColor: "{colors.observed-text}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "5px 8px"
  chip-scenario:
    backgroundColor: "{colors.scenario-soft}"
    textColor: "{colors.scenario-text}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "5px 8px"
  panel:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink}"
    rounded: "{rounded.panel}"
    padding: "20px"
  comparison-record:
    backgroundColor: "transparent"
    textColor: "{colors.ink-secondary}"
    typography: "{typography.body}"
    rounded: "{rounded.compact}"
    padding: "16px 14px"
---

# Design System: PSAT

## Overview

**Creative North Star: "The Investigation Ledger"**

PSAT is a restrained dark analytical workspace: dense enough for protocol review, but ordered so scope, consequence, and proof remain easy to scan. Fine rules and tonal surface shifts carry most of the structure; bright color is scarce and therefore meaningful.

The interface treats data provenance as a visual property. Observed state, hypothetical scenarios, warnings, and failures remain textually labeled as well as colored, while addresses, claim identifiers, and exact values use mono type. Proposal impact extends this incumbent world with comparison-first tables and disclosures placed directly beside the claims they substantiate.

**Key Characteristics:**

- Dark, low-glare analytical canvases with quiet panel separation.
- Compact labels, tabular numerals, and mono evidence values.
- Teal observed-state semantics and amber scenario semantics.
- Fine rules and inline disclosure instead of decorative framing.
- Responsive records that preserve labels and provenance on small screens.

## Colors

The palette is cool, near-black, and deliberately quiet; semantic accents are reserved for state and evidence rather than decoration.

### Primary

- **Observed Teal:** Marks observed scope, active navigation, proof actions, and focus. Its light text partner maintains legibility on the translucent teal wash.

### Secondary

- **Scenario Amber:** Marks proposed values, hypothetical scope, fixtures, warnings, and coverage limitations. The stronger amber is used for compact warning labels.

### Neutral

- **Deep Canvas and Canvas:** Form the page and application-shell ground.
- **Panel and Soft Canvas:** Separate controls and containers without turning every region into a card.
- **Ink and Secondary Ink:** Carry primary and supporting content on dark surfaces.
- **Muted Ink:** Carries metadata, descriptions, labels, and inactive controls.
- **Rules:** Use low-alpha blue-gray strokes for tables, dividers, and panel boundaries.

### Named Rules

**The Scope Before Color Rule.** Every semantic color must be accompanied by an explicit word such as Observed, Scenario, Warning, or Error; hue never carries provenance alone.

**The Two Truths Rule.** Teal means observed or evidentiary state. Amber means hypothetical change or caution. Never style a scenario result as current state.

## Typography

**Display Font:** Instrument Sans (with Inter and system fallbacks)  
**Body Font:** Instrument Sans (with Inter and system fallbacks)  
**Label/Mono Font:** JetBrains Mono (with platform mono fallbacks)

**Character:** Instrument Sans keeps dense analytical prose neutral and legible. Space Grotesk appears on established application headings and brand moments, while JetBrains Mono separates machine identifiers and exact values from explanatory text.

### Hierarchy

- **Display:** A compact, tightly tracked page title used once at the top of an analytical surface; it reduces on mobile.
- **Headline:** Short section and panel headings with modest negative tracking.
- **Body:** Explanations and state copy, generally capped near 68–72 characters and set with an open line height.
- **Label:** Small, bold, uppercase table headers and field labels with wide tracking.
- **Mono:** Addresses, hashes, claim IDs, and machine-shaped values; allow wrapping rather than truncating evidence.

### Named Rules

**The Identifier Voice Rule.** Use mono type for values users may compare, trace, or copy. Keep narrative conclusions in the sans-serif body face.

## Layout

Application pages use centered desktop containers in the 1400–1480px range with 24–32px side padding. Sections are separated by generous vertical intervals, while the content inside a table, control, or evidence record stays compact. Headers pair a title-and-description block with a small contextual control or legend.

Proposal comparisons remain true tables on desktop so baseline, proposed value, scope, and derivation share one scan line. At 760px and below, the header and section controls stack, the table header is removed, and each row becomes a two-column labeled record using its visible `data-label`; value, baseline, proposed, and derivation fields span both columns. Proof values collapse to a single column, trace sections stack, and no horizontal clipping is required.

**The Same Evidence Rule.** Responsive transformations may change arrangement, never labels, order, scope, or access to proof.

## Elevation & Depth

The analytical surfaces are flat by default. Fine borders, near-black tonal shifts, and occasional translucency establish hierarchy; the application shell, overlays, and large established panels may use ambient dark shadows. Proposal tables and inline records use no resting shadow.

### Shadow Vocabulary

- **Ambient Panel:** A broad dark shadow for established floating panels and cards.
- **Strong Overlay:** A deeper broad shadow for modals and overlays.
- **Sticky Navigation:** A shallow shadow beneath the blurred top bar.
- **Focus Halo:** A teal outline or soft ring reserved for keyboard focus.

### Named Rules

**The Flat Evidence Rule.** Keep tables, traces, limitations, and empty states on the page plane; use rules and spacing, not card shadows, to separate evidence.

## Shapes

The shell uses gently rounded controls and larger rounded panels, but evidence-heavy interiors tighten to small radii or straight dividers. Status and scope labels are pills. Circular geometry is reserved for tiny legend dots, status marks, and icon controls rather than content containers.

## Components

### Buttons

- **Shape:** Confident rounded action controls, with compact padding and no ornamental icon requirement.
- **Primary:** A bright teal vertical gradient with dark text and bold weight.
- **Hover / Focus:** Primary buttons rise by one pixel on hover; focusable analytical controls use a visible teal outline or halo.
- **Ghost:** Transparent with a quiet blue-gray border and light text.
- **Error action:** Transparent red-tinted treatment that does not lift on hover.

### Chips

- **Observed scope:** Teal text on a translucent teal pill, always including the word Observed and its exact block when available.
- **Scenario scope:** Amber text on a translucent amber pill, always including Scenario and the ordered step.
- **Reported scope:** Neutral ink on a muted translucent pill.

### Cards / Containers

- **Corner Style:** Large panels use soft 20px corners; embedded analytical records use tighter corners or rule-only separation.
- **Background:** Dark tonal gradients or the panel tone.
- **Shadow Strategy:** Ambient only on established floating panels; evidence tables stay flat.
- **Border:** One-pixel low-alpha blue-gray rules.
- **Internal Padding:** Approximately 20–22px for general panels; denser evidence regions use 10–16px.

### Inputs / Fields

- **Style:** Dark translucent fill, quiet border, 12px corner radius, and full-width behavior in forms.
- **Focus:** Teal border shift with a soft four-pixel halo; scoped proposal selects use a two-pixel teal outline with offset.
- **Error / Disabled:** Disabled controls retain form and reduce opacity; error actions use red text and borders.

### Navigation

The sticky 52px top bar uses a blurred dark gradient, a compact Space Grotesk wordmark, muted default links, and a teal-wash active state. Company context appears as a small neutral label. The hamburger preserves the same dark shell and compact navigation vocabulary on narrow screens.

### Comparison Table / Mobile Record

Desktop comparison tables use uppercase tracked headers, tabular numerals, fine row rules, and a barely visible row hover. Baseline values stay neutral; proposed values use scenario amber. On mobile, every cell prints its own label, the row becomes a two-column grid, and long evidence fields span the full width.

### Proof and Trace Disclosures

Proof is one expansion away in the same row as the claim. The disclosure opens to claim, evidence, and prerequisite records with identifiers and scope intact. A section-level trace disclosure follows scenario context and exposes ordered actions, assumptions, and downstream claims in three desktop columns or one mobile column.

### Loading, Error, and Empty States

Loading uses quiet full-width skeleton rows beneath explicit loading copy. Errors use a live alert, explain that no empty-state conclusion was inferred, and provide a visible retry action. Empty states are bounded by rules and state exactly which collection or scenario step is missing; proposal-empty and observed-claims-empty remain distinct. Coverage limitations appear last as labeled records rather than disappearing into an empty result.

## Do's and Don'ts

### Do:

- **Do** put the scope legend before the first comparison value.
- **Do** keep baseline, proposed value, scenario step, and proof available in the same comparison record.
- **Do** retain explicit labels, tabular numerals, and traceability when a table becomes a mobile record.
- **Do** place limitations after the observed record and state unsupported coverage directly.
- **Do** preserve keyboard focus, semantic table markup on desktop, disclosure controls, live loading copy, and alert roles.

### Don't:

- **Don't** let teal and amber become interchangeable decorative accents.
- **Don't** present a failed or unknown API response as an empty analysis.
- **Don't** hide proof, prerequisites, assumptions, or downstream claims in a detached modal when they can remain inline.
- **Don't** force horizontal table scrolling on the proposal-impact mobile layout.
- **Don't** invent production proposal data or imply that synthetic fixture data is observed.
