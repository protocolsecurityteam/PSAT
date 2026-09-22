# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Protocol security reviewers and governance stakeholders inspecting smart-contract
authority, operational controls, and the downstream effects of proposed changes.

## Product Purpose

PSAT turns static analysis, chain observations, execution evidence, and governance
history into an inspectable assessment of what a protocol can do, who can do it,
and how those answers change over time or under a proposed action.

## Positioning

Every displayed conclusion is a scoped claim connected to exact evidence and
prerequisite claims. Current state, historical state, and scenarios use the same
temporal model instead of separate reports that can silently disagree.

## Operating Context

Users move between protocol-wide surfaces, contracts, functions, principals,
activity timelines, and analysis details. They need dense tabular comparisons
for proposals and the ability to expand a downstream effect into its proof path.

## Capabilities and Constraints

- Distinguish observed, historical, reported, and hypothetical results.
- Preserve prior observations and claims when state changes.
- Represent partial coverage and unsupported semantics explicitly.
- Use row-shaped records and controlled enums without public schema-version fields.
- Never treat a scenario result as observed current state.
- Keep large raw payloads content-addressed rather than duplicating them in views.

## Brand Commitments

Preserve the existing PSAT name, restrained dark analytical interface, vocabulary,
navigation model, and established component behavior.

## Evidence on Hand

The repository contains the running React application, static and temporal
Assessment schemas, policy/effects tests, proposal scenario fixtures, and browser
regression coverage. It does not contain approved production proposal data or
permission to invent deployment claims.

## Product Principles

- Show scope before confidence.
- Preserve history instead of overwriting it.
- Make downstream consequences legible as a comparison.
- Keep evidence and limitations one expansion away.
- Prefer one canonical model over synchronized replicas.

## Accessibility & Inclusion

Retain keyboard navigation, visible focus, semantic controls, reduced-motion
behavior, and non-color-only state labels already established by the application.
