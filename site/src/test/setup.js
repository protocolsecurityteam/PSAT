// vitest setup — runs before every test file. Configures the jsdom
// environment so React components that depend on browser APIs not in
// jsdom (ResizeObserver, IntersectionObserver, matchMedia, fetch) don't
// crash on first render. Also installs the @testing-library/jest-dom
// matchers so tests can use toBeInTheDocument(), toHaveTextContent(),
// etc.
//
// All of this is *test-only* — production code is unchanged.

import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";

import { resetFetchMock } from "./fetchMock.js";

// React Flow + ELK measure DOM nodes via ResizeObserver. jsdom doesn't
// implement it, so we provide a no-op shim — measurements come back as
// zero, which is fine for "did the page render" assertions.
class NoopResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

class NoopIntersectionObserver {
  constructor() {
    this.root = null;
    this.rootMargin = "";
    this.thresholds = [];
  }
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() { return []; }
}

if (typeof window !== "undefined") {
  if (!window.ResizeObserver) window.ResizeObserver = NoopResizeObserver;
  if (!window.IntersectionObserver) window.IntersectionObserver = NoopIntersectionObserver;
  if (!window.matchMedia) {
    window.matchMedia = (query) => ({
      matches: false,
      media: query,
      addEventListener() {},
      removeEventListener() {},
      addListener() {},
      removeListener() {},
      dispatchEvent() { return false; },
      onchange: null,
    });
  }
  // React Flow calls scrollTo on its viewport; jsdom only stubs window.scrollTo.
  if (!Element.prototype.scrollTo) {
    Element.prototype.scrollTo = function scrollTo() {};
  }
  // jsdom's getBoundingClientRect returns all zeros — fine. But React Flow
  // also reads getBBox on SVG; jsdom returns undefined. Provide a stub.
  if (typeof SVGElement !== "undefined" && !SVGElement.prototype.getBBox) {
    SVGElement.prototype.getBBox = function getBBox() {
      return { x: 0, y: 0, width: 0, height: 0 };
    };
  }
}

beforeEach(() => {
  resetFetchMock();
  // Reset URL to a clean state so each test starts at "/".
  window.history.replaceState({}, "", "/");
  // Clear the admin key so each test starts as a non-admin (keyless); tests
  // that exercise operator controls set "psat_admin_key" explicitly.
  window.localStorage.clear();
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});
