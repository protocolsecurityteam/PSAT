// Common /api mock set for component render tests (extracted from the old
// src/components.test.jsx when its suites moved beside their subjects).
import { setFetchHandler } from "./fetchMock.js";
import { ETHERFI_COMPANY, COVERAGE_FIXTURE, ADDRESS_LABELS } from "./fixtures.js";

export function installCommonApiMocks() {
  setFetchHandler(/^\/api\/address_labels$/, () => ADDRESS_LABELS);
  setFetchHandler(
    (url) => /^\/api\/company\/[^/]+$/.test(url.pathname),
    () => ETHERFI_COMPANY,
  );
  setFetchHandler(
    (url) => /^\/api\/company\/[^/]+\/audit_coverage$/.test(url.pathname),
    () => COVERAGE_FIXTURE,
  );
  setFetchHandler(
    (url) => /^\/api\/company\/[^/]+\/audits$/.test(url.pathname),
    () => ({ audit_count: 0, audits: [] }),
  );
  setFetchHandler(
    (url) => /^\/api\/contracts\/[^/]+\/audit_timeline$/.test(url.pathname),
    () => ({ current_status: "unknown", coverage: [] }),
  );
  setFetchHandler(/^\/api\/audits\/.*\/scope$/, () => ({ contracts: [] }));
  setFetchHandler(/^\/api\/audits\/.*\/text$/, () => "");
  setFetchHandler(/^\/api\/audits\/[0-9]+$/, () => ({ id: 1 }));
  setFetchHandler(/^\/api\/audits\/pipeline$/, () => ({ groups: [], recent_completed: [] }));
}
