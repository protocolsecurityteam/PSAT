import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  testIgnore: "**/cloudflare-boundary.spec.js",
  timeout: 30000,
  use: {
    baseURL: "http://127.0.0.1:5173",
    headless: true,
    // CI runs in UTC; pinned so baselines never carry the local zone or locale.
    timezoneId: "UTC",
    locale: "en-US",
  },
  webServer: {
    command: "npm run dev -- --port 5173",
    port: 5173,
    reuseExistingServer: true,
    timeout: 15000,
  },
});
