import { defineConfig } from "@playwright/test";
import base from "./playwright.config.js";
export default defineConfig({
  ...base,
  use: {
    ...base.use,
    proxy: { server: "http://127.0.0.1:1", bypass: "127.0.0.1,localhost" },
  },
  webServer: {
    command: "npm run dev -- --config vite.offline.config.js",
    url: "http://127.0.0.1:5173",
    reuseExistingServer: false,
    timeout: 15000,
  },
});
