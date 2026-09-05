import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  testMatch: "cloudflare-boundary.spec.js",
  use: { baseURL: "http://127.0.0.1:5175", headless: true },
  webServer: {
    command: "env -i PATH=\"$PATH\" HOME=\"$HOME\" PYTHONPATH=.. PYTHON_DOTENV_DISABLED=1 PSAT_CLOUDFLARE_BROWSER_FIXTURE=1 PSAT_EDGE_MODE=cloudflare PSAT_ORIGIN_SECRET=" + "a".repeat(64) +
      " PSAT_ACCESS_ISSUER=https://test-team.cloudflareaccess.com PSAT_ACCESS_AUDIENCE=" + "b".repeat(64) +
      " PSAT_ACCESS_EMAILS=operator@example.com PSAT_ADMIN_KEY=test-admin-key DATABASE_URL=postgresql://psat:psat@127.0.0.1:5433/psat_test ERPC_BASE_URL=http://erpc.invalid ../.venv/bin/uvicorn --app-dir e2e/fixtures cloudflare_origin:app --host 127.0.0.1 --port 5175 --no-proxy-headers --lifespan off",
    url: "http://127.0.0.1:5175/api/version",
    reuseExistingServer: false,
    timeout: 15000,
  },
});
