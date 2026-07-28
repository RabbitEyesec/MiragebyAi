import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/e2e",
  timeout: 30_000,
  retries: 1,
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL ?? "http://127.0.0.1:33119",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: process.env.PLAYWRIGHT_BASE_URL
    ? undefined
    : {
        // Invokes `next dev` directly (not the "dev" npm script, which now
        // pins -p 3001 for the canonical manual-dev workflow) so this
        // fixture server's own explicit --port isn't shadowed by that.
        command:
          "MIRAGE_E2E_FIXTURE=1 npx next dev --hostname 127.0.0.1 --port 33119",
        url: "http://127.0.0.1:33119",
        reuseExistingServer: false,
      },
});
