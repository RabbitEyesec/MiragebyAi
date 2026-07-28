import { defineConfig, devices } from "@playwright/test";

// Real, unmocked OIDC login flow — separate from playwright.config.ts, which
// tests UI behavior against a MIRAGE_E2E_FIXTURE-mocked session/API and spins
// up its own ephemeral dev server. This config runs against whatever is
// already up (see Makefile: `make compose-up` + `scripts/bootstrap-keycloak-realm`,
// or a plain `npm run dev` on the canonical port) — never a mock, never a
// fixture route, never a spawned server of its own. Run scripts/dev-auth-doctor
// first if this fails in a way that looks like misconfiguration rather than a
// genuine bug.
export default defineConfig({
  testDir: "./tests/e2e-auth",
  timeout: 30_000,
  retries: 0,
  use: {
    baseURL: process.env.MIRAGE_DASHBOARD_URL ?? "http://localhost:3001",
    trace: "retain-on-failure",
    screenshot: "on",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
