import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { expect, test } from "@playwright/test";

// Full, real OIDC round trip against an actually-running Keycloak — no
// mocks, no MIRAGE_E2E_FIXTURE, no /test-fixture route. This is the one
// test in the repo that proves the dashboard <-> Keycloak wiring itself
// (redirect URIs, cookies, PKCE, session) is correct end to end, not just
// that the UI renders correctly given a trusted session (that's
// tests/e2e/dashboard.spec.ts's job).
//
// Requires the full stack up and Keycloak bootstrapped first:
//   make compose-up && .venv/bin/python scripts/bootstrap-keycloak-realm
//   make dev-auth-doctor   # confirms the above before you spend time here
//
// The dev-user password is never a hardcoded literal here (that was F-02: a
// single shared password committed to tracked source) — bootstrap-keycloak-realm
// generates a random one per machine and writes it to
// .dev-auth-keys/dev-credentials.json (gitignored); this test reads the same
// file so it always matches whatever Keycloak was actually bootstrapped with.
const DEV_CREDENTIALS_PATH = path.resolve(
  __dirname, "..", "..", "..", ".dev-auth-keys", "dev-credentials.json",
);

function readGeneratedDevPassword(): string | undefined {
  if (!existsSync(DEV_CREDENTIALS_PATH)) return undefined;
  const parsed = JSON.parse(readFileSync(DEV_CREDENTIALS_PATH, "utf-8"));
  return typeof parsed.password === "string" ? parsed.password : undefined;
}

const USERNAME = process.env.MIRAGE_E2E_AUTH_USERNAME ?? "dev-platform-admin";
const PASSWORD = process.env.MIRAGE_E2E_AUTH_PASSWORD ?? readGeneratedDevPassword();
const SCREENSHOT_PATH =
  process.env.MIRAGE_E2E_AUTH_SCREENSHOT ?? "test-results/dashboard-after-login.png";

if (!PASSWORD) {
  throw new Error(
    "No dev-user password available: set MIRAGE_E2E_AUTH_PASSWORD, or run " +
      "`.venv/bin/python scripts/bootstrap-keycloak-realm` first to generate " +
      `${DEV_CREDENTIALS_PATH}.`,
  );
}

test("landing -> sign in -> Keycloak -> callback -> dashboard -> refresh -> logout -> login again", async ({
  page,
}) => {
  // 1. Landing page, unauthenticated.
  await page.goto("/");
  const signInLink = page.getByRole("link", { name: "Sign in with Keycloak" });
  await expect(signInLink).toBeVisible();
  await expect(signInLink).toHaveAttribute("href", "/api/auth/login");

  // 2. Click through to the real Keycloak credential page.
  await signInLink.click();
  await expect(page).toHaveURL(/\/realms\/mirage\/protocol\/openid-connect\/auth/);
  await expect(page.getByRole("heading", { name: "Sign in to your account" })).toBeVisible();

  // 3. Real credentials, real Keycloak form submission.
  await page.getByLabel("Username or email").fill(USERNAME);
  await page.getByLabel("Password", { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: "Sign In" }).click();

  // 4. Successful callback lands back on the dashboard, authenticated.
  await expect(page).toHaveURL(new RegExp(`^${page.url().split("/").slice(0, 3).join("/")}/?$`));
  await expect(page.getByText("MIRAGE", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Log out" })).toBeVisible();
  await expect(signInLink).not.toBeVisible();

  const sessionAfterLogin = await page.request.get("/api/auth/session");
  expect(sessionAfterLogin.ok()).toBe(true);
  const sessionBody = await sessionAfterLogin.json();
  expect(sessionBody.authenticated).toBe(true);
  expect(sessionBody.user.username).toBe(USERNAME);
  expect(sessionBody.user.roles).toContain("platform_admin");

  await page.screenshot({ path: SCREENSHOT_PATH, fullPage: true });

  // 5. Refresh stays logged in (the encrypted __Host- session cookie survives
  // a full page reload — this is exactly the bug that was previously broken
  // by the Secure-flag gap on __Host- prefixed cookies).
  await page.reload();
  await expect(page.getByRole("button", { name: "Log out" })).toBeVisible();
  await expect(signInLink).not.toBeVisible();

  // 6. Logout through the real app flow (CSRF-protected POST, then the
  // Keycloak end-session redirect), landing back on the unauthenticated
  // page.
  await page.getByRole("button", { name: "Log out" }).click();
  await expect(signInLink).toBeVisible();
  const sessionAfterLogout = await page.request.get("/api/auth/session");
  expect(sessionAfterLogout.status()).toBe(401);

  // 7. Login again — proves the login route's stale-cookie clearing means a
  // second full cycle in the same browser works exactly like the first,
  // rather than getting confused by leftover state/verifier/session cookies.
  await signInLink.click();
  await expect(page.getByRole("heading", { name: "Sign in to your account" })).toBeVisible();
  await page.getByLabel("Username or email").fill(USERNAME);
  await page.getByLabel("Password", { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: "Sign In" }).click();
  await expect(page.getByRole("button", { name: "Log out" })).toBeVisible();
});
