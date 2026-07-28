import { expect, type Page, test } from "@playwright/test";

import { caseId, evidenceId, model } from "../fixtures";

const user = {
  subject: "e2e-user",
  username: "e2e-investigator",
  roles: [
    "platform_admin",
    "investigator",
    "operator",
    "auditor",
    "read_only",
    "export",
    "direct_intervention",
    "emergency_control",
  ],
  expiresAt: 4102444800,
};

async function mockApi(page: Page, options: { degraded?: boolean } = {}) {
  let streamConnections = 0;
  await page.route("**/api/auth/session", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ authenticated: true, user, csrfToken: "e2e-csrf" }),
    }),
  );
  await page.route("**/api/mirage/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    if (path.endsWith("/dashboard/stream")) {
      streamConnections += 1;
      const update = {
        update_id: `update-${streamConnections}`,
        update_type: "CASE_UPDATED",
        case_id: caseId,
        projection_version: 5,
        event_time: "2026-07-26T10:00:03Z",
        payload: {},
        correlation_id: `corr-${streamConnections}`,
      };
      return route.fulfill({
        status: 200,
        contentType: "text/event-stream",
        body: `id: ${streamConnections}\nevent: CASE_UPDATED\ndata: ${JSON.stringify(update)}\n\n`,
      });
    }
    if (path.endsWith("/dashboard/cases")) {
      return route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({
          cases: [
            {
              case_id: caseId,
              state: "ENGAGING",
              version: 7,
              severity: "HIGH",
              owner: "e2e-investigator",
              created_at: "2026-07-26T10:00:00Z",
            },
          ],
        }),
      });
    }
    if (path.endsWith("/dashboard/operations")) {
      if (options.degraded) {
        return route.fulfill({
          status: 503,
          contentType: "application/json",
          body: JSON.stringify({ detail: "dependency unavailable" }),
        });
      }
      return route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({
          platform_health: "HEALTHY",
          open_cases: 1,
          cases_by_state: { ENGAGING: 1 },
          cases_by_severity: { HIGH: 1 },
          recent_operational_alerts: [],
        }),
      });
    }
    if (path.endsWith(`/dashboard/cases/${caseId}`)) {
      return route.fulfill({ contentType: "application/json", body: JSON.stringify(model) });
    }
    if (path.endsWith(`/cases/${caseId}/directive`) && route.request().method() === "POST") {
      return route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({
          directive_id: "directive-e2e",
          status: "SUBMITTED",
          objective: "Observe the next authentication attempt",
        }),
      });
    }
    if (path.endsWith("/evidence-board")) {
      return route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({
          evidence: [
            {
              evidence_id: evidenceId,
              type: "LOG",
              filename: "activity.log",
              media_type: "text/plain",
              size_bytes: 12,
              sha256: "a".repeat(64),
              source: "spider",
              sequence: 3,
              certificate_serial: "serial",
              acquisition_time: "2026-07-26T10:00:00Z",
              s3_version_id: "version-1",
              object_lock: { mode: "GOVERNANCE", retention_until: "2026-08-26T10:00:00Z" },
              verification_status: "VERIFIED",
              classification: "SENSITIVE",
              related_events: [],
              related_graph_nodes: [],
              export_inclusion: true,
            },
          ],
        }),
      });
    }
    if (path.endsWith("/ai-state")) {
      return route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({
          status: "AVAILABLE",
          proposal: {
            strategy_phase: "ENGAGE",
            action_type: "PLACE_ARTIFACT",
            rationale: "Evidence-backed inference",
            confidence: 0.8,
            supporting_event_ids: [model.timeline[0].source_event_ids[0]],
          },
          snapshot: {
            snapshot_hash: "b".repeat(64),
            size_bytes: 1024,
            estimated_tokens: 256,
            trimmed_fields: [],
          },
          policy: { decision: "ALLOW", reason_codes: ["APPROVED_INERT"] },
          cost_gbp: "0.024",
        }),
      });
    }
    if (path.endsWith(`/cases/${caseId}/messages/preview`)) {
      return route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({
          preview_hash: "c".repeat(64),
          confirmation_required: true,
          content: "The controlled session is ready.",
          surface: "DECOY_WEB_CHAT",
        }),
      });
    }
    if (path.endsWith(`/cases/${caseId}/messages`) && route.request().method() === "POST") {
      return route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({
          message_id: "message-e2e",
          status: "PENDING_CONFIRMATION",
          preview_hash: "c".repeat(64),
          confirmation_required: true,
        }),
      });
    }
    if (path.endsWith(`/cases/${caseId}/messages/message-e2e/confirm`)) {
      return route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({ message_id: "message-e2e", status: "APPROVED" }),
      });
    }
    if (path.endsWith("/sandbox-state")) {
      return route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({
          sandbox: {
            sandbox_id: "sandbox-e2e",
            image_id: "ami-approved",
            state: "ACTIVE",
            state_version: 2,
            spider_status: "HEALTHY",
            controller_status: "HEALTHY",
            agent_status: "HEALTHY",
          },
          action_journal: [],
        }),
      });
    }
    if (path.endsWith("/reports")) {
      return route.fulfill({ contentType: "application/json", body: JSON.stringify({ reports: [] }) });
    }
    return route.fulfill({ status: 404, contentType: "application/json", body: JSON.stringify({ detail: "not mocked" }) });
  });
  return () => streamConnections;
}

test("login entry uses Keycloak and explains secure session storage", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("link", { name: "Sign in with Keycloak" })).toHaveAttribute(
    "href",
    "/api/auth/login",
  );
  await expect(page.getByText(/No access token is stored in localStorage/)).toBeVisible();
});

test("analyst operates all six workspaces and 2D/3D canonical pivots", async ({ page }) => {
  const streamConnections = await mockApi(page);
  await page.goto("/test-fixture");
  await expect(page.getByText("Control plane")).toBeVisible();
  await page.getByRole("button", { name: /Investigation/ }).click();
  await expect(page.getByText("Facts, correlation, inference, and action")).toBeVisible();
  await page.getByLabel("Objective").fill("Observe the next authentication attempt");
  await page.getByRole("button", { name: "Submit directive" }).click();
  await expect(page.getByText("SUBMITTED: directive-e2e")).toBeVisible();
  await expect(page.getByText("Cytoscape 2D")).toBeVisible();
  await page.getByRole("button", { name: "3D" }).click();
  await expect(page.getByText("Three.js 3D")).toBeVisible();

  await page.getByRole("button", { name: /Evidence Board/ }).click();
  await expect(page.getByText("activity.log")).toBeVisible();
  await expect(page.getByText("VERIFIED")).toBeVisible();

  await page.getByRole("button", { name: /AI Interaction/ }).click();
  await expect(page.getByText("AI inference — not observed fact")).toBeVisible();
  await expect(page.getByText("PLACE_ARTIFACT")).toBeVisible();
  await page.getByLabel("Session ID").fill("session-e2e");
  await page.getByLabel("ALLOW policy decision ID").fill("policy-e2e");
  await page.getByLabel("Message").fill("The controlled session is ready.");
  await page.getByRole("button", { name: "Prepare direct message" }).click();
  await expect(page.getByText(/Exact preview/)).toBeVisible();
  await page.getByRole("button", { name: "Create pending message" }).click();
  await expect(page.getByText("Message message-e2e: PENDING_CONFIRMATION")).toBeVisible();
  await page.getByRole("button", { name: "Confirm exact preview" }).click();
  await expect(page.getByText("Message message-e2e: APPROVED")).toBeVisible();

  await page.getByRole("button", { name: /^03 Sandbox$/ }).click();
  await expect(page.getByText("sandbox-e2e")).toBeVisible();

  await page.getByRole("button", { name: /Reporting/ }).click();
  await expect(page.getByRole("button", { name: "Create report package" })).toBeVisible();
  expect(streamConnections()).toBeGreaterThanOrEqual(1);
});

test("permission denial is visible and server-independent navigation is hidden", async ({ page }) => {
  await mockApi(page);
  await page.goto("/test-fixture?restricted=1");
  await expect(page.getByText("Permission denied")).toBeVisible();
  await expect(page.getByRole("button", { name: /Operations Overview/ })).toHaveCount(0);
});

test("degraded dependency produces a bounded degraded-service state", async ({ page }) => {
  await mockApi(page, { degraded: true });
  await page.goto("/test-fixture");
  await expect(page.getByText("Degraded service")).toBeVisible();
  await expect(page.getByText(/identity session is unavailable/)).toBeVisible();
});
