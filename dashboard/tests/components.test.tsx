import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { AIView } from "@/features/ai/AIView";
import { EvidenceView } from "@/features/evidence/EvidenceView";
import { InvestigationView } from "@/features/investigation/InvestigationView";
import { OperationsView } from "@/features/operations/OperationsView";
import { ReportingView } from "@/features/reporting/ReportingView";
import { SandboxView } from "@/features/sandbox/SandboxView";
import { caseId, evidenceId, model } from "@/tests/fixtures";

vi.mock("@/components/GraphWorkbench", () => ({
  GraphWorkbench: () => <div aria-label="canonical graph workbench" />,
}));

describe("all six analyst workspaces", () => {
  it("renders Operations Overview", () => {
    render(<OperationsView data={{ platform_health: "HEALTHY", open_cases: 1, cases_by_state: { ENGAGING: 1 }, cases_by_severity: { HIGH: 1 }, recent_operational_alerts: [] }} />);
    expect(screen.getByText("Control plane")).toBeInTheDocument();
  });

  it("renders Investigation and never creates hostile DOM elements", () => {
    const { container } = render(<InvestigationView model={model} />);
    expect(screen.getByText(caseId)).toBeInTheDocument();
    expect(screen.getByLabelText("canonical graph workbench")).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
    expect(screen.getByText("<script>alert(1)</script> PowerShell observed")).toBeInTheDocument();
  });

  it("renders Sandbox with policy-protected controls", () => {
    render(<SandboxView roles={["operator"]} data={{ sandbox: { sandbox_id: "sandbox-1", image_id: "ami-1", state: "ACTIVE", state_version: 3, agent_status: "HEALTHY", controller_status: "HEALTHY", spider_status: "HEALTHY" }, action_journal: [] }} />);
    expect(screen.getByText("Protected controls")).toBeInTheDocument();
  });

  it("renders AI inference with budget and no privileged prompt", () => {
    render(<AIView roles={["investigator"]} data={{ status: "AVAILABLE", proposal: { strategy_phase: "ENGAGE", action_type: "PLACE_ARTIFACT", rationale: "Evidence-backed inference", confidence: 0.7, supporting_event_ids: [] }, snapshot: { snapshot_hash: "a".repeat(64), size_bytes: 100, estimated_tokens: 25, trimmed_fields: [] }, policy: { decision: "ALLOW", reason_codes: [] }, cost_gbp: "0.12" }} />);
    expect(screen.getByText("AI inference — not observed fact")).toBeInTheDocument();
    expect(screen.getByText("£0.12")).toBeInTheDocument();
  });

  it("renders Evidence Board metadata without a permanent S3 URL", () => {
    const { container } = render(<EvidenceView evidence={[{ evidence_id: evidenceId, type: "LOG", filename: "safe.log", media_type: "text/plain", size_bytes: 4, sha256: "a".repeat(64), source: "spider", sequence: 1, certificate_serial: "serial", acquisition_time: "2026-07-26T10:00:00Z", s3_version_id: "version-1", object_lock: { mode: "GOVERNANCE", retention_until: "2026-08-26T10:00:00Z" }, verification_status: "VERIFIED", classification: "SENSITIVE", related_events: [], related_graph_nodes: [], export_inclusion: true }]} />);
    expect(screen.getByText("safe.log")).toBeInTheDocument();
    expect(container.textContent).not.toContain("s3://");
  });

  it("renders Reporting and enforces explicit export visibility", () => {
    const view = render(<ReportingView data={{ reports: [] }} roles={["investigator"]} />);
    expect(screen.getByText("Explicit export permission is required.")).toBeInTheDocument();
    view.rerender(<ReportingView data={{ reports: [] }} roles={["export"]} />);
    expect(screen.getByRole("button", { name: "Create report package" })).toBeDisabled();
  });
});
