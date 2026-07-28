import { describe, expect, it } from "vitest";

import {
  canAccessWorkspace,
  canUseControl,
  visibleWorkspaces,
} from "@/lib/rbac";

describe("workspace RBAC", () => {
  it.each([
    ["platform_admin", "operations", true],
    ["investigator", "investigation", true],
    ["operator", "sandbox", true],
    ["auditor", "reporting", true],
    ["read_only", "evidence", true],
    ["investigator", "operations", false],
  ] as const)("%s -> %s is %s", (role, workspace, expected) => {
    expect(canAccessWorkspace([role], workspace)).toBe(expected);
  });

  it("requires explicit privileged permissions", () => {
    expect(canUseControl(["investigator"], "export")).toBe(false);
    expect(canUseControl(["export"], "export")).toBe(true);
    expect(canUseControl(["investigator"], "direct_intervention")).toBe(false);
    expect(canUseControl(["direct_intervention"], "direct_intervention")).toBe(true);
    expect(canUseControl(["operator"], "emergency_control")).toBe(false);
    expect(canUseControl(["emergency_control"], "emergency_control")).toBe(true);
  });

  it("returns only role-visible navigation", () => {
    expect(visibleWorkspaces(["investigator"])).not.toContain("operations");
    expect(visibleWorkspaces(["read_only"])).toHaveLength(6);
  });
});
