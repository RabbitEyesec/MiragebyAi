export const WORKSPACES = [
  "operations",
  "investigation",
  "sandbox",
  "ai",
  "evidence",
  "reporting",
] as const;

export type Workspace = (typeof WORKSPACES)[number];

const workspaceRoles: Record<Workspace, ReadonlySet<string>> = {
  operations: new Set(["platform_admin", "operator", "auditor", "read_only"]),
  investigation: new Set([
    "platform_admin",
    "investigator",
    "operator",
    "auditor",
    "read_only",
  ]),
  sandbox: new Set(["platform_admin", "investigator", "operator", "auditor", "read_only"]),
  ai: new Set(["platform_admin", "investigator", "operator", "auditor", "read_only"]),
  evidence: new Set(["platform_admin", "investigator", "operator", "auditor", "read_only"]),
  reporting: new Set(["platform_admin", "investigator", "auditor", "read_only", "export"]),
};

export type PrivilegedControl =
  | "export"
  | "directive"
  | "direct_intervention"
  | "emergency_control"
  | "sandbox_mutation";

const controlRoles: Record<PrivilegedControl, ReadonlySet<string>> = {
  export: new Set(["platform_admin", "export"]),
  directive: new Set(["platform_admin", "investigator"]),
  direct_intervention: new Set(["platform_admin", "direct_intervention"]),
  emergency_control: new Set(["platform_admin", "emergency_control"]),
  sandbox_mutation: new Set(["platform_admin", "investigator", "operator"]),
};

export function hasAnyRole(
  actual: readonly string[],
  required: ReadonlySet<string>,
): boolean {
  return actual.some((role) => required.has(role));
}

export function canAccessWorkspace(roles: readonly string[], workspace: Workspace): boolean {
  return hasAnyRole(roles, workspaceRoles[workspace]);
}

export function canUseControl(
  roles: readonly string[],
  control: PrivilegedControl,
): boolean {
  return hasAnyRole(roles, controlRoles[control]);
}

export function visibleWorkspaces(roles: readonly string[]): Workspace[] {
  return WORKSPACES.filter((workspace) => canAccessWorkspace(roles, workspace));
}
