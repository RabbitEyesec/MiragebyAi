"use client";

import type { ReactNode } from "react";

import { StatusBadge } from "@/components/StatusBadge";
import { type Workspace, visibleWorkspaces } from "@/lib/rbac";
import type { CaseListItem, UserSession } from "@/models";

const labels: Record<Workspace, string> = {
  operations: "Operations Overview",
  investigation: "Investigation",
  sandbox: "Sandbox",
  ai: "AI Interaction",
  evidence: "Evidence Board",
  reporting: "Reporting",
};

export function AppShell({
  user,
  cases,
  selectedCase,
  onCaseChange,
  workspace,
  onWorkspaceChange,
  connection,
  freshness,
  notifications,
  onLogout,
  children,
}: {
  user: UserSession;
  cases: CaseListItem[];
  selectedCase: string | null;
  onCaseChange: (caseId: string) => void;
  workspace: Workspace;
  onWorkspaceChange: (workspace: Workspace) => void;
  connection: string;
  freshness: string;
  notifications: number;
  onLogout: () => void;
  children: ReactNode;
}) {
  const workspaces = visibleWorkspaces(user.roles);
  return (
    <div className="app-shell">
      <a className="skip-link" href="#workspace">Skip to workspace</a>
      <header className="topbar">
        <div className="brand" aria-label="Mirage SOC">
          <span className="brand-mark" aria-hidden="true">M</span>
          <div><strong>MIRAGE</strong><span>Analyst operations</span></div>
        </div>
        <label className="case-selector">
          <span>Active case</span>
          <select
            value={selectedCase ?? ""}
            onChange={(event) => onCaseChange(event.target.value)}
            disabled={!cases.length}
            aria-label="Select investigation case"
          >
            {!cases.length && <option value="">No authorised cases</option>}
            {cases.map((item) => (
              <option key={item.case_id} value={item.case_id}>
                {item.severity} · {item.state.replaceAll("_", " ")} · {item.case_id}
              </option>
            ))}
          </select>
        </label>
        <div className="topbar-status">
          <StatusBadge value={process.env.NEXT_PUBLIC_MIRAGE_ENV ?? "DEVELOPMENT"} />
          <span className={`connection-dot connection-${connection.toLowerCase()}`} aria-hidden="true" />
          <span>{connection}</span>
          <span>Freshness: {freshness}</span>
          <button type="button" aria-label={`${notifications} notifications`} className="notification-button">
            Alerts <strong>{notifications}</strong>
          </button>
          <div className="identity">
            <strong>{user.username}</strong>
            <span>{user.roles.filter((role) => !role.startsWith("default-")).join(" · ")}</span>
          </div>
          <button type="button" onClick={onLogout}>Log out</button>
        </div>
      </header>
      <div className="shell-body">
        <nav className="sidebar" aria-label="Analyst workspaces">
          {workspaces.map((item, index) => (
            <button
              type="button"
              key={item}
              className={workspace === item ? "active" : ""}
              onClick={() => onWorkspaceChange(item)}
              aria-current={workspace === item ? "page" : undefined}
              onKeyDown={(event) => {
                if (!["ArrowDown", "ArrowUp"].includes(event.key)) return;
                event.preventDefault();
                const next =
                  (index + (event.key === "ArrowDown" ? 1 : -1) + workspaces.length) %
                  workspaces.length;
                onWorkspaceChange(workspaces[next]);
              }}
            >
              <span>{String(index + 1).padStart(2, "0")}</span>
              {labels[item]}
            </button>
          ))}
        </nav>
        <main id="workspace" tabIndex={-1}>{children}</main>
      </div>
    </div>
  );
}
