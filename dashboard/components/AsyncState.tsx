import type { ReactNode } from "react";

export function LoadingState({ label = "Loading" }: { label?: string }) {
  return (
    <div className="state-panel" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" />
      {label}…
    </div>
  );
}

export function EmptyState({
  title,
  detail,
}: {
  title: string;
  detail: string;
}) {
  return (
    <div className="state-panel">
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}

export function DegradedState({
  title,
  detail,
  children,
}: {
  title: string;
  detail: string;
  children?: ReactNode;
}) {
  return (
    <div className="state-panel state-degraded" role="alert">
      <strong>{title}</strong>
      <span>{detail}</span>
      {children}
    </div>
  );
}

export function PermissionDenied({ workspace }: { workspace: string }) {
  return (
    <div className="state-panel state-denied" role="alert">
      <strong>Permission denied</strong>
      <span>Your server-authorised role does not grant access to {workspace}.</span>
    </div>
  );
}
