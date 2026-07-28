import "server-only";

export interface DashboardServerConfig {
  issuer: string;
  issuerInternal: string;
  clientId: string;
  clientSecret?: string;
  appUrl: string;
  apiUrl: string;
  sessionSecret: string;
}

export function serverConfig(): DashboardServerConfig {
  const config: DashboardServerConfig = {
    issuer: process.env.MIRAGE_OIDC_ISSUER_URL ?? "http://localhost:8081/realms/mirage",
    issuerInternal:
      process.env.MIRAGE_OIDC_INTERNAL_ISSUER_URL ??
      process.env.MIRAGE_OIDC_ISSUER_URL ??
      "http://localhost:8081/realms/mirage",
    clientId: process.env.MIRAGE_OIDC_CLIENT_ID ?? "mirage-dashboard",
    clientSecret: process.env.MIRAGE_OIDC_CLIENT_SECRET,
    appUrl: process.env.MIRAGE_DASHBOARD_URL ?? "http://localhost:3001",
    apiUrl: process.env.MIRAGE_API_URL ?? "http://localhost:18000",
    sessionSecret: process.env.MIRAGE_SESSION_SECRET ?? "",
  };
  if (process.env.NODE_ENV === "production" && config.sessionSecret.length < 32) {
    throw new Error("MIRAGE_SESSION_SECRET must be at least 32 characters in production");
  }
  if (!config.sessionSecret) {
    config.sessionSecret = "mirage_dev_local_only_dashboard_session";
  }
  return config;
}
