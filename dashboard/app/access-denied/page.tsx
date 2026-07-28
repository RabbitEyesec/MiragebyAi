const REASONS: Record<string, string> = {
  oidc_state: "Your sign-in attempt expired or could not be verified (missing or mismatched state/PKCE cookie). This is usually just a stale browser session — try signing in again.",
  token_exchange: "Keycloak rejected the authorization code exchange. This usually means the dashboard's redirect URI is out of sync with the Keycloak client's configuration — ask a platform administrator to check it (or run scripts/dev-auth-doctor).",
  invalid_token: "The identity token returned by Keycloak could not be verified (bad signature, issuer, or audience). Ask a platform administrator to check the Keycloak client and issuer configuration.",
  iss_mismatch: "The identity provider that answered this request does not match the configured Keycloak issuer. Sign-in was blocked for safety.",
};

const DEFAULT_REASON =
  "The OIDC transaction failed. Ask a platform administrator to review the Keycloak assignment.";

export default async function AccessDenied({
  searchParams,
}: {
  searchParams: Promise<{ reason?: string }>;
}) {
  const { reason } = await searchParams;
  const message = (reason && REASONS[reason]) || DEFAULT_REASON;
  return (
    <main className="login-page">
      <section className="login-card state-denied" role="alert">
        <p className="eyebrow">Access denied</p>
        <h1>This identity cannot enter Mirage.</h1>
        <p>{message}</p>
        <a className="primary-button" href="/api/auth/login">Try another identity</a>
      </section>
    </main>
  );
}
