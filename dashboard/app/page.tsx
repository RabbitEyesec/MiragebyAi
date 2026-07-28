import { DashboardApp } from "@/components/DashboardApp";
import { readUserSession } from "@/lib/session";

export const dynamic = "force-dynamic";

export default async function Home() {
  const session = await readUserSession();
  if (!session) {
    return (
      <main className="login-page">
        <section className="login-card">
          <span className="brand-mark brand-mark-large" aria-hidden="true">M</span>
          <p className="eyebrow">Controlled lab operations</p>
          <h1>See the investigation.<br />Keep the provenance.</h1>
          <p>Mirage separates observed fact, deterministic correlation, AI inference, analyst action, and system action across one evidence-linked read model.</p>
          <a className="primary-button" href="/api/auth/login">Sign in with Keycloak</a>
          <small>No access token is stored in localStorage. Sessions use encrypted, HTTP-only cookies.</small>
        </section>
      </main>
    );
  }
  return <DashboardApp initialUser={session} />;
}
