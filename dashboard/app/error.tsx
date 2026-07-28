"use client";

export default function ErrorPage({ reset }: { reset: () => void }) {
  return (
    <main className="login-page">
      <section className="login-card state-degraded" role="alert">
        <p className="eyebrow">Dashboard boundary</p>
        <h1>Mirage could not open this view.</h1>
        <p>No diagnostic stack or internal connection detail is shown in the browser.</p>
        <button type="button" onClick={reset}>Retry</button>
      </section>
    </main>
  );
}
