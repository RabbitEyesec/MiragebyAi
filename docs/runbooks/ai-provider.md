# AI provider

AI output is an untrusted proposal. Strict schema validation, deterministic
policy, budgets, case state, health gates, and analyst-approval rules remain
authoritative.

## Enablement

Keep `AI_ALLOW_EXTERNAL_PROVIDER=false` until the provider contract is tested.
Set the provider, model allowlist, timeout, concurrency, token limits, retry
limits, circuit threshold, and per-case/daily/monthly budgets. Supply the API
credential through `AI_PROVIDER_SECRET_ARN`; do not place it in YAML or logs.

Run `make test-ai`, `make test-injection`, and `make test-policy`. Observe the
`mirage.ai.*` OpenTelemetry metrics for requests, latency, tokens, estimated
cost, fallback, validation failures, and circuit state.

## Failure response

On timeout, invalid output, budget exhaustion, or an open circuit, Mirage uses
the deterministic fallback and records why. Disable external calls immediately
for unexplained spend or malformed output. Never bypass proposal validation or
policy to restore service. Live provider execution is
`LAB_VERIFICATION_REQUIRED`.
