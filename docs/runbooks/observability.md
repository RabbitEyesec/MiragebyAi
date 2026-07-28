# Observability runbook

The OTel collector configuration drops attributes containing secret,
credential, token, prompt, evidence bytes, or hostile content before export.
The stable core catalogue has 40 instruments covering API, realtime, NATS,
outbox, Elastic, PostgreSQL, agents/certificates, sandbox, AI/policy, artifacts,
evidence/S3, reports, canaries, clocks, workers, projections, and teardown.

Correlation fields are limited to durable IDs such as case, session, event,
action, proposal, policy decision, evidence, artifact, and source. Never attach
raw prompts, message content, evidence bytes, or credentials.

```sh
make test-observability
otelcol-contrib --config infra/otel/collector.yaml
```

Load `infra/otel/elastic-dashboard.ndjson` and provision
`infra/otel/alert-rules.yaml`. Profile B must measure actual alert delivery:
worker critical under 60 seconds, heartbeat warning at 30 seconds/offline at
90 seconds, and NATS lag above 10,000 messages or 30 seconds.
