# Mirage Elastic templates

Applied via `scripts/provision-elastic-templates` (idempotent; called by
`scripts/bootstrap-development`). Verified for real against both a live dev
Elasticsearch container and an ephemeral testcontainer
(`tests/integration/test_elastic_templates.py`).

See `docs/architecture/windows-telemetry.md` for the full ownership split
between Elastic Agent (raw Sysmon/Windows Event Log ingestion) and
MirageSpider (Mirage-specific sandbox signals only), and how the two are
correlated (`libs/mirage_common/telemetry_correlation.py`) rather than
duplicated.

## Two physical paths behind one conceptual "endpoint telemetry" stream

Appendix E names `mirage-telemetry-endpoint` as holding "Sysmon + OS
telemetry from the employee VM." The topology table (spec §5) locks two
*separate* ingestion paths for that VM:

1. **Sysmon → Elastic Agent → Fleet Server → Elasticsearch.** This is
   Elastic's own standard Windows/Sysmon integration package — it manages
   its own ECS-mapped data streams (typically
   `logs-windows.sysmon_operational-<namespace>`). Mirage does not define
   custom mappings for this path; Fleet's integration policy owns it. Set up
   in Step 21 / the lab (LAB_VERIFICATION_REQUIRED — needs a real Fleet
   Server).
2. **MirageEndpoint's own service → mirage-agent-ingestion → (future NATS
   consumer) → this `mirage-telemetry-endpoint` data stream.** This is
   what `component_templates/mirage-common-mappings.json` and
   `index_templates/mirage-telemetry-endpoint.json` in this directory
   define — the Step 1 event envelope shape, `dynamic: strict` at the
   envelope level (an unexpected top-level field is rejected, matching
   Step 1's "unknown fields are rejected" rule) with `payload` staying
   `dynamic: true` (already schema-validated once at ingestion — see
   `mirage_contracts.envelope.validate_event` — not worth mapping twice).

The two are correlated at query/dashboard time by `source_id` /
hostname, not merged into one physical index — trying to force both into
one data stream would mean either loosening our own envelope's strict
mapping to accommodate arbitrary ECS fields, or fighting Fleet's own
index-template ownership of the Sysmon integration. Neither is worth it for
what is, in the end, a Kibana-side correlation problem.

## @timestamp

Every Elasticsearch data stream requires a `@timestamp` field, and —
confirmed empirically against a real 8.15 cluster, not assumed — the field
name is **not** configurable via `data_stream.timestamp_field` in this
version (`x_content_parse_exception: unknown field [timestamp_field]`).
Rather than bolt a non-contract `@timestamp` field onto the Step 1 envelope
schema, `ingest_pipelines/mirage-set-timestamp.json` derives it from the
envelope's own `ingest_time` via a `set` processor, wired in as
`index.default_pipeline` on the index template.

## Retention

7-day ILM delete phase (`ilm/mirage-telemetry-ilm-policy.json`) — the
Appendix L dev cost-control figure ("7-day Elastic ILM"). Acceptance/
production profiles should override this with a longer window sized to the
case lifecycle, not reuse the dev default — tracked as a config decision to
make explicitly when Stage 5's evidence pipeline (which is authoritative for
long-term retention, not raw telemetry) is built.
