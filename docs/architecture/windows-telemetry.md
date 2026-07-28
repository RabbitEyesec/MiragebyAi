# Windows telemetry ownership

## The decision (confirmed, not changed by this remediation)

**Elastic Agent, via Fleet's Windows/Sysmon integration, is the sole owner
of raw Sysmon, Security, System, and PowerShell log ingestion.**
MirageEndpoint and MirageSpider do not run their own native Windows Event
Log collectors, and this remediation does not add one — building a second,
parallel collector would duplicate what Elastic Agent already does, not fix
a bug. This was verified against the actual codebase before any code
changed: `infra/elastic/README.md`'s "two physical paths" section and
`infra/packer/scripts/install-elastic-agent.ps1`/`install-sysmon.ps1`
already establish this split; there is no native collector "missing" to
add.

What Priority 1 actually needed, and what this remediation adds:

## 1. Spider's observation types were overlapping, not scoped

Before this fix, `spider.observation`'s `PROCESS_START/PROCESS_STOP/
FILE_CREATE/FILE_MODIFY/FILE_DELETE/NETWORK_CONNECTION/REGISTRY_MODIFY`
types described the exact same category of event Sysmon already collects
natively via Elastic Agent — two independent, uncorrelated views of the
same real-world action, with no way to tell they were the same thing.

Fixed in two parts (`schemas/events/spider.observation.v1.schema.json`,
`libs/mirage_common/telemetry_correlation.py`):

- Every observation now optionally carries `host_id` (Spider auto-
  populates this from its own host fingerprint — the same identifier
  Elastic's own `host.id` uses for the same machine) and `process_guid`
  (Sysmon's own braced-GUID format), plus an optional `correlation_id` for
  linking an observation to a specific cross-source action (e.g. a
  controller action's `action_id`).
- `libs/mirage_common/telemetry_correlation.py` classifies every
  `observation_type` as either `OBSERVATION_TYPES_OWNED_BY_ELASTIC_AGENT`
  (the pre-existing process/file/network/registry types — kept in schema
  only for the fingerprint-gate and dev-sandbox-target consumers that read
  them directly from Postgres, not Elasticsearch) or
  `MIRAGE_SPECIFIC_OBSERVATION_TYPES` — signals Elastic Agent cannot
  observe at all: `ARTIFACT_INTERACTION`, `DECOY_INTERACTION`,
  `CONTROLLER_ACTION_OBSERVED`, `ANALYST_INTERACTION_OBSERVED`,
  `AI_INTERACTION_OBSERVED`, `USER_INTERACTION_INDICATOR`.
  `is_duplicate_of_elastic_agent_event()` lets any consumer showing both
  sources (a future dashboard view, a report) recognize when a Spider
  observation and an Elastic Agent Sysmon event describe the same process,
  rather than presenting one action as two pieces of evidence.
  `tests/unit/test_telemetry_correlation.py` proves the classification is
  exhaustive (every schema enum value is classified as exactly one of the
  two sets) and that the dedup function never claims a false correlation.

## 2. Telemetry-gap detection (agent liveness, not evidence-sequence gaps)

`GET /api/v1/agents` (`services/mirage-api/mirage_api/app.py`) now flags
`telemetry_gap: true` for any `ACTIVE` agent whose `last_seen_at` is either
NULL (enrolled, never reported) or older than
`TELEMETRY_GAP_THRESHOLD_SECONDS` (90s, matching the pre-existing
export-eligibility staleness check). This is a different concept from
`evidence_collection_gaps` (sequence-continuity gaps in already-received
evidence) — this is "is the agent even still talking to us at all."
Real, tested against real Postgres
(`tests/integration/test_mirage_api.py`'s two new tests).

## What this remediation did NOT build (real gaps, not hidden ones)

- **A Fleet Agent Policy / integration-package template enumerating
  required Windows channels as a checked-in artifact.** No such file
  exists in the repo today (only the enrollment script). A real Fleet
  Server would need one; this remains outstanding.
- **A Fleet Server health-check client** (querying Fleet's own agent
  status/checkin API). No Fleet Server exists in this dev stack at all
  (confirmed: no compose service, no Terraform resource) — there is
  nothing to build a tested client against yet, unlike the AWS Secrets
  Manager provider (Priority 4), which had a real, specified schema to
  implement against even without a live account.
- **Bookmark/checkpoint validation against Elastic Agent's own internal
  Winlogbeat-style state.** Elastic Agent manages this internally; no
  API surface for validating it externally was identified in this pass.

These three remain real, scoped, honestly-tracked gaps —
`ENGINEERING_REMEDIATION_STATUS.md`'s F-09 entry records them explicitly
rather than folding them into a claim of completion.
