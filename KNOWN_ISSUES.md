# Known Issues

## Prompt 3 blocking external verification

- **P3-LAB-01:** No Profile B acceptance run has occurred. All 61 Profile B
  rows (25 numeric and 36 scenario) remain `NOT_RUN`; together with 10 local
  numeric `NOT_RUN` rows, the signed local package contains 71 total
  `NOT_RUN`. A second clean Profile B run is therefore also absent.
- **P3-LAB-02:** Endpoint and sandbox MSI/Burn packages have not been compiled,
  Authenticode-signed, or lifecycle-tested on clean Windows hosts.
- **P3-LAB-03:** A fresh Ubuntu 24.04 container passed the non-mutating
  OS/capacity/DNS/port/Docker/Compose/config/secret-reference/package/SBOM
  preflight. The signed release has not been installed, upgraded, rolled back,
  repaired, or uninstalled on a clean supported server with production image
  digests, protected bootstrap recipes, and protected external signing keys.
- **P3-LAB-04:** The deployed 1,000 events/second five-minute run, five-minute
  outage, endpoint-to-Elasticsearch p95, sandbox-to-dashboard p95, reset/rebuild
  times, deployment p95, and alert-delivery timing are not measured.
- **P3-LAB-05:** Real AWS S3 Object Lock/KMS/RFC3161, public canary/DNS, live
  AI provider, Kali/Fleet/Elastic, AWS teardown, and revoked Windows identity
  reconnect tests are not run.
- **P3-LAB-06:** Hosted GitHub Actions has not executed this working tree.

Non-blocking local limitation: local acceptance combines real integration
scenarios with simulated Windows/AWS/public surfaces; it is not a live
end-to-end environment and cannot change the product status to `ACCEPTED`.

Real gaps, deferred work, and things that are implemented but weaker than the
spec ultimately wants. Updated continuously. Nothing here should be a surprise
to whoever picks up Prompt 2 — cross-reference `SESSION_HANDOFF.md`.

Severity: **BLOCKING** (must resolve before the affected requirement can be
ACCEPTED) · **DEFERRED** (explicitly out of Prompt 1 scope per the brief) ·
**WEAKNESS** (works, but a known corner is thinner than the spec's bar).

---

## Stage 0 / Step 1 — Contracts

**WEAKNESS** — `scripts/validate-contracts`'s breaking-change-without-version-bump
check (`check_no_breaking_change_without_version_bump`) diffs each
`schemas/**/*.v<N>.schema.json` against its content at `git show HEAD:<path>`.
With no commits yet in this repository, that check is a no-op (it returns
immediately when `git show HEAD:.` fails). It is real, working code — proven
by unit-level reasoning, not yet by an end-to-end run against actual git
history — and will start doing real work the first time this repo has two
commits that both touch the same schema file. Re-verify with a real drift
scenario once the repo has commit history. See REQUIREMENTS_TRACEABILITY.md
S0-1-018 (CODE_COMPLETE, not LOCALLY_VERIFIED).

## Stage 0 / Step 3 — Trust, enrolment, rotation

**RESOLVED (Priority 4 remediation)** —
`mirage_agent_ingestion.provisioners.SecretsManagerProvisionerSource` is now
a real implementation (typed IAM/JSON-shape errors, last-known-good
caching, `docs/runbooks/secrets.md`'s `mirage/<environment>/step-ca` schema),
proven with `botocore.stub.Stubber` in
`tests/unit/test_secrets_manager_provisioner.py` (15 tests) — no AWS
account needed to verify the retrieval/parsing/error-handling logic itself.
`DevFileProvisionerSource` remains the dev-only loader;
`build_provisioner_source()` is the new single decision point and refuses
to fall back to it in production. **Still LAB_VERIFICATION_REQUIRED:** a
real AWS account exercising the actual `get_secret_value` call against a
real (or LocalStack) Secrets Manager secret — see
`docs/runbooks/step-ca-secrets.md`.

**WEAKNESS** — `mirage_agent_ingestion.enrollment` has no HTTP layer yet
(`POST /api/v1/enroll` per Appendix F). The core logic
(`create_enrollment_token`, `enroll_agent`, `renew_agent`, `revoke_agent`,
`is_agent_active`) is real and integration-tested end-to-end against a real
Postgres + real step-ca, but nothing calls it over HTTP yet — that lands in
Step 4b (`schemas/api/enroll_request.v1` / `enroll_response.v1` already
exist and match this module's inputs/outputs exactly).

**WEAKNESS** — Certificate revocation is *passive*, not active/OCSP (see
ARCHITECTURE_DECISIONS.md ADR-0013) — a deliberate, tested, and justified
choice given step-ca's badgerv2 backend, not an oversight. Recorded here so
it isn't rediscovered as a surprise: a revoked certificate remains
*cryptographically valid* (would pass signature/chain verification) until
its natural (short) expiry; Mirage's actual revocation enforcement is the
Postgres `agents.status` check on every connection-admission path, which
*is* immediate.

## Stage 1 / Step 4 — MirageEndpoint + dev MSI

**WEAKNESS (real architectural finding, not an oversight)** — uvicorn does
not expose the TLS peer certificate to ASGI application code (verified
empirically: `transport.get_extra_info("ssl_object")` returns `None` inside
a request handler even with `ssl_cert_reqs=CERT_REQUIRED` actively enforcing
the handshake — see TEST_RESULTS.md §Step4). mTLS enforcement at the TLS
layer is real and tested (an unauthenticated client gets a handshake
rejection, not a 401); associating *which* certificate authenticated a
request with application logic requires a proxy in front that terminates
TLS and forwards the verified identity — which is exactly Nginx's job in
the locked stack. `mirage_agent_ingestion.auth` implements and tests the
CONTRACT (a header pair a trusted proxy would inject) but the actual Nginx
mTLS listener is not built until Step 8b. Until then, `EndpointHttpClient.heartbeat()`
presents a real client certificate over real mTLS (tested end-to-end against
a real uvicorn TLS listener — see `test_mirage_endpoint_e2e.py`), but there
is no Nginx in front of the dev `mirage-agent-ingestion` instance to
translate that into the header pair `mirage_agent_ingestion.auth` expects.
Both halves are independently real and tested; they are not yet wired
together end-to-end. Fix lands with Step 8b.

**WEAKNESS** — `EncryptedEventQueue.pending_count()` (queue_depth) is
computed correctly and sent on every heartbeat, but nothing persists a
snapshot of it to a location an out-of-process lab script can poll (e.g.
`installers/endpoint/scripts/test-queue-recovery.ps1` expects a
`queue-depth.metric` file that does not exist yet). A real fix is either a
small periodic file-export in `service_logic.py`, or waiting for Step 4b's
`GET /api/v1/agents` to expose it server-side and querying that instead —
noted inline in the script rather than silently assumed to work.

**DEFERRED** — `mirage_endpoint.win_service` (the pywin32 ServiceFramework
shim) cannot be imported, executed, or tested on macOS/Linux by
construction (`sys.platform != "win32"` guard, ADR-0002) — it is reviewed
for structural correctness only. Every behavior it delegates to
(`service_logic.py`, `queue.py`, `client.py`, `keys.py`) is independently
unit/integration-tested; the shim itself, the WiX MSI/Bundle compilation,
and all `installers/endpoint/scripts/*.ps1` lifecycle tests are
LAB_VERIFICATION_REQUIRED on a real Windows host with WiX v5 installed.

**WEAKNESS** — The TS/Python "generated representations agree" check
(`tests/contract/test_generated_agreement.py`) compares *required field
names* only, via a line-anchored regex over the generated `.ts` output, not a
full structural (type-level) diff. It would not catch, for example, a field
whose TYPE disagrees between the two languages (e.g. `integer` vs `number`
precision nuances) as long as both call it required. Acceptable for Prompt 1
given both are generated from the identical JSON Schema by dedicated
generators (datamodel-code-generator, json-schema-to-typescript) — the risk
this leaves open is generator-bug-shaped, not schema-drift-shaped, and is the
same class of risk any team accepting off-the-shelf codegen tools accepts.

## Stage 1 / Step 4b — Early engineering console

**SCOPED SIMPLIFICATION (deliberate, not an oversight)** — every route in
`mirage-api`'s Step 4b console requires `platform_admin` and nothing else;
there is no per-role access differentiation (e.g. a hypothetical
`read_only`-can-view-but-not-trigger-synthetic-checks split). This console
is a pre-Stage-9 engineering/ops diagnostic tool, not the real analyst
dashboard — see ADR-0014. When Stage 9 builds the real dashboard, it must
design real per-role access against the actual case/telemetry data model;
`mirage_common.oidc.require_any_role` already accepts an arbitrary role set,
so the mechanism is ready, only the per-endpoint policy is not.

**GAP (no dedicated automated test)** — `scripts/mirage-health` (the CLI
health command) was exercised manually against the dev stack but has no
integration test of its own. It is a thin argument-parsing/HTTP-call wrapper
around `GET /api/v1/health`, which IS integration-tested end-to-end
(`test_platform_admin_can_view_health`); the untested surface is limited to
argument parsing and exit-code mapping.

**GAP** — The Kibana dashboard (`infra/kibana/mirage-engineering-dashboard.ndjson`)
was verified by importing it into a real, temporary Kibana 8.15.0 container
and confirming the saved objects resolve with correct references — it was
NOT visually verified in a browser (headless environment). The underlying
data (recent events, agent heartbeat health) has not been visually confirmed
to render correctly in the histogram/search panels, only that the saved
objects themselves are structurally valid and import cleanly.

## Stage 1 / Step 5 — MirageSpider

**DEFERRED** — `mirage_spider.win_service` (the pywin32 ServiceFramework
shim) cannot be imported, executed, or tested on macOS/Linux by construction
(`sys.platform != "win32"` guard, ADR-0002), exactly like Step 4's
`mirage_endpoint.win_service`. Every behavior it delegates to
(`service_logic.py`, and the shared `agent_queue.py`/`agent_keys.py`/
`agent_http_client.py`) is independently unit/integration-tested; the shim
itself and the eventual MSI packaging (not yet built for Spider — Step 4's
WiX/PowerShell work was Endpoint-specific and hasn't been replicated for
Spider in this prompt) are LAB_VERIFICATION_REQUIRED on a real Windows host.

**SCOPE NOTE (not a gap, a deliberate boundary)** — MirageSpider's E2E test
does not exercise telemetry/tamper submission against the real live uvicorn
server, only against the in-process ASGI transport
(`tests/integration/test_agent_ingestion_api.py`). This is the exact same
architectural boundary Step 4's heartbeat test already documented: the
mTLS-terminating Nginx listener that extracts the verified client
certificate serial and forwards it as a header is Step 8b work; without it,
a real client presenting a real certificate over real TLS still gets a real
401 from `mirage_agent_ingestion.auth.require_client_certificate_serial`
(verified empirically — see TEST_RESULTS.md §Step5). Confirmed NOT a
regression risk masked as a known issue: `record_tamper()`'s
never-lose-an-event guarantee is proven against exactly this real failure
mode, not skipped.

**GAP** — MirageEndpoint's own local queue (`win_service.py` line ~96) still
sends nothing real — Sysmon/OS telemetry ships via the separate Elastic
Agent → Fleet path (per the topology table), not through MirageEndpoint's
own encrypted queue, so there is still no concrete event type for it to
enqueue/flush. The real transport now exists
(`mirage_common.agent_http_client.AgentHttpClient.submit_telemetry`, proven
via MirageSpider) and closing this gap is now purely "give MirageEndpoint
something real to say," not a missing mechanism — tracked here so it isn't
mistaken for finished.

## Stage 2 / Step 6 — Case state machine + migrations + outbox

**SCOPE NOTE (not a gap, a deliberate boundary)** — `ALLOWED_TRANSITIONS`
implements only the nine linear happy-path edges the spec states
(CREATED→...→DESTROYED). There is no abort-from-any-state transition, no
MONITORING loop, no re-engagement path — none of these are specified
anywhere in the spec text, and Step 6's own acceptance line only requires
the linear chain. See ADR-0016 for the reasoning; Step 7's real
detection/steering logic is the natural place to discover what non-linear
transitions are actually needed, rather than this step guessing.

**GAP (documented, not silently skipped)** — `processed_events`
(idempotency table, Appendix B) exists in the schema (migration 0003) but
has no writer yet: no consumer that would need it exists within Step 6's
scope (the case state machine itself doesn't consume events, it produces
them). Step 7's detection-into-cases adapter is the first real consumer
that needs to write to this table (to dedup incoming detections) — tracked
here so an empty table isn't mistaken for a missing feature versus a
not-yet-needed one.

**SCOPE NOTE** — `mirage-outbox-relay` polls every 250ms rather than
blocking on the `outbox_events_channel` LISTEN the migration's trigger
emits (see ADR-0016). The trigger and channel are real and fire on every
insert; nothing currently subscribes to them. A future revision could cut
worst-case dispatch latency from ~250ms to near-zero by adding a LISTEN
loop — purely additive, not a correctness gap (the poll loop is the
documented backstop either way per §6.3's own wording).

## Stage 2 / Step 7 — Detection into cases

**RESOLVED (was tracked as a gap in Step 6)** — `processed_events` now has
a real writer: `mirage_common.detection_correlation.correlate_detection`.

**SCOPE NOTE (not a gap)** — There is no dedicated `detections`/
`case_detections` tracking table (Appendix B doesn't list one). A second
(and any subsequent) detection that correlates into an already-existing
case is durably recorded as an `audit_events` row
(`action='detection.correlated_to_existing_case'`), not a queryable
per-detection ledger row — sufficient for Step 7's own acceptance line, and
consistent with what Appendix B actually specifies (see ADR-0017). If a
later stage needs to enumerate every detection that ever contributed to a
case (beyond the first one, which `case.created`'s
`source_detection_ids` already carries), that's a new table to add then,
not a gap in what Step 7 promised.

## Stage 2 / Step 7b — Development sandbox target

**DEFERRED (lab-only, no viable local substitute)** — RDP is not part of
`infra/compose/docker-compose.dev-sandbox.yml` and has no test coverage of
any kind in this prompt. Unlike HTTP/SSH, there is no macOS/Linux-native
RDP SERVER that could stand in for even a minimal protocol-acceptance
check, and building a fake one would violate this project's own
prohibition on fabricated success (see ADR-0018). Step 8d's RDP broker
(Stage 3) and the real RD Gateway config will need a genuine Windows
sandbox target (Step 9a) on a real Windows host before any part of the RDP
path can be exercised, even at the "does it accept a connection" level.

**SCOPE NOTE (not a gap)** — The dev sandbox target is real HTTP/SSH
containers, not a Windows guest. "Spider + Controller" from Step 7b's Build
line is satisfied by Spider's already-proven Step 5 business logic
reporting real observations about this target; MirageEnvironmentController
itself isn't built until Step 9b (Stage 4) and has no role in this step —
see ADR-0018 for why the spec's own stated dependency ("Stands on: Step
5," not Step 9b) makes this the correct reading, not a shortcut.

## Stage 3 / Step 8a — The /route decision API

**DEFERRED (Step 8b's own responsibility)** — "If /route is unreachable,
brokers fail safe to the endpoint and alert" describes BROKER behavior, not
something `/route` itself can implement (its own unreachability is the
scenario). No broker exists yet (Step 8b, next) — this is not a gap in
Step 8a, it is the boundary between what the server and the client each own
(see ADR-0019).

**SCOPE NOTE (not a gap)** — `POST /api/v1/cases/{id}/steer` accepts a raw
dict body (not a generated Pydantic model), matching mirage-agent-ingestion's
telemetry endpoint precedent: FastAPI enforces "it's a JSON object";
`write_routing_decision`'s typed parameters plus the DB's own CHECK/EXCLUDE
constraints enforce the real shape. There is no dedicated
`schemas/api/steer_request.v1.schema.json` — nothing in Appendix A requires
one for every internal endpoint, only for the event/command contracts
crossing service boundaries via NATS.

## Stage 3 / Step 8b/8c/8d — The three brokers

**DEFERRED (lab-only, no viable local substitute)** — RDP (Step 8d) has no
runnable artifact at all, only a design document
(`infra/broker/rdp/README.md`). RD Gateway's dynamic backend-selection
point is a compiled COM plugin interface (`IRDGPolicyEngine`), not a config
file or script — there is no portable, locally-testable equivalent the way
Nginx `auth_request` and OpenSSH `ForceCommand` provided for the other two
protocols. Genuinely needs a real Windows Server + RD Gateway role + Step
9a's golden AMI before any part of it (even a bare connection-acceptance
check) can be exercised.

**SCOPE NOTE (not a gap)** — Neither broker terminates real TLS for the
lab hostname in this prompt's local tests. The HTTP broker listens on plain
HTTP (8080); "Mirage owns TLS" per Appendix H.1 is a certificate-issuance
concern Step 4 already proved buildable via step-ca — re-proving it here
would exercise step-ca again, not the routing mechanism Step 8b is
chartered to prove. A real deployment wires a step-ca-issued cert into the
same nginx.conf.template's `listen` directive; nothing about the
`auth_request`/`map` mechanism this step proved changes when that happens.

**SCOPE NOTE (not a gap)** — `infra/compose/docker-compose.broker.yml` is
syntactically valid (`docker compose config` succeeds) but has not been
brought up as a running persistent stack in this prompt, because
mirage-api has no Dockerfile yet — containerizing every service is Task
#17's explicit job. The broker MECHANISM is fully proven via
`live_mirage_api_server` (a real uvicorn process, not a mock) in the
automated test suite; only the "package mirage-api as a container" step
remains, tracked under Task #17, not this one.

**SCOPE NOTE (not a gap)** — The SSH broker's onward connection to the
selected backend authenticates as a fixed system account (`employee01`),
not per-connecting-user identity mapping. Appendix H.2 doesn't specify
per-user backend credentials for this leg (unlike RDP's "user mapping" in
H.3), and Step 8c's own acceptance line only requires "a new session...
enters the selected sandbox, fingerprints match" — which this design
satisfies. Per-user backend identity, if ever required, is a policy
decision for whichever later stage actually needs it.

## Stage 4 / Step 9a — Golden image (Packer)

**DEFERRED (lab-only, no viable local substitute)** — `packer build` itself
has never been run. It launches a real EC2 instance, provisions it over
real WinRM, runs a real Windows Defender full scan, and needs a real
Windows guest for every PowerShell provisioner. None of that is
reproducible without an AWS account and a Windows host, the same
constraint ADR-0012 already recorded for `terraform apply`. Validation here
is static HCL structural testing (16 tests, `tests/unit/test_packer_pipeline.py`)
plus unit tests on the comparator engine the harness embeds — real,
meaningful, deterministic checks that catch provisioner-order regressions
and structural drift, but they cannot prove the guest-side PowerShell
scripts themselves run correctly end-to-end on a live Windows Server 2022
instance.

**DEFERRED (lab-only)** — `scripts/sign-ami-manifest`'s real KMS signing
(`kms.sign`) and AMI tagging (`ec2.create_tags`) calls have never executed
against real AWS. Its `--dry-run` path (manifest construction + the
refuse-to-sign-an-unverified-image guard) has been exercised and works;
the boto3 calls themselves need a real AWS account + KMS key.

**DEFERRED (lab-only)** — `install-mirage-spider.ps1`'s `pywin32` service
registration and `run-malware-scan.ps1`'s `Update-MpSignature`/
`Start-MpScan` calls have never executed on a real Windows host, for the
same reason Step 4/5's own `win_service.py` shims are lab-only.

**SCOPE NOTE (not a gap)** — MirageSpider is installed on the golden image
via a plain Python Windows service registration
(`install-mirage-spider.ps1`), not a second WiX MSI project. Step 4's own
title specifies "(dev MSI)"; Step 5's title (MirageSpider) does not — see
ADR-0021 decision 4.

**RESOLVED (Priority 6 / F-05 remediation)** — `install-mirage-env-controller.ps1`
now exists and is wired into `employee-sandbox.pkr.hcl` immediately after
`install-mirage-spider.ps1`. It creates the dedicated restricted local
service account (`svc-mirage-envctl`, matching `config.SERVICE_ACCOUNT`), a
fresh random password per build/repair run, installs the service under
that account (never LocalSystem — the script's own final check aborts the
build if it isn't), and grants that account Modify (never FullControl)
NTFS rights on the approved decoy-content root. A new
`verify-image-cleanliness.ps1` final pipeline stage (extended to cover the
Controller's own state directories alongside Spider's, per this same
finding) checks for no active case ID, no live Fleet enrollment token
residue, no baked-in private key material, and actively removes the
`C:\mirage-build` staging tree before capture — failing the build closed on
any violation. See `tests/unit/test_packer_pipeline.py` (12 new tests) and
`ARCHITECTURE_DECISIONS.md` (extends ADR-0021/ADR-0022's reasoning).
**Still lab-only:** the exact SDDL grant restricting the account's decoy-
*service* control rights (start/stop/query only, never
`SERVICE_CHANGE_CONFIG`) is left as an explicit in-script `TODO` — composing
it correctly requires reading each decoy service's own pre-existing security
descriptor (`sc.exe sdshow`) on a real build host, which does not exist in
this environment; overwriting it blind here would risk fabricating an SDDL
string nobody here could verify. A real gap discovered and fixed in the
same pass: `install-mirage-spider.ps1` never copied `mirage_contracts`
either, despite `service_logic.py` importing it directly — masked by every
environment that ran it having this repo's own editable install already on
`sys.path` (the same class of gap F-11 found for `scripts/install-server`).
Fixed in both scripts.

## Stage 4 / Step 9b — Environment Controller + output tagging

**RESOLVED (Priority 6 / F-05 remediation — was DEFERRED)** — The dedicated
restricted service account (`config.SERVICE_ACCOUNT`, "never LocalSystem")
and its filesystem ACL grant are now provisioned by
`infra/packer/scripts/install-mirage-env-controller.ps1` (see the Step 9a
entry above for the full description). The policy `_resolve_within_roots`
enforces IN CODE (ADR-0022 decision 4) never depended on this and was
already proven; the OS-level account restriction script itself is now real
and locally verified (via static text assertions cross-checked against
`config.py`/`actions.py`), while the actual Windows-host execution of that
script remains `WINDOWS_VERIFICATION_REQUIRED` — no Windows build host
exists in this environment to run it.

**RESOLVED (Priority 8 remediation)** — ENABLE/DISABLE_DECOY_SERVICE and
CHANGE_VISIBLE_METADATA's Windows-specific attribute bits now have real
implementations: `mirage_env_controller.windows_actions.
WindowsDecoyServiceController` (real `win32serviceutil` StartService/
StopService/QueryServiceStatus against an approved allowlist) and
`WindowsMetadataAttributeController` (real `win32file` GetFileAttributes/
SetFileAttributes for hidden/read-only). `actions.py` itself still stays
pywin32-free (ADR-0002 pattern) — the real calls live in the new
`windows_actions.py`, selected via `ExecutorContext`'s
`decoy_service_controller`/`metadata_attribute_controller` fields
(`win_service.py` wires the real ones; tests use the portable
`MarkerFileDecoyServiceController`/`NoopMetadataAttributeController`
defaults). See `docs/runbooks/windows-controller-actions.md`. **Still
LAB_VERIFICATION_REQUIRED:** the actual Windows API calls have not executed
on a real Windows host — `windows_actions.py` cannot be imported outside
Windows, same constraint as `win_service.py`; it is statically typechecked,
not run.

**DEFERRED (lab-only)** — SOFT_RESET/FULL_REBUILD's "< 3 min / < 10 min"
spec thresholds are ultimately about real AWS EC2 instance-replacement
latency (ADR-0022 decision 7). The local wipe-and-reseed mechanism is real
and its own elapsed time is asserted under threshold, but that is not
evidence about AWS's actual replace-instance timing, which needs a real
AWS account.

**DEFERRED (Stage 7 dependency)** — PLACE_ARTIFACT requires an explicit
`content_b64` action param rather than fetching artifact bytes by
`artifact_id` from an evidence/artifact store, because that store
(`artifacts` table, Appendix B) is Stage 7's own scope and does not exist
in Prompt 1. Wiring PLACE_ARTIFACT to the real Stage 7 artifact store is
that stage's job; missing `content_b64` fails loudly (`FAILED`) rather than
fabricating placeholder bytes — see ADR-0022 decision 5.

**RESOLVED (P12 test-honesty-audit remediation)** — Several of this
suite's own module-scoped Docker testcontainer fixtures (`keycloak_realm`,
`elasticsearch_url`, `step_ca_container`) started a container, then polled
a health-check URL with a `raise TimeoutError(...)` on the `else` branch of
the polling loop if it never became healthy in time — but never called
`container.stop()` on that failure path, so the container was silently
leaked. Originally discovered while diagnosing a `tests/integration`
full-suite run that failed with repeated `TimeoutError: keycloak did not
become healthy` under host memory pressure (see TEST_RESULTS.md's Step 9b
entry) — several ~470-500MB orphaned Keycloak containers from earlier
interrupted runs were found still running via `docker ps`/`docker stats`
and had to be removed by hand (`docker rm -f`), which was itself
contributing to the memory pressure causing further failures. Re-verified
during a systematic P12 pass over the full test tree: `keycloak_realm` had
already been partially fixed since this note was written (its health-check
timeout branch alone called `container.stop()`), but its own later
`bootstrap_realm()` call — added after that partial fix — had no such
protection and would have leaked exactly the same way if it ever raised;
`elasticsearch_url` and `step_ca_container` still had the original gap
unchanged. All three now wrap their entire setup (not just the health-check
branch) in `try: ... finally: container.stop()` in
`tests/integration/conftest.py`, so ANY exception during setup — a health-
check timeout, a provisioning API error, anything — stops the container.
Verified: `tests/integration/test_elastic_templates.py`,
`test_step_ca_enrollment.py`, and `test_routing_api.py` (which exercise all
three fixtures) still pass unchanged.

## Stage 4 / Step 10 — Deception-quality gate (blocking)

**DEFERRED (lab-only, no Windows host)** — Actually collecting live OS
observations for the §6.5 checklist on a real running sandbox (the
run-time equivalent of Step 9a's `run-fingerprint-harness.ps1`, calling
`SpiderServiceLogic.submit_fingerprint_snapshot` instead of writing a local
file) has not been built or exercised — there is no Windows host or live
sandbox in this environment to collect from. The gate mechanism this step
owns (blocking, audit, the Postgres read side, the Spider report ->
upsert -> gate-read pipeline) is fully real and LOCALLY_VERIFIED; only the
Windows-side collector script is outstanding.

**SCOPE NOTE (not a gap)** — `spider.fingerprint_snapshot`'s `checks`
payload is supplied by the caller of `submit_fingerprint_snapshot`, not
collected by `service_logic.py` itself, mirroring the SAME "collection
logic is OS-specific, submission logic is portable" boundary Step 4/5's own
`win_service.py` split already established (ADR-0002). No new pattern was
invented for this step.

**SCOPE NOTE (not a gap)** — The gate's read query
(`sandbox_fingerprint_snapshots`) is a single-row-per-`sandbox_id` "latest
observation cache," not a history table. If a future step needs "was the
sandbox EVER fingerprint-compliant, not just right now," that's a
different, not-yet-requested query against a different (history-preserving)
table — this step only needed "right now," per the spec's own "Run the
fingerprint harness live" wording.

## Task #17 — CI/Docker/Makefile wiring (cross-cutting, not a spec Step)

**DEFERRED (lab-only, no real GitHub remote to push to)** — `.github/workflows/ci.yml`
has never executed inside an actual GitHub Actions runner. Every individual
command it invokes was independently verified locally against equivalent
real infrastructure (see TEST_RESULTS.md), and the YAML itself parses
cleanly, but the workflow AS A WHOLE — runner provisioning, action
versions, GitHub's own Docker/testcontainers environment specifics — is
untested. No `actionlint`/`act` tool was available in this environment for
a deeper static/dry-run check either.

**FOUND AND FIXED (real, pre-existing, cross-cutting)** — Three genuine
gaps present since earlier steps, all invisible until this task actually
built/ran the real artifacts instead of only validating config syntax:
1. `pyproject.toml`'s `packages` list was missing the
   `mirage_contracts.generated` subpackage, and had no `package-data` entry
   for the bundled JSON schemas — a real `pip install .` (as any Dockerfile
   or production deployment would do) produced a broken package. Every
   test this whole build ran used `pip install -e ".[dev]"`, which never
   exercises this path. Fixed — see ADR-0024 decision 3.
2. `scripts/bootstrap-development`'s `compose_up()` and the Makefile's
   `compose-up`/`compose-down` targets never passed `--env-file`, meaning
   `.env`'s actual contents were never really being read by `docker
   compose` — every variable "worked" only because its
   `${VAR:-default}` fallback happened to match `.env.example`. Fixed —
   see ADR-0024 decision 5.
3. `ruff check scripts` (as `make lint` has invoked it since the Bootstrap
   Gate step) matched zero of the extensionless Python CLI tools under
   `scripts/` — `make lint` reported clean the entire build while never
   actually linting `scripts/bootstrap-development`,
   `scripts/validate-config`, `scripts/validate-contracts`, `scripts/migrate`,
   etc. 8 real style violations existed in 3 of those files; fixed both
   the violations and the coverage gap. See ADR-0024 decision 7.

**SCOPE NOTE (not a gap)** — mirage-worker and mirage-outbox-relay have no
Docker HEALTHCHECK (plain background loops, no HTTP endpoint to probe).
`docker compose ps`/`scripts/bootstrap-development`'s own health-wait logic
treats "no healthcheck declared, container running" as success for these
two specifically, not "unhealthy forever" — a real design accommodation,
not an oversight (see the fixed `wait_healthy()` docstring).
## Prompt 2 — external and operational limitations

**LAB_VERIFICATION_REQUIRED — evidence trust anchors.** The S3 adapter,
version-ID reads, retention requests, multipart behavior, and Object Lock API
were exercised against real local MinIO. This is not verification of AWS S3
IAM, AWS Object Lock retention enforcement, AWS KMS RSA-PSS, cross-account
access, or recovery from AWS service faults.

**LAB_VERIFICATION_REQUIRED — trusted time.** The exporter constructs and
parses real OpenSSL RFC 3161 requests/responses and requires a configured CA
chain for independent trust. No approved external timestamp authority was
called. Local export time is `LOCAL_SELF_ASSERTED`.

**LAB_VERIFICATION_REQUIRED — live AI.** Provider-independent transport,
secret refresh/last-known-good handling, strict parsing, timeouts, retries,
circuit breaker, budgets, fallback, and telemetry are locally verified. No live
provider credential was supplied, so actual model behavior, provider billing,
rate limits, or Secrets Manager retrieval were not asserted.

**LAB_VERIFICATION_REQUIRED — artifact/canary surfaces.** Real Linux scanner
tools run locally, but production ClamAV feed updates and real Windows artifact
placement/rollback/observation need a Windows sandbox. Canary Terraform
validates against provider schemas, but public DNS/TLS, API Gateway, WAF,
Lambda, DLQ, and an external callback were not deployed.

**LAB_VERIFICATION_REQUIRED — hosted CI.** GitHub Actions itself has not run
inside an actual runner (see Task #17 entry above); the workflow YAML parses
cleanly and every individual command it invokes was independently verified
locally, but the workflow as a whole is untested.

**RESOLVED (GitHub-readiness pass, 27 July 2026)** — `make scan-dependencies`
(`.venv/bin/pip-audit`) previously could not query vulnerability metadata
because network escalation was not approved in that session; re-run with
network access available and completed successfully: `No known vulnerabilities
found` (one package, `mirage` itself, skipped as expected — a local editable
install, not published to PyPI). This is a real, clean result, not a
re-assertion of the old blocked state — re-verify again close to the actual
push/release date since new CVEs can appear after this scan.

**Known bounded-cancellation limitation.** Async callers can cancel evidence
operations and boto3 requests have bounded connect/read timeouts, but a Python
thread already executing a synchronous boto3 call cannot be forcefully stopped.
The operation may finish in the background; sequence idempotency makes a retry
safe. Production fault-injection should verify this under real S3 latency.

**Operational reconciliation state.** If legacy or manual data creates more
than one active deployment for the same artifact, artifact-wide revocation
returns a conflict and requires operator reconciliation. New deployment
requests prevent this state.

## GitHub-readiness verification pass — 27 July 2026

**RESOLVED** — see `ENGINEERING_REMEDIATION_STATUS.md` F-14 for full detail.
Every F-01..F-13 finding's documented evidence (test files/counts, tfsec
baseline) was independently re-run against a clean `remediation/github-readiness`
branch and matched exactly. Two real, previously-untested gaps were found and
fixed in F-12's own tooling, discovered specifically because F-12's new files
had never actually been in the tracked/staged state their own logic depends
on: (1) `scripts/audit-public-repository` would have failed permanently on
its own source once committed (self-referential private-key-marker match);
(2) `gitleaks:allow` inline comments do not retroactively suppress a finding
already recorded in an earlier historical commit — fixed with a
fingerprint-scoped root `.gitleaksignore` entry, no history rewrite.

**Not yet done, tracked for the operator:** no verified secret was found
requiring a git-filter-repo history rewrite, so none is proposed. Windows
(`WINDOWS_VERIFICATION_REQUIRED`) and AWS (`AWS_VERIFICATION_REQUIRED`) items
already listed throughout this file are unchanged by this pass — this pass
verifies engineering completion and local-test honesty, not lab execution.
