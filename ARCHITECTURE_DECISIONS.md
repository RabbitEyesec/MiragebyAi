# Architecture Decision Records

## ADR-0031: Dashboard OIDC login incident — root causes and fixes

A local end-to-end login audit (landing → sign in → Keycloak → callback →
dashboard → refresh → logout → login again, no mocks) found four
independent, real bugs, each masking the next:

1. **Port drift.** `next dev`'s default silent port-fallback (3000 → 3001
   when 3000 is taken) was never reflected in the Keycloak client's
   `redirectUris`/`webOrigins`/`rootUrl`/`baseUrl`, which were also only
   ever set once at client *creation*, never updated. Fix: `next dev -p
   3001` (explicit `-p` disables Next's silent-retry, per its own source —
   a taken port now fails loudly instead of silently moving); Keycloak
   client provisioning (`libs/mirage_common/keycloak_admin.py`) now
   PUTs/updates this config on every run, not just on first create.
2. **`__Host-` cookies without `Secure`.** `dashboard/lib/session.ts` only
   set the `Secure` attribute when `NODE_ENV === "production"`. Browsers
   reject any `__Host-`-prefixed `Set-Cookie` lacking `Secure` outright, so
   under plain `next dev` the OIDC state/verifier/session cookies were
   silently never stored — `Secure` is now unconditional (`http://
   localhost` is a secure context in every modern browser, so this holds
   for local dev too).
3. **Oversized session cookie.** `writeTokens` encrypted
   accessToken+refreshToken+idToken into one cookie; with this realm's 8
   roles the encrypted, base64url-encoded blob exceeds a browser's
   4096-byte per-cookie limit and is silently dropped — a "successful"
   login reverted to logged-out on the very next request. Fixed by
   splitting into three independent cookies (session/refresh/idtoken),
   each comfortably under the limit regardless of future role/claim growth.
   Separately, `next/headers`'s `cookies().delete(name)` sends a Set-Cookie
   with no `Path`/`Secure` at all, so it can never actually clear a
   `__Host-` cookie either — every deletion now goes through a helper that
   passes the full attribute set.
4. **CSRF token coupled to unrelated feature data.** The dashboard's logout
   button sends `x-csrf-token` from React state populated by
   `Promise.all([api.session(), api.cases(), api.operations()])`; since
   this environment's `mirage-api` has no `/api/v1/dashboard/{cases,
   operations}` routes yet (a separate, pre-existing gap — the UI's own
   `DegradedState` is the correct, by-design response to that), the whole
   `Promise.all` rejected and the CSRF token was never set, so every
   logout was rejected as a CSRF failure. Fixed by fetching the session
   (and its CSRF token) independently of the feature-data fetch.

`scripts/dev-auth-doctor` (new) checks the canonical URL, Keycloak client
config, dev users, and `dashboard/.env.local` consistency in one gate, and
`dashboard/tests/e2e-auth/real-auth.spec.ts` (new, `make
test-dashboard-auth-e2e`) exercises the full flow against a real Keycloak —
no mocks, separate from the `MIRAGE_E2E_FIXTURE`-mocked suite in
`dashboard/tests/e2e/dashboard.spec.ts`.

## ADR-0030: Canonical dashboard projection, not browser reconstruction

The UI consumes a versioned, gap-aware PostgreSQL projection with durable
provenance. Cytoscape and Three.js share one filtered model. SSE invalidates;
it does not become the source of truth. This keeps parity testable and prevents
the browser from inventing relationships after reconnect.

## ADR-0029: OIDC BFF and explicit privilege roles

Authorization Code + PKCE terminates at a same-origin Next.js BFF. Encrypted
HttpOnly cookies hold tokens; the browser never receives a bearer token.
`export`, `direct_intervention`, and `emergency_control` are separate roles,
and API/case authorization remains authoritative.

## ADR-0028: Reports are signed evidence packages

PDF and DOCX are views of the same classified JSON model. Every statement has
one allowed category and provenance. The canonical ZIP signs its manifest and
is verified before evidence-ledger acquisition; format rendering never decides
truth.

## ADR-0027: Destructive and fault workflows are argv-only, exact-scope plans

Teardown and Profile B fault injection use explicit confirmations, exact
environment/case or test IDs, ordered journals, and argv arrays without shell
evaluation. Missing evidence, recovery, revocation, or inventory proof blocks
completion.

## ADR-0026: Acceptance packages evidence but never promotes NOT_RUN

The immutable spec contains 25 numeric targets and 36 steps. Local substitutes
are named. A single Profile B input can be signed and verified but cannot set
overall acceptance; the full clean run must pass twice.

Records every point where an engineering choice was made that the specification
(`Mirage_Complete_Engineering_Specification.docx`, hereafter "the spec") left open,
or where local environment constraints required a documented deviation from a
"locked technology" being *run* (as opposed to *specified*) during Prompt 1.

No ADR here substitutes a locked technology. Where a locked technology cannot be
executed in this development environment (e.g. RD Gateway needs Windows Server;
WiX needs a Windows build host), the technology is still the target — only local
*execution* is deferred to a lab, and that is tracked in `EXTERNAL_DEPENDENCIES.md`
and `LAB_EXECUTION_CHECKLIST.md`, not worked around with a substitute.

---

## ADR-0001: Repository root is the monorepo root (no nested `mirage/` directory)

**Status:** Accepted

**Context:** The spec's Appendix A shows the layout rooted at a directory literally
named `mirage/`. The working repository directory is already the repository
root itself.

**Decision:** Treat the existing repository root as the monorepo root described in
Appendix A. `contracts/`, `schemas/`, `services/`, `agents/`, `dashboard/`, `infra/`,
`installers/`, `tests/`, `scripts/`, `docs/` live directly under the repo root, not
under a nested `mirage/` subfolder.

**Why:** A nested `mirage/mirage/...` path adds no value and would only exist to
match a folder name that is cosmetic in the spec. Import paths, Docker build
contexts, and CI workflow paths are all simpler with a flat root.

**Consequence:** Any reference elsewhere in this document set to `mirage/contracts/...`
should be read as `<repo-root>/contracts/...`.

---

## ADR-0002: Windows agents (MirageEndpoint, MirageSpider, MirageEnvironmentController) are implemented in Python 3.12

**Status:** Accepted

**Context:** Appendix G specifies account model, privilege boundaries, and channel
behaviour for the two sandbox-side services, and Step 4 specifies MirageEndpoint.
The spec does not lock an implementation language for these services — it locks
WiX-built signed MSI as the *packaging* mechanism, not the runtime.

**Decision:** Implement all three Windows services in Python 3.12, using
`pywin32` (`win32serviceutil.ServiceFramework`) as the Windows service shim. All
business logic (enrolment, queueing, sequencing, command validation, journalling)
lives in plain Python modules with no Win32 dependency, imported by a thin
`win32serviceutil`-based entrypoint. The shared `contracts` package (Pydantic
models generated from `/schemas`) is imported directly by the agents — no
duplicate envelope types.

**Why:** (1) Reuses the same contracts package, event envelope validation, and
test tooling as the backend, instead of a second language stack (e.g. C#/.NET)
duplicating envelope/schema logic. (2) Keeps the whole platform on one locked
language (Python 3.12) except where a technology is explicitly locked otherwise
(React/Next.js for the dashboard). (3) Splitting Win32-specific code from logic
means the logic modules run and unit-test on macOS/Linux CI, while only the thin
service shim requires a Windows host to execute — maximizing what Prompt 1 can
actually prove without lab access.

**Consequence:** `pywin32` and the Win32 service shim cannot be imported or run on
macOS/Linux. CI and this development environment exercise the logic modules
directly (constructing them without the `ServiceFramework` base). Actually running
as a Windows service, installing via MSI, and integrating with Sysmon/Elastic
Agent/Windows Firewall/registry ACLs is LAB_VERIFICATION_REQUIRED on a Windows
host per `LAB_EXECUTION_CHECKLIST.md`.

---

## ADR-0003: Pin Python 3.12 explicitly; host/dev shell may show 3.13

**Status:** Accepted

**Context:** The spec locks Python 3.12. The development machine's default
`python3` is 3.13.3.

**Decision:** All containers (`infra/compose/docker-compose.yml`), CI workflows,
and `pyproject.toml` (`requires-python = "==3.12.*"`) pin Python 3.12 explicitly.
Local venvs are created with `python3.12` if present, falling back with a clear
`scripts/doctor` warning if only 3.13 is available on a given workstation.

**Why:** Cannot change what Python version ships on the host machine; the
authoritative runtime is the one declared in `pyproject.toml`/Dockerfiles, which
CI and containers enforce regardless of host default.

**Consequence:** `scripts/doctor` checks and reports the discrepancy rather than
silently passing. Contributors on this machine run tests inside Docker/CI or a
`python3.12` venv, not bare `python3`.

---

## ADR-0004: Step 7b "development sandbox target" is split into a Windows target (lab-only) and a Linux broker-testing stand-in

**Status:** Accepted

**Context:** Step 7b requires "a real steering target" so Stage 3 brokers have
something to route HTTP/SSH/RDP connections to. The actual target — per Appendix
G/H — is a Windows sandbox VM running MirageSpider + MirageEnvironmentController
and Windows-native HTTP/SSH/RDP services. That VM requires AWS EC2 (or another
Windows host) and is out of reach of this local environment.

**Decision:** Two things exist under Step 7b, clearly labeled:
1. `infra/compose/sandbox-target/` — a containerized Linux stand-in exposing
   HTTP, SSH, and an RDP-protocol-shaped TCP listener with the same
   `/route`-selected upstream contract, used ONLY so the Stage 3 broker tests
   (Nginx `/route` calls, SSH `ForceCommand` selector, RDP gateway policy logic)
   can be exercised end-to-end locally against real sockets.
2. `infra/packer/windows-sandbox/` and `scripts/sandbox-dev/` — the real Windows
   dev-sandbox build definition and verification scripts called for by Step 7b,
   which require a Windows host/AMI and are LAB_VERIFICATION_REQUIRED.

**Why:** Being explicit prevents exactly the failure mode the user's brief warns
against — claiming a broker "reaches the sandbox" when it only reached a
same-shape stand-in. Every test and doc referencing the stand-in says so in its
name and output.

**Consequence:** Broker acceptance criteria that depend on genuine Windows
fingerprint/service behaviour (fingerprint gate, Spider telemetry from the
sandbox) remain LAB_VERIFICATION_REQUIRED even though routing-selection logic
itself is locally proven.

---

## ADR-0005: Terraform/Packer/tfsec/AWS CLI installed locally for static validation only

**Status:** Accepted

**Decision:** `terraform fmt -check`, `terraform validate`, `tfsec`, and
`packer validate` are run for real in this environment (tools installed via
Homebrew's `hashicorp/tap`). `terraform apply`/`destroy`, `packer build`, and any
AWS API call remain LAB_VERIFICATION_REQUIRED — there is no AWS account
configured in this session, and none should be assumed.

**Why:** Maximizes real, provable local verification while keeping cloud spend
and blast radius at zero until a human explicitly runs the lab steps in
`LAB_EXECUTION_CHECKLIST.md` against a real AWS account with billing alarms set
per Appendix L.

---

## ADR-0006: PostgreSQL, NATS JetStream, Elasticsearch, Keycloak, step-ca, Nginx run as real local Docker containers for testing

**Status:** Accepted

**Decision:** `infra/compose/docker-compose.yml` and
`infra/compose/docker-compose.test.yml` define real containers for every stateful
locked dependency Stage 0–4 needs. Integration tests in `tests/integration/` run
against these real containers (ephemeral, `docker compose -f ... up` in CI and
locally), not mocks or in-memory fakes.

**Why:** The user's completion bar explicitly rejects "no fake success" —
in-memory fakes of Postgres/NATS would satisfy that bar in letter but not
substance. Docker is available locally, so there is no reason to fake these.

**Consequence:** `make test-integration` requires Docker to be running; `scripts/doctor`
checks for it.

---

## ADR-0007: RD Gateway (Step 8d) is configuration-and-scripts only in Prompt 1

**Status:** Accepted

**Context:** Windows RD Gateway is a Windows Server role. There is no Windows
Server host (physical, VM, or cloud) available in this session.

**Decision:** Author real PowerShell configuration scripts, RAP/CAP policy
definitions, and test/acceptance-checklist scripts under `infra/rdp/`, matching
Appendix H.3 exactly. None of it is executed here. All of it is
LAB_VERIFICATION_REQUIRED, tracked per-file in `REQUIREMENTS_TRACEABILITY.md`.

---

## ADR-0008: WiX MSI sources are authored but not compiled in this environment

**Status:** Accepted

**Context:** WiX Toolset (`candle`/`light` or WiX v5 `wix build`) requires a
Windows host (or at minimum the .NET-based WiX v5 CLI, which is not installed
here and whose MSI output still targets Windows installation semantics that
cannot be meaningfully verified on macOS).

**Decision:** Real `.wxs` source, `.wixproj`, and PowerShell build scripts are
authored under `installers/endpoint/`, `installers/spider/`, `installers/controller/`.
XML well-formedness is validated locally (`scripts/validate-config` /
dedicated test). Actual MSI compilation, install/upgrade/rollback/uninstall
execution against a real Windows machine is LAB_VERIFICATION_REQUIRED.

---

## ADR-0009: Schema/contract toolchain — JSON Schema 2020-12, `datamodel-code-generator` for Pydantic, `quicktype`-style hand-rolled generator for TypeScript

**Status:** Accepted

(Recorded in full at Stage 0 Step 1 implementation; see
`docs/adr/0009-contracts-toolchain.md` for the detailed rationale, including why
TypeScript generation is a small first-party script rather than an added
dependency.)

---

## ADR-0010: ULID generation and validation

**Status:** Accepted

(Recorded in full at `docs/adr/0010-ulid.md`.) Python `python-ulid` library for
generation; canonical-uppercase-Crockford-Base32 regex validation is
hand-written in `contracts/python/mirage_contracts/ulid.py` so validation has no
runtime dependency on any one library's internal representation and can be
mirrored exactly in TypeScript.

---

## ADR-0011: IAM — one control-node instance role (union of five least-privilege policies), not per-service roles

**Status:** Accepted

**Context:** The spec locks "Server packaging: Docker Compose (single control
node)" for the five Prompt-1 control-plane services (mirage-api,
mirage-worker, mirage-outbox-relay, mirage-agent-ingestion,
mirage-sandbox-gateway). Plain Docker Compose on one EC2 instance has no
per-container IAM isolation mechanism — that requires ECS/Fargate task
roles or a sidecar credential broker, neither of which is in the locked
technology list.

**Decision:** `infra/terraform/modules/iam` defines a distinct least-privilege
`aws_iam_policy` per service (real, reviewable, individually attachable) and
attaches the union of all five to one `aws_iam_role.control_node` /
instance profile, which is what the EC2 instance running Docker Compose
actually assumes.

**Why:** This keeps the per-service policies honest and ready for a future
ECS/Fargate migration (where they'd become task roles directly, no rewrite)
while being truthful about today's actual blast radius: a container escape
on the control node inherits the union of all five services' AWS
permissions, not just its own service's. Pretending otherwise (e.g. writing
only one merged policy with no per-service breakdown) would hide that
distinction instead of documenting it.

**Consequence:** `KNOWN_ISSUES.md` records this as a real, currently-accepted
limitation. Endpoint and sandbox EC2 instances get NO instance profile at
all — they authenticate via step-ca mTLS only (ADR-0002), so this limitation
never extends past the single control node.

---

## ADR-0012: Terraform validated locally without a live AWS account, using static HCL-based network policy tests

**Status:** Accepted

**Context:** Step 2's "network rules have automated policy tests" acceptance
line, and the general instruction not to fake success, both need a real test
— but `terraform plan` against the `hashicorp/aws` provider still makes live
AWS API calls (STS, partition/account lookups) even with dummy credentials
and cannot run fully offline the way `terraform validate` can.

**Decision:** `terraform validate` and `terraform fmt -check` run for real
(offline, no AWS calls). `tfsec` runs for real (static analysis, no AWS
calls). Network isolation invariants (attacker cannot reach control/evidence,
no private subnet has a public IP, sandbox egress restricted to approved
control services, etc.) are additionally tested by
`tests/unit/test_terraform_network_policy.py`, which parses the raw `.tf`
HCL via `python-hcl2` and asserts the exact security-group/subnet
invariants Step 2 requires — directly against the source configuration, not
a plan or live state.

**Why:** This is real, deterministic, fully offline verification of the
actual isolation rules the spec cares about, rather than a weaker "the HCL
merely parses" check. `terraform plan`/`apply` reachability tests against
real deployed resources remain LAB_VERIFICATION_REQUIRED (Step 2 lab
acceptance) — that is the one thing that genuinely cannot be done without an
AWS account, and is tracked as such.

---

## ADR-0013: Certificate revocation is Postgres-authoritative + passive step-ca revocation, not active/OCSP

**Status:** Accepted

**Context:** Step 3 requires "revoked-client connection rejection." Testing
directly against the running dev step-ca (badgerv2 storage backend)
showed `POST /1.0/revoke` returns `501 "non-passive revocation not
implemented"` for active (immediate, CRL/OCSP-backed) revocation, but
succeeds (`200 OK`) when the request body includes `"passive": true` — this
was discovered empirically, not assumed from documentation (see
TEST_RESULTS.md §Step3).

**Decision:** Two layers, both real:
1. **Postgres `agents.status`** is the authoritative, immediately-effective
   revocation check. `mirage_agent_ingestion.enrollment.is_agent_active()`
   is called on every connection/event-acceptance path; a REVOKED row is
   rejected instantly, with zero dependency on CA-side revocation
   propagation delay.
2. **step-ca passive revocation** is still called on every `revoke_agent()`
   — it guarantees the certificate can never be *renewed* again, so even in
   a hypothetical bug where the Postgres check was skipped, the certificate
   cannot outlive its short natural lifetime (<=24h for agent certs, per
   infra/step-ca/PROFILES.md) by renewing itself.

**Why:** Passive revocation is explicitly what step-ca's own help text
recommends pairing with short certificate lifetimes ("works best with short
certificate lifetimes") — which is already Mirage's design. Chasing active
revocation would mean standing up OCSP/CRL infrastructure step-ca's badger
backend doesn't support out of the box, for a guarantee Postgres already
provides faster and more simply.

**Consequence:** A production deployment using a step-ca DB backend that
does support active revocation (e.g. MySQL/PostgreSQL backend, per
smallstep's docs) could upgrade to active revocation later without changing
Mirage's own code — `revoke_certificate()` always requests passive, which
remains valid regardless.

---

## ADR-0014: Step 4b's engineering console is entirely platform_admin-gated, and adds an extra `mirage-health` data stream beyond Appendix E's literal seven

**Status:** Accepted

**Context:** Step 4b builds the first HTTP surface with real authentication
(`GET /api/v1/health`, `/agents`, `/events/recent`, `/cases`, plus a
synthetic end-to-end health-check transaction). The spec's role model
(Appendix — roles table) defines several roles (`platform_admin`,
`incident_responder`, `read_only`, etc.) intended for the eventual Stage 9
analyst dashboard. Appendix E's Elasticsearch data-stream list has seven
named streams, none of which is a general "is the platform itself healthy"
stream — the closest is per-domain telemetry (endpoint, network, etc.).

**Decision:**
1. Every route in this console requires `platform_admin`, full stop — no
   role-differentiated access is implemented yet. This console is an
   engineering/ops diagnostic tool built ahead of Stage 9, not the
   analyst-facing product; giving it fine-grained per-role access now would
   mean designing that access model twice (once here, throwing it away, then
   again for real in Stage 9 against the real case/telemetry data model).
2. A new `mirage-health` Elasticsearch data stream was added (composed of
   the shared `mirage-common-mappings` component template and the
   `mirage-set-timestamp` ingest pipeline already built in Step 4), carrying
   synthetic and future real platform-health events. This is additive to,
   not a replacement for, Appendix E's seven streams — health/liveness data
   has different retention needs (short-lived, operational) than the
   evidentiary telemetry streams (long-lived, case-linked), so co-mingling
   them in one stream would force one retention policy to serve two
   different purposes.

**Consequence:** When Stage 9 builds the real dashboard, `require_any_role`
(already written generically in `mirage_common/oidc.py`, not hardcoded to
`platform_admin`) will need per-endpoint role sets instead of the single
blanket check in `mirage_api/app.py::require_platform_admin` — tracked in
KNOWN_ISSUES.md so it isn't mistaken for a finished per-role model.

---

## ADR-0015: MirageSpider (Step 5) — shared agent transport library, single-event telemetry submission, tamper events routed to the audit stream, and the Controller interlock needs no new mechanism

**Status:** Accepted

**Context:** Step 5 builds MirageSpider, the second Windows agent after
MirageEndpoint (Step 4). Appendix G specifies MirageSpider and
MirageEnvironmentController share almost the same shape (LocalService,
encrypted queue + sequence store, mTLS → Agent Ingestion), and its own text
flags four things this ADR resolves: "Local state: Encrypted queue,
sequence store" (identical wording to Step 4's own requirement), "Tamper +
health high-priority", and "If the Spider fails, adaptive actions freeze."

**Decisions:**

1. **Shared agent transport library.** `EncryptedEventQueue` (queue.py),
   `KeyProvider`/`LocalFileKeyProvider`/`DpapiKeyProvider` (keys.py), and the
   enroll/heartbeat/telemetry HTTP client were moved from
   `agents/mirage-endpoint/mirage_endpoint/` into
   `libs/mirage_common/{agent_queue,agent_keys,agent_http_client}.py`.
   `win_service.py` (Step 4) already left an explicit comment anticipating
   this ("replaced with a real transport call in Step 5/9b's shared
   pattern") — the code was byte-for-byte identical between what Step 4
   built and what Step 5 needed, differing only in a queue-key description
   string and (now) an added `submit_telemetry()` method. Business
   orchestration logic (`EndpointServiceLogic`/`SpiderServiceLogic` proper —
   enroll(), the payload shapes, record_observation/record_tamper) stays
   per-agent, not extracted, since Step 9b's Environment Controller will
   likely look different again and two data points aren't enough to find
   the right further abstraction.

2. **Telemetry submission is one event per HTTP call**
   (`POST /api/v1/agents/{id}/telemetry`), not a batch endpoint. This
   matches the granularity `EncryptedEventQueue.peek_batch()` /
   `flush_queue()` already assumed (per-event `send_fn(event) -> bool`,
   stop-at-first-failure to preserve order) and keeps the server-side
   monotonic-sequence check (`SELECT ... FOR UPDATE` on `agents.last_sequence`,
   reject with 409 if not strictly increasing) a single, simple
   read-check-write per request rather than needing partial-batch-result
   semantics nothing in the spec asked for.

3. **`spider.tamper` events route to `audit.spider.tamper`
   (MIRAGE_AUDIT stream), not a telemetry subject** — Appendix G's
   "Tamper + health high-priority" is satisfied two ways: health already had
   its own priority path (heartbeat, a separate endpoint/cadence from
   routine telemetry, unchanged since Step 4); tamper gets a NEW priority
   path — `SpiderServiceLogic.record_tamper()` attempts immediate delivery
   first (bypassing the routine queue entirely on success) and only falls
   back to the same durable encrypted queue on failure, so a tamper event is
   never lost, merely delayed. Routing it into the immutable, one-year-retention
   audit stream (rather than the 24h-retention telemetry stream) reflects
   that "something tried to interfere with the sensor" is inherently
   security-relevant regardless of whether the case it happened in is ever
   revisited.

4. **The Controller interlock ("if the Spider fails, adaptive actions
   freeze") needs no new signaling mechanism.** Every heartbeat already
   updates `agents.last_seen_at`/`agents.status` in Postgres — the same row
   Step 4b's `GET /api/v1/agents` already surfaces. Step 9b's Environment
   Controller (not yet built) implements the freeze by checking that row's
   staleness before executing any adaptive action, not by MirageSpider
   pushing a signal to the Controller directly — the two agents are
   deliberately never wired to each other (Appendix G: "The two are never
   combined"), only to the shared control plane.

**Consequence:** MirageEndpoint's own local queue (`win_service.py`) still
has no concrete telemetry content to send — Sysmon/OS telemetry ships via
the separate Elastic Agent → Fleet path, not through MirageEndpoint's own
queue — so wiring its `flush_queue()` call to `AgentHttpClient.submit_telemetry`
is deferred until MirageEndpoint has a real event type of its own to emit;
the transport to do so now exists and is proven correct via MirageSpider.

---

## ADR-0016: Case state machine — linear happy-path transitions only, `case_id` enforced as a real ULID at the DB level, and the outbox relay polls rather than blocking on LISTEN/NOTIFY

**Status:** Accepted

**Context:** Step 6's literal Done-when line is "A case runs every state and
replays with zero conflicting-state bugs and zero duplicate effective
events" — the spec lists a single linear chain of ten states
(CREATED→...→DESTROYED) and does not describe abort/loop/re-engagement
edges anywhere. Building `transition_case()` against real Postgres
immediately surfaced a real bug: migration 0002 (Step 4b's bootstrap)
defined `cases.case_id` as a bare `TEXT PRIMARY KEY`, but Appendix C's event
envelope requires `case_id` to be a canonical ULID (or null) — the first
integration test run failed with `EnvelopeValidationError` the moment
`transition_case()` tried to build a real `case.state_changed` event
carrying a non-ULID test `case_id`.

**Decisions:**

1. **`ALLOWED_TRANSITIONS` implements only the nine linear edges the spec
   states**, not a speculative full graph (no abort-from-any-state, no
   MONITORING loop, no re-engagement). Inventing transition rules the spec
   doesn't specify risks building the WRONG graph that Step 7's real
   detection/steering logic then has to work around or silently violate.
   `InvalidTransitionError` on `DESTROYED` is deliberately generic ("no
   further allowed transition") rather than a fixed terminal-state message,
   so extending the graph later is additive, not a rename.

2. **`cases.case_id` gets a real DB-level CHECK constraint**
   (`case_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'`) added in migration 0003 —
   not just an application-level convention. This closes the exact bug the
   first test run caught, permanently, at the layer that can't be bypassed
   by a future caller that forgets to generate a real ULID. Added in 0003
   rather than retrofitted into 0002 so Step 4b's already-`ACCEPTED`
   migration/tests are never touched.

3. **`mirage-outbox-relay` polls every 250ms rather than blocking on the
   `outbox_events_channel` LISTEN/NOTIFY the migration's trigger emits.**
   §6.3 explicitly names both ("Poll 250ms, woken by NOTIFY") — the polling
   loop is unconditionally required as the correctness backstop regardless;
   NOTIFY-driven wake is a latency optimization (near-zero-latency dispatch
   instead of an up-to-250ms worst case) that adds real complexity in
   psycopg3's async LISTEN/NOTIFY API interacting correctly with the batch
   `FOR UPDATE SKIP LOCKED` transaction pattern. The trigger/channel already
   exist in the schema for a future relay revision to consume; nothing about
   today's polling-only relay needs to change for that upgrade to be purely
   additive.

**Consequence:** `mirage_common.case_state_machine` and
`mirage_outbox_relay.relay` are both framework-agnostic (no FastAPI import,
no HTTP), matching `mirage_agent_ingestion.enrollment`'s existing pattern —
Step 7's detection-into-cases adapter and any future HTTP endpoint that
triggers a transition (Stage 3's steering approval, eventually) call
`transition_case()` directly rather than duplicating its transaction logic.

---

## ADR-0017: Detection correlation — a new `cases.correlation_key` column (not a new table), and "adapter never steers" enforced by omission

**Status:** Accepted

**Context:** Step 7 builds the adapter that turns `detection.raised` events
into cases: "Consume detections; dedup; correlate into one case; assign
severity + confidence; publish investigation.created via outbox. Adapter
never steers. Case creation + steering are operator-approved." Appendix B's
table list does not include a dedicated "detections" or "case_detections"
tracking table — only `cases`, `case_state_transitions`,
`processed_events`, `outbox_events`, and `audit_events` (all already built
in Step 6) are available.

**Decisions:**

1. **Correlation is a single new column, `cases.correlation_key`**
   (migration 0004), with a partial unique index
   (`WHERE correlation_key IS NOT NULL`) that both enforces "one case per
   correlation_key" and IS the lookup query. A second detection sharing a
   `correlation_key` is recorded via an `audit_events` row
   (`detection.correlated_to_existing_case`) rather than a new table —
   Step 6 already built `audit_events` for exactly this "something happened
   to a case, durably record it" purpose, and Appendix B doesn't call for
   more structure than that.

2. **Dedup reuses `processed_events`** (Step 6's schema, unused until now —
   closes the KNOWN_ISSUES.md gap noted when Step 6 shipped): a redelivered
   `detection.raised` event (NATS at-least-once) is recognized via
   `(consumer_name='mirage-detection-adapter', event_id)` and produces zero
   additional effect, looked up via the existing case's `correlation_key`
   rather than re-running correlation logic.

3. **"Adapter never steers" is enforced by omission, not a guard clause.**
   `mirage_common.detection_correlation.correlate_detection()` has no
   import of, or call to, `case_state_machine.transition_case` anywhere in
   it — a newly created case is inserted directly with `state='CREATED'`
   (the column's own DEFAULT) and never touched again by this module. There
   is no code path in Step 7's adapter that could advance a case past
   CREATED even by accident, which is a stronger guarantee than a runtime
   check would be.

**Consequence:** `mirage_common.detection_correlation` and
`mirage_worker.detection_adapter` are the FIRST real writer to
`processed_events` and the first real consumer built on top of
`DeadLetterAwareConsumer` for a business (non-infrastructure) subject —
future Stage 3+ consumers (steering approval, sandbox command results) can
follow the exact same two-module split (a framework-agnostic correlation/
transaction function + a thin NATS consumer-loop wrapper) `mirage-worker`
now establishes.

---

## ADR-0018: Dev sandbox target (Step 7b) — real HTTP/SSH containers, RDP explicitly out-of-scope, fingerprint baseline is a data artifact not the gate itself

**Status:** Accepted

**Context:** Step 7b's Build line says "Minimal Windows sandbox with Spider
+ Controller + HTTP/SSH/RDP services, so brokers have a real target" and
"a fingerprintable profile," but explicitly "Stands on: Step 5" (not Step
9b, where MirageEnvironmentController is actually built) and its Done-when
line only requires "The dev sandbox accepts the three protocols and
reports Spider telemetry." There is no Windows host, no AWS account, and no
viable macOS/Linux-native RDP SERVER available in this environment.

**Decisions:**

1. **The dev sandbox target is real HTTP (nginx) and real SSH
   (linuxserver/openssh-server, key-based auth) containers, not a Windows
   VM.** This is the honest local substitute for "brokers have a real
   target to route to" ahead of Step 9a's actual signed Windows AMI — it
   proves the PROTOCOL surface Stage 3's brokers need to reach, not the
   full Windows guest OS. `infra/compose/docker-compose.dev-sandbox.yml`
   is deliberately a separate compose file/network from the platform's own
   `docker-compose.yml`, matching the SANDBOX network segment's real
   isolation from CONTROL.

2. **RDP is not included, anywhere, and is marked LAB_VERIFICATION_REQUIRED**
   rather than stubbed with something that isn't real RDP. Faking an RDP
   listener that doesn't actually speak the protocol would be exactly the
   "fake success" this build explicitly must not produce; Step 8d's real
   RD-Gateway brokering can only be genuinely proven against Step 9a's real
   Windows sandbox on a real Windows host.

3. **"Spider + Controller" in the Build line is read as aspirational**,
   not a hard Step-7b dependency on Step 9b (Controller isn't built until
   Stage 4, later in the numbered order, which would make a literal
   same-step dependency impossible). Spider's ALREADY-PROVEN business logic
   (Step 5) is what demonstrates "reports Spider telemetry" here — enrolled
   against the real live agent-ingestion server, recording real observation
   events about the real HTTP/SSH services actually running on this
   target. Controller's role in a dev sandbox is Step 9b's own concern.

4. **The fingerprint baseline (`infra/fingerprint/dev-sandbox-baseline.v1.json`,
   `baseline.schema.json`) is a versioned DATA artifact, not the comparison
   harness.** §6.5 calls the baseline "a versioned file with named
   comparators" — Step 7b's job is producing that file, structured exactly
   per §6.5's 8-row checklist (hostname/domain, user profiles, installed
   software, file timestamps, processes/services, network — all MUST;
   uptime, decoy banners — SHOULD). Step 10 ("Fingerprint gate harness")
   owns actually RUNNING comparisons against it. Not part of the Appendix A
   event/command contracts pipeline (it isn't a message envelope), so it's
   validated with a plain unit test against a hand-written JSON Schema,
   matching `config/schema.json`'s precedent rather than the codegen path.

**Consequence:** Step 8b/8c's HTTP/SSH brokers (Stage 3, next) have a real,
already-tested target to route real connections to in local dev — no
target-side work is needed when those brokers are built. Step 8d's RDP
broker will have nothing to route to locally until a real Windows sandbox
exists; its own tests will need to be scoped around that same LAB boundary.

---

## ADR-0019: /route decision API — mTLS-authenticated (not OIDC), one Postgres EXCLUDE constraint enforces the overlap rule, steering.decision_recorded published on every resolution (not just writes)

**Status:** Accepted

**Context:** Step 8a builds §6.1's mechanism: `routing_decisions` table +
`/route` + a 1-second TTL cache, plus (per §6.1's own diagram, which starts
with "Analyst approves steering") the write side that creates a decision.
Appendix F's endpoint table separately lists `POST /api/v1/cases/{id}/steer`
("Approve steering... Writes routing_decisions; audited") with no other
numbered build step ever mentioned for it between Step 8a and Stage 8 — its
natural home is here, alongside `/route`, since both are the same
mechanism's two halves.

**Decisions:**

1. **`/route` is mTLS-authenticated via the shared Nginx-header contract**
   (`libs/mirage_common/mtls_auth.py`, moved out of
   `mirage_agent_ingestion` since it is now used by two services), not the
   Keycloak-OIDC bearer-token scheme Step 4b's console uses. Brokers are
   machine clients with their own `BROKER_CLIENT` certificate identity
   (already in Step 3's role enum) calling `/route` at high frequency per
   connection — an interactive OIDC token flow doesn't fit that shape.
   `/route` additionally checks the presented certificate belongs to an
   ACTIVE agent with role `BROKER_CLIENT` or `INTERNAL_CONTROL` (defense in
   depth: a revoked or wrong-role certificate cannot keep querying routes),
   mirroring mirage-agent-ingestion's own identity re-verification pattern.
   `POST /steer` stays platform_admin-OIDC-gated (a human analyst action).

2. **The overlap rule ("A unique constraint forbids two active decisions
   sharing one match_key during overlapping validity") is a real Postgres
   `EXCLUDE USING gist` constraint** (migration 0005, `btree_gist`
   extension) over `(match_key, tstzrange(valid_from, valid_until))` — not
   an application-level SELECT-then-INSERT race-prone check. A conflicting
   write raises `psycopg.errors.ExclusionViolation`, mapped to `409` by the
   `/steer` handler.

3. **`steering.decision_recorded` is published on every `/route`
   resolution, not just on decision writes** — the schema's own
   description says "Emitted whenever /route selects a backend... and
   whenever a routing_decisions row is created/revoked," and its `action`
   enum (`CREATED`, `SELECTED`, `FAILSAFE_DEFAULT`, ...) was clearly
   designed for exactly this. A 1-second-TTL cache HIT does not re-publish
   (the durable "we authoritatively resolved this" record happens at the
   source-of-truth refresh point, not on every cached read) — documented in
   `routing.py`'s module docstring so this isn't mistaken for an
   inconsistency later.

**Consequence:** Step 8b's three brokers (next) call `GET /route` exactly
as thin clients (§6.1: "Brokers are thin clients that call /route before
establishing a backend") using their own enrolled `BROKER_CLIENT` identity
— no new auth mechanism needed. "If /route is unreachable, brokers fail
safe to the endpoint and alert" is explicitly the BROKER's own
responsibility (Step 8b), not something `/route` itself can implement.

---

## ADR-0020: The HTTP and SSH brokers are real and locally proven; RDP is a documented design, not fabricated code — plus four empirically-caught nginx/OpenSSH bugs

**Status:** Accepted

**Context:** Step 8b/8c/8d builds "HTTP (Nginx), SSH (bastion), RDP (RD
Gateway) — each a thin /route client with its own acceptance suite
(Appendix H)." mirage-api has no Dockerfile yet (containerizing every
service is Task #17's job), and there is no Windows host anywhere in this
environment.

**Decisions:**

1. **mirage-api runs as a real uvicorn process bound to `0.0.0.0`** (not a
   container) for these tests, reachable from real Docker containers via
   `host.docker.internal` — the same "real server, no packaging work
   assumed" pattern `live_agent_ingestion_server` already established in
   Step 4/5, extended here as `live_mirage_api_server` (conftest.py).

2. **The HTTP broker (Step 8b) is real, working Nginx** —
   `infra/broker/http/nginx.conf.template` — using `auth_request` (not
   njs; §6.1 permits either) to call `/route` before selecting an upstream
   via a `map` directive. Proven end-to-end against real backend
   containers, a real match_key round-trip, and the real 1-second TTL
   cache. TLS is not terminated at this broker for local dev (plain HTTP
   on 8080) — "Mirage owns TLS" is a cert-issuance concern Step 4 already
   proved buildable via step-ca; re-proving it here would test step-ca
   again, not the broker mechanism.

3. **The SSH broker (Step 8c) is real, working OpenSSH** —
   `infra/broker/ssh/mirage-route-selector.sh`, a `ForceCommand` script
   that calls `/route` then `exec`s a NEW ssh session (authenticated with
   the bastion's own key) into whichever backend was selected — proven
   end-to-end with real nested SSH connections landing in the correct
   container. Backend selection happens once, per new connection, before
   any backend channel opens — no claim of moving an established session
   (§6.2's own wording, which this design satisfies structurally, not just
   by convention).

4. **RDP (Step 8d) is a written design document
   (`infra/broker/rdp/README.md`), not code.** RD Gateway's dynamic
   backend-selection point is a compiled COM plugin interface
   (`IRDGPolicyEngine`), not a config file or shell script — there is
   nothing analogous to write and structurally review the way Step 4's
   WiX/PowerShell artifacts could be, without fabricating something that
   could never actually run in that role. `LAB_VERIFICATION_REQUIRED` in
   full.

**Four real bugs, caught empirically before being accepted as working**
(each independently reproduced with a minimal, non-pytest debug harness
before the fix was baked into the real config — same discipline as every
other empirically-discovered bug this build has logged):

- Nginx's `resolver` picked the AAAA (IPv6) record for `host.docker.internal`
  by default, which was unreachable from the container ("Network
  unreachable") — fixed with `resolver 127.0.0.11 valid=5s ipv6=off;`.
- Nginx's `auth_request` module only captures a `$upstream_http_<name>`
  variable from the subrequest response if it is named in an explicit
  `auth_request_set` directive somewhere in the config — referencing it
  directly inside a bare `map` block (with no `auth_request_set`) silently
  reads as empty. Confirmed the header WAS present with a direct `curl`
  from inside the broker container before concluding this was nginx's
  behavior, not mirage-api's.
- `linuxserver/openssh-server` ships `Include /etc/ssh/sshd_config.d/*.conf`
  **commented out** in its default `sshd_config` — a drop-in ForceCommand
  file there is silently never read; the symptom (the client's own
  requested command ran directly on the bastion, not the intended backend)
  looked like a routing bug but was actually a config-loading bug. Fixed
  by appending directly to the real, active config file (confirmed via the
  running `sshd` process's own `-f` argument).
- An SSH session's `ForceCommand` process runs with a sanitized/reset
  environment — it does **not** inherit the container's own `docker run
  -e` variables, even though `docker exec` into the same container sees
  them fine. Fixed by having the init script persist the needed values to
  a file at container-start time (when it DOES have the container's real
  environment) and having the ForceCommand script source that file
  explicitly, rather than assuming env-var inheritance.

**Consequence:** Step 9a's golden AMI (next) is what finally gives the SSH
and RDP brokers a real Windows target instead of the Linux stand-ins Step
7b/8c use; the mechanism itself (call /route, select once, before
establishment) is already proven and does not need to change when that
target arrives — only the backend host/port values do.

---

## ADR-0021: Golden image (Step 9a) — Packer validated by static HCL parsing (not `packer build`), the fingerprint engine ships as a shared library the harness embeds at build time, MirageSpider installs as a plain Windows service (no second WiX project), and manifest signing is a separate post-build script

**Status:** Accepted

**Context:** Step 9a builds "Packer: source AMI -> install -> config ->
employee profile -> fingerprint harness (§6.5) -> malware scan -> SBOM ->
capture -> KMS-sign manifest -> tag AMI with manifest hash. Terraform
consumes only approved AMI IDs." There is no AWS account or Windows host in
this environment (the same constraint ADR-0012 and ADR-0020 already
recorded for Terraform and RD Gateway respectively).

**Decisions:**

1. **The §6.5 comparator engine (`libs/mirage_common/fingerprint.py`) is a
   pure-Python shared library, not build-specific script logic.** It
   implements the exact 8 named checks and 6 comparators the baseline
   schema (Step 7b) defines, plus the MUST=100%/SHOULD>=75% scoring rule,
   and is unit-tested against the REAL Step 7b baseline file
   (`tests/unit/test_fingerprint_engine.py`, 8 tests). Step 9a's
   `run-fingerprint-harness.ps1` embeds it via `python.exe -c` on the
   build guest; Step 10's live pre-`ENGAGING` gate imports the identical
   module. One engine, two callers, no drift between "what the golden
   image checks at build time" and "what the case state machine checks at
   run time."

2. **`_compare_allowed_set_forbidden_patterns` exempts any process listed
   in the baseline's own `allowed` set from the forbidden-pattern check.**
   The Step 7b baseline's own `note` field documents MirageSpider and
   MirageEnvironmentController as "the two sanctioned exceptions to the
   forbidden_patterns rule" — they legitimately match the `Mirage*`
   pattern (any real attacker tooling named that would also be a genuine
   finding) but must not fail the build. Caught by 3/8 unit tests failing
   before this exemption was added; a real bug, not a hypothetical.

3. **Packer is validated by static HCL parsing
   (`tests/unit/test_packer_pipeline.py`, 16 tests via `python-hcl2`), the
   same approach ADR-0012 established for Terraform** — `packer build`
   launches a real EC2 instance and needs a real AWS account + a real
   Windows guest to run WinRM provisioners against; neither exists here.
   The test asserts real structural invariants against the source
   template: no public IP, WinRM-over-TLS, required tags, the exact
   provisioner stage order the spec's own pipeline sentence specifies
   (including that `windows-restart` sits strictly between
   `apply-employee-profile.ps1` and `run-fingerprint-harness.ps1`, since
   `Rename-Computer` needs a reboot before the harness can observe the
   final hostname), and that the Fleet enrollment token flows through a
   `sensitive` Packer variable rather than being hardcoded anywhere.

4. **MirageSpider is installed on the golden image as a plain Python
   Windows service (`install-mirage-spider.ps1`, `pywin32`-registered
   under `NT AUTHORITY\LocalService`), not a second WiX MSI project.** Step
   4's title explicitly says "MirageEndpoint + dev MSI"; Step 5's title
   (MirageSpider) has no such qualifier. Building a second installer
   project for a component the spec never asked to be packaged that way
   would be scope invention, not fidelity — the service still needs to
   exist and be verified on the image, which `apply-mirage-config.ps1`
   and the harness's own observation both do.

5. **The fingerprint harness provisioner's own exit code aborts the
   Packer build on any MUST-check failure** (`run-fingerprint-harness.ps1`
   calls `run_fingerprint_check()` and exits 1 if `report.passed` is
   false) — "the pipeline emits a signed, versioned AMI passing the
   fingerprint harness automatically" is enforced structurally, not by a
   human sign-off step reading a report after the fact. The malware scan
   and SBOM stages run after the harness (test-asserted ordering) so a
   failing image never wastes build time on them.

6. **KMS-signing and AMI-tagging are a separate post-build script
   (`scripts/sign-ami-manifest`), not a Packer provisioner.** Packer's own
   templating has no way to feed a value computed by a guest-side
   provisioner (the fingerprint report's own hash) back into that same
   build's AMI tags, and the build instance is already terminated by the
   time any post-build signing could run. The script is real, reviewed
   boto3 code (KMS `Sign` with `RSASSA_PKCS1_V1_5_SHA_256`, then
   `ec2.create_tags`) with a `--dry-run` path that builds and prints the
   manifest without any AWS calls (exercised without credentials); it
   refuses to sign a manifest whose fingerprint report didn't pass —
   "Terraform consumes only approved AMI IDs" means an unsigned AMI must
   never look approved. `boto3` is kept in a new `aws-lab` optional
   dependency group (pyproject.toml), the same way `pywin32` is
   Windows-only — it is never needed to run the core test suite.
   `LAB_VERIFICATION_REQUIRED`: real execution needs a real AWS account
   and KMS key, same documented-stub pattern as Step 3's Secrets Manager
   loader.

**Consequence:** Step 9b (Environment Controller) adds one more provisioner
stage (`install-mirage-env-controller.ps1`) to this same template — a
placeholder comment already marks where — and Step 10's live gate reuses
`fingerprint.py` unchanged rather than reimplementing comparator logic
against the running sandbox.

---

## ADR-0022: Environment Controller (Step 9b) — synchronous command dispatch over a live WSS connection layered on the transactional outbox, ENV_CONTROLLER's pre-reserved PKI identity reused as-is, and a code-enforced (not just OS-ACL) restricted-mutation-root policy

**Status:** Accepted

**Context:** Step 9b builds "MirageEnvironmentController as a restricted
Windows service (Appendix G) accepting only structured actions... Tags
every output REAL_OS_OUTPUT/DECOY_SERVICE_OUTPUT/AI_GENERATED_INTERACTION/
ANALYST_MESSAGE. Snapshot, reset, rollback, destruction with cert
revocation." Done-when: "A structured action executes and rolls back with
full audit; every output carries a source tag; soft reset < 3 min, full
rebuild < 10 min." There is no Windows host and no Stage 7 artifact/
evidence store in this environment; Step 13 (Stage 6, out of Prompt 1's
scope) is what will eventually decide WHICH actions to send — Step 9b's own
job is the restricted EXECUTION path, not that decision.

**Decisions:**

1. **Command delivery is a synchronous RPC-style round trip over a live
   WebSocket, layered on top of the same transactional-outbox discipline
   every other state change in this system uses — not a §6.3 violation.**
   `POST /api/v1/cases/{case_id}/sandbox-actions` opens one Postgres
   transaction (optimistic-concurrency check against
   `sandbox_instances.state_version`, a PENDING `sandbox_actions` row, an
   outbox row for audit/history) and commits, THEN pushes the command frame
   directly over the connected controller's WebSocket and awaits the real
   result with a bounded timeout, THEN opens a second transaction recording
   the result + bumping `state_version` + writing the
   `sandbox.command_result` outbox event. §6.3's rule ("state changes never
   publish to NATS inline") governs how a state change reaches NATS — both
   of THIS flow's state changes still go exclusively through the outbox;
   the live WS push is the real-time delivery mechanism to one specific
   already-connected process, structurally analogous to Nginx's
   `auth_request` calling `/route` synchronously mid-request (Step 8a) —
   neither bypasses the outbox for anything that actually needs to reach
   NATS.

2. **MirageEnvironmentController reuses the IDENTICAL step-ca enrolment
   mechanism Endpoint/Spider already proved, with ZERO new PKI work** —
   `ROLE_TO_PROFILE["ENV_CONTROLLER"] = "MirageEnvironmentController"` and
   its own JWK provisioner (`mirage-env-controller`) have existed since
   Step 3 (`infra/step-ca/PROFILES.md`, `agents` table's role CHECK
   constraint) specifically anticipating this step. Step 9b is simply its
   first real user — proven end-to-end in
   `tests/integration/test_sandbox_gateway.py` via a real enrolment against
   a real ephemeral step-ca container, not a stub.

3. **The WSS channel to mirage-sandbox-gateway authenticates via the SAME
   mTLS header-forwarding contract every other Mirage endpoint uses**
   (`mtls_auth.py`'s `X-Mirage-Client-Cert-Serial`/`X-Mirage-Proxy-Auth`,
   originally chosen in Step 4 because uvicorn doesn't expose ASGI TLS peer
   certs) — headers arrive on a WebSocket upgrade request exactly like a
   normal HTTP request, so this needed no new auth mechanism, only reusing
   the existing dependency against `websocket.headers`.

4. **"Privilege: Only approved mutation dirs/services" (Appendix G) is
   enforced IN CODE, not left to OS ACLs alone.**
   `mirage_env_controller.actions._resolve_within_roots` resolves `..`
   traversal and rejects any target path that escapes the configured
   `allowed_mutation_roots`, for every handler, before any filesystem call
   — defense in depth alongside whatever ACLs the golden image's installer
   grants the restricted service account, the same "don't rely solely on
   external enforcement" reasoning ADR-0013 already applied to certificate
   revocation. Proven with a real path-traversal attempt in both
   `tests/unit/test_env_controller_actions.py` and end-to-end in
   `tests/integration/test_sandbox_gateway.py`.

5. **PLACE_ARTIFACT requires an explicit `content_b64` param in Prompt
   1, rather than fetching bytes by `artifact_id` from an evidence/artifact
   store.** That store is Stage 7's own scope (`artifacts` table, Appendix
   B — "Upload + scan record"), out of Prompt 1 entirely. Silently
   fabricating placeholder bytes would misrepresent what this action
   proves; requiring real caller-supplied content instead proves the
   REAL mechanism this step owns (placement, hash verification against
   `expected_hash`, metadata application, rollback, output tagging) without
   inventing Stage 7's storage layer. Missing `content_b64` fails loudly
   (`FAILED`, not a silent no-op) — see KNOWN_ISSUES.md.

6. **ENABLE/DISABLE_DECOY_SERVICE and CHANGE_VISIBLE_METADATA's
   Windows-specific attribute bits use a portable local mechanism (a marker
   file; `os.utime` for timestamps) rather than `win32service`/`win32file`
   calls**, keeping `actions.py` importable and unit-testable on any OS
   (the same ADR-0002 boundary `win_service.py` already draws for
   Endpoint/Spider). Real Windows service start/stop and file-attribute
   bits are LAB_VERIFICATION_REQUIRED — see KNOWN_ISSUES.md.

7. **SOFT_RESET/FULL_REBUILD are implemented as a real local
   wipe-and-reseed-from-baseline-snapshot, timed with the real
   `time.monotonic()` clock** — proving the Controller's OWN reset
   mechanism executes correctly and measuring its real (trivially fast,
   locally) elapsed time. This is NOT a substitute for measuring the real
   AWS EC2 terminate-and-relaunch-from-golden-AMI latency the spec's
   "< 3 min / < 10 min" thresholds are ultimately about — that measurement
   needs a real AWS account and is LAB_VERIFICATION_REQUIRED (see
   KNOWN_ISSUES.md); the local timing assertions guard against a
   regression making the LOCAL mechanism itself pathologically slow, no
   more, no less.

**Consequence:** Step 9a's Packer template gets its remaining
`install-mirage-env-controller.ps1` provisioner stage (the placeholder
comment already marks where) once a Windows build host can be exercised.
Step 10's live pre-`ENGAGING` fingerprint gate and Step 13's AI/policy loop
both become real CALLERS of `POST /api/v1/cases/{case_id}/sandbox-actions`
— neither needs to change anything about the delivery mechanism this ADR
establishes.

---

## ADR-0023: Live fingerprint gate (Step 10) — a new Spider telemetry event feeds a Postgres "latest observation cache," missing data is a hard failure by construction (not a special case), and a blocked evaluation commits its own audit trail ahead of the caller's transaction

**Status:** Accepted

**Context:** Step 10 builds "The live fingerprint gate (§6.5) before
ENGAGING... Run the fingerprint harness live. Any MUST failure blocks
advancement. An inconsistent sandbox is worse than none." Done-when: "The
sandbox passes 100% of MUST checks before any case enters ENGAGING." The
comparator engine itself (`libs/mirage_common/fingerprint.py`) was already
built and proven in Step 9a; this step's own scope is wiring a LIVE
invocation of it into the one case transition the spec names, plus getting
real observed data to it from a running sandbox — Step 9a's own live-host
data collection is PowerShell-only (build-time), so a new path was needed
for run-time observations without a Windows host to source them from.

**Decisions:**

1. **A new MirageSpider telemetry event, `spider.fingerprint_snapshot`,
   carries the SAME 8-named-check shape `run_fingerprint_check`'s
   `observed` parameter already expects** — not a repurposed
   `spider.observation` (whose `observation_type` enum and `detail` shape
   are both deliberately narrow and `additionalProperties: false`, per
   Step 5). `SpiderServiceLogic.submit_fingerprint_snapshot()` uses the
   identical immediate-send-else-durable-queue-fallback pattern
   `record_tamper()` already established — freshness matters for a
   blocking gate the same way it matters for a tamper alert. Collecting
   the underlying OS observations on a real Windows sandbox remains
   PowerShell's job (mirroring Step 9a's harness), out of this
   cross-platform module's scope, same ADR-0002 boundary every agent in
   this build already draws.

2. **mirage-agent-ingestion's existing `/telemetry` endpoint upserts the
   latest snapshot per `sandbox_id` into a new Postgres table,
   `sandbox_fingerprint_snapshots`, in the SAME transaction as its
   existing publish-and-sequence-advance work** — a "latest observation
   cache," not a history log, because the gate only ever needs "what does
   the sandbox look like right now." Querying Elasticsearch (where
   telemetry more generally ends up) would work too but adds a second
   read path and eventual-consistency lag to a BLOCKING gate; Postgres,
   already in the transaction, is both simpler and stronger for this one
   read. No foreign key to `sandbox_instances` (Step 9b) — Appendix G:
   "If the Controller fails, observation continues... the two are never
   combined." Coupling Spider's own reporting to the Controller's row
   existing would violate that documented independence.

3. **A sandbox with NO snapshot at all is not a special error case — it
   naturally produces every check reporting "no observation collected"
   via `run_fingerprint_check`'s ALREADY-existing missing-observation
   handling** (`observed.get(check_name)` returning `None`), by passing
   `observed = {}` rather than inventing a parallel
   `NoFingerprintSnapshotError` path. One less thing to keep in sync with
   `fingerprint.py`'s own rules, and it is exactly the right behavior per
   §6.5's own framing — a sandbox nobody has ever reported on is at least
   as "inconsistent" as one that reported and failed.

4. **A BLOCKED evaluation commits its own audit/outbox rows immediately,
   before raising `FingerprintGateBlockedError`** — deliberately breaking
   from `transition_case`/`correlate_detection`/Step 9b's own "caller owns
   the transaction boundary" convention for this ONE path, because "an
   inconsistent sandbox is worse than none" means the failure record
   itself must survive even if the caller's own transaction later rolls
   back for an unrelated reason. A PASSED evaluation does NOT commit
   early — its audit row and the resulting `transition_case` call commit
   together as one atomic unit, preserving the normal convention wherever
   it doesn't conflict with the block-durability requirement.

5. **The optimistic-concurrency check (`expected_version` vs.
   `cases.version`) runs BEFORE the fingerprint evaluation**, even
   though `transition_case` would eventually perform the identical check
   itself — a real bug caught during testing: without this, a stale
   `expected_version` still let a full fingerprint evaluation run and
   commit-durable a `fingerprint_gate.passed` audit/outbox record for a
   transition that then failed and never actually happened. Checking
   version first (same error type `transition_case` would raise) avoids
   ever producing that orphaned, misleading record.

6. **The gate is a no-op pass-through to `transition_case` for every
   transition except SANDBOX_ACTIVE -> ENGAGING** — including invalid
   ones, which are left to `transition_case`'s own `InvalidTransitionError`
   rather than this module inventing a second state-machine validation
   path.

**Consequence:** Step 13's AI/policy orchestration (out of Prompt 1's
scope) becomes a real producer of fresh `spider.fingerprint_snapshot`
events feeding this same gate — nothing about the gate itself needs to
change when a genuine live Windows sandbox exists; only the source of
`checks` data does.

---

## ADR-0024: Task #17 (CI/Docker/Makefile wiring) — five real Dockerfiles reusing existing env-var-driven launcher conventions, two real packaging bugs and one silent lint-coverage gap found and fixed by actually building/running them, and a static-checks-plus-testcontainers CI split

**Status:** Accepted

**Context:** Task #17 is not one of the spec's own numbered Stage/Step
items — the spec's only explicit words on this are "Docker Compose (single
control node)" (a locked technology) and "CI validates golden fixtures for
current + previous versions" (already satisfied by
`scripts/validate-contracts`'s drift/breaking-change check). This task
closes the gap KNOWN_ISSUES.md flagged across Steps 8b/8c/8d/9b: mirage-api
and its four siblings had no Dockerfile, so "Docker Compose" as a locked
deployment technology was only ever proven for the five STATEFUL infra
containers, never for Mirage's own application code.

**Decisions:**

1. **Each of the five services (mirage-api, mirage-agent-ingestion,
   mirage-sandbox-gateway, mirage-worker, mirage-outbox-relay) gets its own
   `services/<name>/Dockerfile`**, all built from the repo root as context
   (pyproject.toml's package-dir mapping requires every `mirage_*` package
   directory to exist for `pip install .` to succeed, even though a given
   image only ever RUNS one of them) — matching pyproject.toml's own
   pre-existing "deployment units stay separated by directory and by their
   own Dockerfile ENTRYPOINT" comment.

2. **Three new launcher scripts** (`scripts/run-mirage-api`,
   `run-agent-ingestion`, `run-sandbox-gateway`) read the identical
   `MIRAGE_POSTGRES_*`/`MIRAGE_NATS_URL` env-var convention
   `scripts/run-outbox-relay`/`run-detection-adapter` already established,
   then call each app's existing `create_app(...)` factory and serve it via
   `uvicorn.run(...)` — no new configuration mechanism invented, and the
   SAME scripts work identically whether run directly on a developer's
   host (against `docker compose up`'s infra containers) or as a
   container's own CMD.

3. **A real `pip install .` inside the first Docker build immediately
   surfaced two genuine, previously-invisible packaging bugs**, neither
   ever caught because every test this entire build ran used
   `pip install -e ".[dev]"` (editable installs path-insert the source
   tree directly, bypassing both gaps):
   - `mirage_contracts.generated` (a real subpackage) was missing from
     `[tool.setuptools] packages` — listing the parent `mirage_contracts`
     package does NOT recursively include its subpackages. Fixed by adding
     it explicitly.
   - The bundled JSON schemas under `mirage_contracts/schemas/` (data
     files `registry.py` depends on at runtime) had no
     `[tool.setuptools.package-data]` entry — a real install would have
     shipped a package with a Schema Registry that finds nothing, failing
     every `validate_event()`/`build_event()` call at RUNTIME rather than
     at import time. Fixed by adding `package-data`.

4. **Every Dockerfile sets `ENV PYTHONUNBUFFERED=1`** — without it,
   `docker logs` on mirage-worker/mirage-outbox-relay (plain `print()`
   loops, no HTTP server whose own logging framework already flushes)
   showed nothing at all until Python's stdout buffer happened to fill,
   since a container's stdout is a pipe, not a TTY. Confirmed empirically:
   identical symptom, identical fix, as the debug-script buffering issue
   documented earlier in this build (Step 8b/8c/8d's TEST_RESULTS entry).

5. **`docker-compose.yml`'s app services require `--env-file .env`
   passed explicitly wherever `docker compose` is invoked** — Compose's
   default `.env` lookup is relative to the directory of the FIRST `-f`
   file (`infra/compose/`), not the caller's cwd, confirmed empirically
   (Compose v5.1.0) when the newly-added REQUIRED variable
   `MIRAGE_PROXY_SHARED_SECRET` (no `${VAR:-default}` fallback, unlike
   every pre-existing variable in the file) turned a previously-silent gap
   into a hard error. `scripts/bootstrap-development`'s own `compose_up()`
   and the Makefile's `compose-up`/`compose-down` targets were both
   missing this flag and are now fixed — meaning `.env`'s actual contents
   were silently never read by either this whole build, only ever falling
   back to the compose file's own hardcoded (matching) defaults.

6. **`mirage-api`'s host port mapping is 18000, not 8000** — port 8000
   was already bound by unrelated software on the verification machine
   (confirmed via `lsof`), a real collision caught by actually running
   `docker compose up` rather than only validating `config`.

7. **`ruff check scripts` was silently checking zero files** — ruff's
   directory-walk only considers `*.py`/`*.pyi` by default, but every CLI
   tool under `scripts/` is an extensionless Python file with a shebang.
   `make lint` had listed `scripts` as a target since the Bootstrap Gate
   step and reported clean the entire build, while pre-commit's ruff hook
   (shebang-aware file-type detection) immediately found 8 real style
   violations across three pre-existing scripts the very first time it
   ran. Fixed with `extend-include = ["scripts/*"]`, and the 8 flagged
   issues (semicolon-joined statements, ambiguous `l` variable names, a
   bare `raise` losing exception context) were fixed for real, not
   suppressed.

8. **CI (`.github/workflows/ci.yml`) is split into offline-only jobs
   (lint/typecheck/unit/contract/validate-contracts/secret-scan — exactly
   `make ci`, so a local failure reproduces identically) and infra-backed
   jobs (integration tests via testcontainers against the runner's own
   Docker daemon; a full `docker compose up` + real health-check wait).**
   Every individual command in this workflow was verified by hand against
   equivalent real infrastructure (see TEST_RESULTS.md); the workflow file
   itself has NOT been executed inside an actual GitHub Actions runner in
   this environment — LAB_VERIFICATION_REQUIRED, tracked in
   KNOWN_ISSUES.md, the same honest boundary already applied to every
   other CI-shaped artifact (Terraform `apply`, Packer `build`) this build
   could only statically validate.

9. **pre-commit is a lightweight local safety net, not spec-mandated** —
   ruff (`--fix`), mypy, the secret scanner, and the contract-drift checker
   as local hooks reusing the EXACT SAME entrypoints `make ci` uses, so
   pre-commit and CI can never silently disagree about what "passing"
   means.

**Consequence:** `scripts/bootstrap-development` now brings up a complete,
real, ten-container stack in one command — the five stateful infra
containers plus all five application services — closing the
containerization gap KNOWN_ISSUES.md tracked since Step 8b/8c/8d.

---

*This file is appended to throughout the build. Each new non-obvious engineering
choice gets a new numbered ADR rather than silently living only in code.*
## ADR-0025: Prompt 2 trust boundaries — exact-version evidence, untrusted AI proposals, fail-closed artifacts, historical canary classification, and evidenced analyst output

**Status:** Accepted for local implementation; external trust anchors require
lab verification.

**Decision:**

1. PostgreSQL is the provenance/control ledger, while immutable bytes live in a
   versioned object store. Every read used for verification or export names the
   recorded version ID; acquisition hashes while streaming and makes
   `(source_id, source_sequence)` a replay boundary.
2. Export trust is layered: canonical manifest and deterministic package,
   RSA-PSS SHA-256 signature, and optional independently verified RFC 3161
   response. Local keys and local time prove mechanics but are labeled
   self-asserted; only AWS KMS and an approved TSA can establish external trust.
3. AI input is a bounded snapshot with attacker-controlled material isolated as
   untrusted data. Provider output is never an action: it must parse as the
   strict versioned proposal schema and pass deterministic policy, health,
   budget, case-state, and approval gates. Timeout/circuit/budget failure uses a
   deterministic fallback.
4. Scanner adapters are fail-closed. Missing tools, timeouts, archive-limit
   violations, or inconsistent hashes cannot become `CLEAN`. Deployment
   requires explicit `INERT`/`CONTROLLED` approval and a single-use short-lived
   download. Revocation is asynchronous: a deployed artifact is
   `ROLLBACK_PENDING` until the controller journal confirms rollback.
5. Canary classification is calculated from verified callback metadata and
   time-bounded infrastructure-source history before persistence/display.
   Stale internal knowledge becomes `UNKNOWN`, never attacker activity.
6. Analyst directives influence strategy but do not bypass policy. Direct
   messages recheck channel controls and policy immediately before delivery,
   carry `ANALYST_MESSAGE` attribution, and are acquired through the evidence
   pipeline.

**Consequences:** The local MinIO, deterministic fake provider, local RSA key,
local time, and non-Windows controller surface give high-confidence integration
coverage without impersonating AWS, a live model provider, a trusted TSA, or a
Windows lab. Those boundaries remain explicit in configuration, APIs,
runbooks, tests, and control records.

---

## ADR-0026: Terraform compute module — one EC2 instance per topology role, KMS key policies scoped past the AWS-default root-only grant

**Status:** Accepted

**Context:** Engineering-remediation Priority 6 (F-04) found `infra/terraform/modules/`
had VPC/IAM/evidence/log/canary modules (Step 2's actual Prompt-1 scope per
`IMPLEMENTATION_STATUS.md`) but no `aws_instance` resource anywhere — the
five topology roles (broker, control, endpoint, sandbox, attacker; spec §5)
had subnets and security groups reserving their place, but nothing to put in
them. The evidence module's `aws_kms_key.signing`/`aws_kms_key.evidence_encryption`
also had no explicit `policy` argument, meaning both relied entirely on the
AWS-default key policy (every IAM principal in the account with a
sufficiently permissive identity policy can use the key — not the
least-privilege posture the rest of this codebase holds itself to, e.g.
ADR-0011's per-service IAM policy documents).

**Decision:**
1. New `infra/terraform/modules/compute` declares exactly one `aws_instance`
   per role, wired 1:1 to the vpc module's existing subnet/security-group
   outputs (`broker` maps to the vpc module's `public_edge` subnet — the one
   subnet actually named that in spec §5 terms). Only `broker` gets
   `associate_public_ip_address = true`; only `control` gets an
   `iam_instance_profile` (the single control-node role from ADR-0011).
   Every instance: encrypted root volume, IMDSv2-only (`http_tokens =
   "required"`, one-hop), and a `Role` tag. AMI IDs default to the project's
   established `"LAB_VERIFICATION_REQUIRED"`-shaped placeholder convention
   (matching `environments/*/variables.tf`'s `canary_*` vars) so
   `terraform validate`/`fmt` stay real and fully offline; a real `apply`
   must override every one with an actual region-specific AMI (Ubuntu for
   broker/control, Step 9a's golden Windows AMI for endpoint/sandbox, a Kali
   AMI for attacker). Gated behind `var.enable_compute` (default `false`,
   same pattern as `enable_canary`) since most dev work uses the local
   Docker Compose stack, not real EC2.
2. `infra/terraform/modules/evidence`'s two KMS keys gain an explicit
   `policy`: a mandatory account-root statement (omitting it makes a key
   unmanageable — AWS's own constraint, not a choice made here) plus a
   `dynamic "statement"` that only materializes when the caller supplies
   `signing_key_authorized_principal_arns` / `encryption_key_authorized_principal_arns`,
   scoped to exactly the actions a signer/decrypter needs
   (`kms:Sign`/`kms:GetPublicKey`/`kms:DescribeKey`, or
   `kms:Decrypt`/`kms:GenerateDataKey`/`kms:DescribeKey`) — never `kms:*` for
   an arbitrary principal. `environments/{dev,acceptance}/main.tf` pass in
   the single control-node role's ARN, computed as a plain string
   (`arn:aws:iam::${var.aws_account_id}:role/mirage-${var.environment}-control-node`)
   rather than a `module.iam.*` attribute reference — `module.iam` already
   takes these two key ARNs as *input*, so referencing `module.iam` back
   from `module.evidence` would be a circular module dependency.

**Why:** Same static-verification posture ADR-0012 already established:
`terraform fmt -check`/`terraform validate`/`tfsec` run for real and
offline; `tests/unit/test_terraform_compute_policy.py` (30 tests) and
`tests/unit/test_terraform_evidence_kms_policy.py` (13 tests) parse the raw
HCL (and, for the two KMS policy documents, bounded text windows around each
named statement) to assert the exact invariants above, directly against
source — no AWS account, no live plan, fully deterministic. `terraform
plan`/`apply` against a real account remain `AWS_VERIFICATION_REQUIRED`
(unchanged from ADR-0012's own scope boundary).

**Consequence:** A real `apply` still needs real AMI IDs and a real AWS
account before any of this compute topology or KMS scoping takes effect —
tracked as `AWS_VERIFICATION_REQUIRED` in `KNOWN_ISSUES.md`, not silently
assumed. The Terraform-declared least-privilege KMS scoping is real
either way: it constrains what a *future* `apply` will actually set up,
the same "real code, lab-gated execution" split this codebase already uses
for Packer (ADR-0021) and the RDP steering scaffold.
