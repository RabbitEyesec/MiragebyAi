# External Dependencies

## Prompt 3 additions

Prompt 3 additionally requires: Node 22.17 and Chromium matching Playwright
1.62 for dashboard browser verification; a clean supported Ubuntu host and
production image-digest catalogue; WiX and PowerShell on clean Windows
endpoint/sandbox hosts; an Authenticode certificate; real Fleet/Elastic and
Kali; OTel/alert delivery; and a controlled operator for fault injection and
twice-run Profile B acceptance.

Local substitutes are explicit: testcontainers PostgreSQL/NATS/Elasticsearch/
MinIO, ephemeral RSA keys, deterministic fake AI, local cloud adapter,
simulated Windows surfaces, and controlled callback classification. None is
evidence for AWS KMS/Object Lock, Authenticode, real Windows behavior, public
DNS, live provider behavior, or Profile B performance.

Everything in Mirage that this development environment (macOS workstation, no
AWS account, no Windows host, Docker available) cannot itself execute. Anything
not listed here that looks like it needs a lab is a bug in this document — file
it in `KNOWN_ISSUES.md`.

## Environment used for Prompt 1

| Tool | Present locally | Used for |
|---|---|---|
| Docker / Docker Compose | Yes (29.2.1 / v5.1.0) | Postgres 16, NATS JetStream, Elasticsearch 8.x, Keycloak, step-ca, Nginx — real local integration tests |
| Terraform | Yes (installed this session, v1.15.8) | `fmt`, `validate` only — no state backend, no credentials |
| Packer | Yes (installed this session, v1.15.4) | `validate`/`fmt` only — no build |
| tfsec | Yes (v1.28.14) | Static Terraform security scan |
| AWS CLI | Yes (v2.36.8) | `scripts/doctor` / `scripts/check-prerequisites` shape checks only — **no credentials configured, no calls made** |
| Python | 3.13.3 (host default); containers/venvs pin 3.12 per ADR-0003 | |
| Node.js | v25.6.1 | Dashboard, TypeScript contract generation |
| WiX Toolset | **Not available** (Windows-only) | MSI compilation — lab only |
| Windows (any) | **Not available** | Everything Windows-service, Sysmon, Elastic Agent, RD Gateway, MSI install/upgrade/rollback |
| AWS account | **Not configured** | VPC apply, AMI build, S3/KMS/Secrets Manager, Fleet Server |
| GitHub remote | **Not configured** (local git only, no commits made per Prompt-1 instructions) | Actually running `.github/workflows/ci.yml` inside a real GitHub Actions runner (Task #17) — every command it invokes is independently verified locally instead, see TEST_RESULTS.md |

## Hard external dependencies (cannot be resolved by more local engineering)

1. **AWS account with billing alarms configured** — required for Step 2
   (`terraform apply`), Step 9a (Packer AMI build), Stage 5+ evidence storage,
   and the full Step 24 acceptance run. Appendix L's cost-control checklist
   (billing alarms at $20/$50/$80, `Project=mirage` tagging, Profile A for dev)
   must be done by a human with account access before any `terraform apply`.
2. **A Windows Server 2022 host (or EC2 instance) with the WiX Toolset v5 and a
   code-signing certificate** — required to compile and sign the three MSIs
   (Step 4, Step 5, Step 21 hardening) and to run install/upgrade/rollback/uninstall
   tests for MirageEndpoint, MirageSpider, MirageEnvironmentController.
3. **A Windows Server host with the RD Gateway role installable** — required for
   Step 8d. RD Gateway has no Linux/container equivalent; it cannot be
   approximated locally the way the HTTP/SSH stand-in target can (ADR-0004).
4. **An approved Windows base AMI** — Step 9a's Packer pipeline starts from "approved
   base AMI"; sourcing/approving that base image is an AWS/organizational step
   outside this repository's control.
5. **Fleet Server + a real Elastic deployment sized per Appendix L Profile B** —
   used for the numeric Definition-of-Done measurements (p95 latencies, 1,000
   events/s burst). Local Docker Elasticsearch proves correctness of mappings
   and ingestion logic, not Profile B performance.
6. **A canary callback domain with public DNS + TLS** — Stage 7's serverless
   collector (API Gateway + Lambda) is implemented but needs a real domain,
   certificate, AWS account, and external client for acceptance.
7. **A code-signing certificate for installer signing** — referenced by
   `mirage/<environment>/installer-signing` in the Secrets Manager catalogue;
   procurement is an organizational/PKI step.
8. **AWS S3 with Object Lock and an asymmetric AWS KMS key** — needed to prove
   IAM, exact-version reads, retention enforcement, multipart failure recovery,
   and RSA-PSS signing beyond the locally verified MinIO/local-key mechanics.
9. **An approved RFC 3161 timestamp authority and CA chain** — needed for
   independently trusted export time. Local self-asserted timestamps are not a
   substitute.
10. **An approved live AI provider credential and secret backend** — needed to
    verify real provider behavior, billing, rate limits, and secret rotation.
11. **Production scanner feeds/tooling** — ClamAV signature updates, approved
    YARA rules, and any licensed analyzers must be supplied operationally.

## What is deliberately NOT an external dependency (i.e. built and tested for real here)

- Contract schema validation and codegen (Step 1)
- NATS JetStream stream behaviour, dedup, dead-letter, replay (Step 1b) — real
  `nats:latest` container
- step-ca enrolment flow (Step 3) — real `smallstep/step-ca` container
- PostgreSQL state machine, outbox relay, optimistic locking (Step 6) — real
  `postgres:16` container
- Detection-to-case correlation logic (Step 7) — unit + integration tested
  against the real Postgres/NATS containers
- Routing decision API and its exclusion constraint (Step 8a) — real Postgres
- HTTP broker `/route` integration (Step 8b) — real Nginx container + njs
- SSH bastion selector logic (Step 8c) — real OpenSSH container, tested against
  the Linux stand-in target from ADR-0004
- Environment Controller command validation, journalling, rollback bookkeeping,
  and the fingerprint-comparator engine (Steps 9b, 10) — pure Python, fully
  unit-testable without Windows because the controller's *logic* has no Win32
  dependency (only the eventual service host does, per ADR-0002)
- Evidence ledger, exact-version S3-compatible storage mechanics, deterministic
  export, local RSA-PSS signing, and independent verification — real
  PostgreSQL/MinIO/local cryptography, with AWS/trusted-time edges excluded
- AI snapshot/schema/policy/budget/fallback mechanics — deterministic and
  provider-independent; no live model is needed to verify these controls
- Artifact archive controls and scanner orchestration — real file, ClamAV,
  YARA, and OLE tools in the scanner image with controlled local signatures
- Canary token lifecycle, HMAC validation, and classification logic — pure
  application logic; only the public serverless delivery path is external

Every requirement row in `REQUIREMENTS_TRACEABILITY.md` states explicitly
whether it is locally verified or lab-dependent, and if lab-dependent, points at
the exact checklist item in `LAB_EXECUTION_CHECKLIST.md`.
