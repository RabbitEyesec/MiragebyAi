# Fresh Repository Readiness Report

Date: 2026-07-28
Working tree: `/Users/<developer>/Documents/Miragebyai`
Fresh commit: a single commit on `main` (SHA reported at hand-off; a file cannot
contain the hash of the commit that adds it).

---

## 1. Backup status

| Item | Location | Status |
| --- | --- | --- |
| Full repository backup (incl. old `.git`) | `../Miragebyai-backup-before-clean-reset` | Present, 422 MB |
| Last CI run — full log | `../mirage-last-ci-full.log` | 11,792 lines |
| Last CI run — failures only | `../mirage-last-ci-failures.log` | 815 lines |
| Pre-reset `git status` | `../mirage-pre-reset-status.txt` | Empty (tree was clean) |
| Pre-reset working-tree diff | `../mirage-pre-reset-working-tree.patch` | Empty (tree was clean) |
| Pre-reset staged diff | `../mirage-pre-reset-staged.patch` | Empty (tree was clean) |
| Pre-reset history | `../mirage-pre-reset-history.txt` | 3 commits recorded |

Taken **before** any destructive step.

## 2. Deleted GitHub repository confirmation

**NOT DONE — BLOCKED.**

`gh repo delete RabbitEyesec/MiragebyAi --yes` returns:

```
HTTP 403: Must have admin rights to Repository.
This API operation needs the "delete_repo" scope.
```

The authenticated token carries `gist, read:org, repo` only. Granting
`delete_repo` requires an interactive browser flow that cannot be performed
non-interactively:

```
gh auth refresh -h github.com -s delete_repo
```

`gh repo view RabbitEyesec/MiragebyAi` still returns `{"visibility":"PUBLIC"}`.
The old repository and its history are still live.

## 3. Local old Git history removal

Removed. `rm -rf .git` executed only after the backup was confirmed to contain
`.git`. A fresh repository was then initialised — `git log` now shows exactly
one commit with no ancestry from the old history.

## 4. Local artefacts removed

Working tree went from **423 MB to 5.1 MB** before dependencies were
reinstalled.

Removed: `.venv/`, all `node_modules/`, `.next/`, every `__pycache__/`, `*.pyc`,
`.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`, `mirage.egg-info/`, `build/`,
`dist/`, `htmlcov/`, `coverage.xml`, `test-results/`, `playwright-report/`,
`.next-e2e-fixture/`, `*.tsbuildinfo`, `tests/acceptance/reports/`,
`infra/compose/.data/`, `infra/step-ca/{data,secrets,dev-provisioner-keys}/`,
`.broker-keys/`, `.dev-auth-keys/`, `.dev-sandbox-keys/`, `.env`,
`config/{development,acceptance,production}.yaml`, `.DS_Store`, and `.claude/`.

`.claude/` held only `settings.local.json` — local permission state containing
machine-specific absolute paths, no shared project instructions. It was removed
twice: once during cleanup, and again immediately before staging, because this
session recreated it. `.gitignore` now ignores `.claude/` entirely.

Phase 7 verification command output: **no paths**.

Dependencies were then reinstalled (`.venv`, `contracts/typescript/node_modules`,
`dashboard/node_modules`) and the test suites regenerate `__pycache__` and
`.next/cache`. These are gitignored and **not tracked** — confirmed by
`git ls-files` and by extracting the release archive (below). Physical absence
of build caches and running the full test suite are mutually exclusive; the
guarantee delivered is that none of it is tracked or publishable.

## 5. Credentials rotated

Full detail in `CREDENTIAL_ROTATION_REPORT.md`. Summary:

- **No real credential was ever committed.** Both scanners over the old
  three-commit history found only the synthetic `AKIA…` fixture string and
  prose references to it.
- The genuine exposure was structural: `scripts/bootstrap-development` copied
  the public `.env.example` verbatim, so every clone used the same published
  literals (`mirage_dev_local_only` and friends).
- New `scripts/rotate-dev-credentials` generates all 9 secret-bearing variables
  with `secrets.token_urlsafe(32)` per machine into a `0600` `.env`, and
  discards on-disk key material so it is re-minted. `bootstrap-development` now
  calls it instead of copying, and `--check` warns on an existing stale `.env`.
- Verified: `--check` exits 0 on a rotated file and exits 1 naming the variable
  when a published literal is planted back in.
- AWS credentials, AI provider keys and a Keycloak client secret: **NOT_PRESENT**
  (the dashboard is a public PKCE OIDC client — `publicClient: true` — so no
  client secret exists).

## 6. CI `release-package` — root cause and fix

**Two** defects, the second only reachable once the first was fixed.

**(a) Privileged-port preflight check.** `_internal_check("ports")` proved
availability by `bind()`ing each required port. The default is 443, and CI runs
unprivileged, so Linux returned `EACCES` — reported as
`PermissionError: [Errno 13] Permission denied` and indistinguishable from a
real collision. macOS never showed it because Docker Desktop already holds 443
locally (a different error) and the runner's container defaults let root bind
anyway.

*Fix:* `_probe_port_available()` still binds first and still treats `EADDRINUSE`
as fatal, but on `EACCES` falls back to a connect probe — which detects a live
listener without privilege. Verification is not weakened; the check simply no
longer conflates "not root" with "port taken".

*Verified* on `linux/amd64`, uid 1001, `net.ipv4.ip_unprivileged_port_start=1024`:
old code reproduces the exact CI error; new code returns
`443 (connect-probe (unprivileged))` and still raises `[Errno 98]` against a
real listener.

**(b) No external trust anchor for clean-install validation.** With the port
check fixed, preflight advanced to `_verify_release_inventory`, which called
`verify_release(package)` with no key. The trust model deliberately refuses a
package's own embedded key, so it failed closed:
`no external trust anchor configured`.

*Fix:* `ServerInstaller` gained `trusted_public_key` / `trust_store_dir`, exposed
as `--trusted-public-key` / `--trust-store`, and CI now passes the same
**external** `ci-release-public.pem` it verifies with. The verifier still never
trusts an embedded key; it is now simply given the anchor explicitly.

*Verified:* the complete job — `test-installers`, ephemeral keygen,
`build-release`, `verify-release`, `test-clean-install --preflight-only` — run
end to end in an Ubuntu 24.04 `linux/amd64` container as uid 1001 with the
runner's privileged-port sysctl, finishing `"result": "PASS"`, exit 0.

## 7. CI `docker-build-and-boot` — root cause and fix

`infra/step-ca/dev-provisioner-keys` is gitignored, so a fresh CI checkout does
not contain it — but the compose file bind-mounts it. When a bind-mount source
is missing, the **Docker daemon creates it, as root**. The unprivileged
bootstrap that runs next then died with
`PermissionError: … /dev-provisioner-keys/mirage-endpoint.priv.json`.
Docker Desktop hides this by remapping bind-mount ownership to the calling user.

*Fix:*
- `make compose-dirs` pre-creates every bind-mounted host directory and is now a
  prerequisite of `compose-up`, so ordering is deterministic for CI and
  developers alike. (`config/yara` needs no entry — it is tracked.)
- `step_ca_admin` converts a bare `errno 13` into an actionable
  `StepCaAdminError` naming the cause and the fix.
- New `scripts/ci-wait-for-services` replaces the inline health loop. The old
  loop shelled to `docker compose ps` **without `--all`**, so an
  already-crashed service was absent from the listing and the loop reported
  "all services healthy". It now checks the declared service set explicitly and
  fails on unhealthy, exited-non-zero, or missing — while still accepting a
  completed one-shot job (`minio-init`, exit 0).
- Bootstrap is gated on step-ca and Keycloak being reachable first.
- Failure handler dumps `ps --all`, per-container `inspect` for anything not
  healthy, and `logs --no-color` (never `logs -f`).

## 8. CI `integration` — root cause and fix

Previous run: **2 failed, 88 passed, 4 errors**.

**(a) `test_ssh_broker` (2 failed).** `infra/broker/ssh/mirage-route-selector.sh`
was mode **100644** in git. s6-overlay refuses to run a `/custom-cont-init.d`
script that is neither root-owned nor executable, logging only
`is not an executable file` — so the bastion came up as a plain SSH server with
**no ForceCommand**, and the client's `cat /marker` ran on the bastion itself.
That surfaced as `cat: /marker: No such file or directory`, which reads like a
routing bug.

*Verified directly*, both halves: with the script owned by uid 1001 (a real
Linux checkout) mode 644 → `is not an executable file`, ForceCommand count **0**;
at mode 755 → executes, ForceCommand count **1**. Docker Desktop masks it by
presenting bind-mounts as root-owned.

*Fix:* script is now **100755** in git, plus `_assert_force_command_installed`
so a regression names itself instead of masquerading as bad routing.

**(b) `test_http_broker` (2 errors).** The nginx broker was started on the
default bridge and connected to the user-defined network only afterwards. Its
config declares `resolver 127.0.0.11` — Docker's embedded DNS, available only on
a user-defined network — so the `auth_request` subrequest could not resolve and
nginx answered **500**. The readiness loop waited for `(200, 502, 504)`, and
only slept inside its `except` branch, so an unlisted status spun the CPU until
the deadline.

*Fix:* the container joins the network at **creation**; readiness now accepts any
HTTP response (the tests assert the actual routing), always backs off, and dumps
nginx logs on timeout.

**(c) `test_dev_sandbox_target` (2 errors).** `lscr.io` rate-limited the pull:
`toomanyrequests: … allowed: 44000/minute`. The image was also floating on
`:latest`.

*Fix:* pinned to `10.3_p1-r0-ls232` (in tests and both compose files) and
pre-pulled once per session via `pull_image_with_retry`, which retries only rate
limiting and still raises on a genuinely missing image.

Also hardened: `exec_run` exit codes for `/marker` writes were silently
discarded in both broker suites, which is what made (a) so hard to read.

## 9. Files changed

21 files, 2 of them new:

```
 .dockerignore                                | ignore hardening
 .github/workflows/ci.yml                     | release + docker-boot jobs
 .gitignore                                   | ignore hardening
 .gitleaksignore                              | fingerprint removed, markers instead
 CREDENTIAL_ROTATION_REPORT.md                | NEW
 FRESH_REPOSITORY_READINESS_REPORT.md         | NEW (this file)
 ENGINEERING_REMEDIATION_STATUS.md            | invisible gitleaks:allow markers
 GITHUB_READINESS_REPORT.md                   | markers + personal path removed
 REPOSITORY_CLEANUP_REPORT.md                 | invisible gitleaks:allow markers
 Makefile                                     | compose-dirs prerequisite
 docs/runbooks/dashboard-auth.md              | stale compose filename
 infra/broker/ssh/mirage-route-selector.sh    | mode 644 -> 755  (root-cause fix)
 infra/compose/docker-compose.broker.yml      | pinned image tag
 infra/compose/docker-compose.dev-sandbox.yml | pinned image tag
 libs/mirage_common/server_installer.py       | port probe + trust anchor
 libs/mirage_common/step_ca_admin.py          | actionable permission error
 scripts/_lib.py                              | load_env_file() for host scripts
 scripts/bootstrap-development                | generate .env, not copy
 scripts/bootstrap-keycloak-realm             | load .env before resolving defaults
 scripts/ci-wait-for-services                 | NEW
 scripts/rotate-dev-credentials               | NEW
 tests/integration/conftest.py                | pinned image + pull retry
 tests/integration/test_dev_sandbox_target.py | pinned image fixture
 tests/integration/test_http_broker.py        | network-at-create + readiness
 tests/integration/test_ssh_broker.py         | pinned image + ForceCommand assert
```

## 10. Tests passed

| Target | Result |
| --- | --- |
| `make lint` | PASS |
| `make typecheck` | PASS |
| `make test` | PASS — 435 passed |
| `make test-contracts` | PASS — 46 passed |
| `make validate-contracts` | PASS |
| `make scan-secrets` | PASS |
| `make audit-public-repository` | PASS |
| `make test-prompt3-local` | PASS — 71 passed |
| `make test-installers` | PASS — 14 passed |
| `make test-signature-trust` | PASS — 9 passed |
| `make test-release-clean-room` | PASS — 1 passed |
| `make test-dashboard` | PASS |
| `make test-dashboard-e2e` | PASS |
| `make test-integration` | PASS — 94 passed, exit 0 |
| `make docker-build` | PASS — all 8 images |
| `make scan-dependencies` | PASS — no known vulnerabilities |
| `docker compose … config` (development) | PASS |
| `git diff --check` | PASS |
| release-package job on `linux/amd64`, uid 1001 | PASS — `"result": "PASS"` |
| Live compose stack boot (14 services) | PASS — all healthy/running, gate exit 0 |
| `scripts/ci-wait-for-services` positive case | PASS — exit 0 with all 14 healthy |
| `scripts/ci-wait-for-services` negative case | PASS — exit 1, named 4 restarting services **and** `mirage-dashboard: not created` |
| step-ca provisioner key **write** path | PASS — keys written to the bind-mounted directory |
| `bootstrap-keycloak-realm` | PASS — realm, 8 roles, 5 dev users |
| `load_env_file()` picks up rotated `.env` | PASS — resolves rotated value, not the published literal |

### Live stack boot — what it proved, and one caveat

`make compose-dirs` → `compose up` → readiness gate → step-ca + Keycloak
bootstrap → full health gate → `compose down` (never `-v`) was run for real
against 14 of the 15 services. `mirage-dashboard` was excluded because host
port 3001 was already taken by an unrelated process; that exclusion is what
produced the negative test case above.

The health gate initially failed, correctly, with four services crash-looping on
`psycopg.OperationalError: password authentication failed for user "mirage_dev"`,
plus a 401 from Keycloak's admin API. **Not a CI defect** — the Postgres and
Keycloak volumes on this machine dated from 2026-07-24, and both services bake
their credential into the data directory on first initialisation and ignore the
environment on every later boot. A freshly rotated `.env` therefore cannot
authenticate against them. CI creates volumes fresh every run, so it never sees
this. Re-pointing `.env` at the values those volumes were built with brought all
14 services to healthy, confirming the stack itself is sound.

That is a genuine trap for anyone who rotates, so `scripts/rotate-dev-credentials`
now detects the four stateful volumes and prints exactly which credential each
one pins and how to recreate them. Verified: it lists all four when present.

Two smaller findings from the same run, both fixed:
`scripts/bootstrap-keycloak-realm` read `MIRAGE_KEYCLOAK_ADMIN_PASSWORD` from
`os.environ` only and never loaded `.env`, so a rotated password would never
have reached it (`scripts/_lib.py: load_env_file()` now does, with existing
environment variables still taking precedence); and `make test-dashboard-e2e`
rewrites the tracked `dashboard/next-env.d.ts` to point at `.next-e2e-fixture`,
which was reverted rather than committed since it would break a clean build.

## 11. Tests failed

None outstanding.

Transient states resolved during the run, recorded for honesty: five unit tests
(`test_config_schema`, `test_repository_hygiene`) failed while the tree had no
`.git` — they legitimately require a repository — and passed once the fresh
history existed. `make lint` failed once against the first draft of
`scripts/ci-wait-for-services`, which was written in bash inside a `scripts/`
directory ruff parses as Python; it was rewritten in Python (also dropping a
`jq` dependency) and passes.

## 12. Tests not run

| Item | Status | Reason |
| --- | --- | --- |
| Windows endpoint installer (`installers/endpoint/**.ps1`) | NOT_RUN | No Windows host |
| Packer AMI build / AWS provisioning | NOT_RUN | No AWS account |
| Terraform `apply` | NOT_RUN | No AWS account (static tests only, and those pass) |
| `make test-dashboard-auth-e2e` | NOT_RUN | Needs a live bootstrapped Keycloak realm |
| Acceptance Profile B | NOT_RUN | Unchanged — pre-existing scope boundary |

None of these is marked PASS.

## 13. Secret scan results

| Scan | Result |
| --- | --- |
| `gitleaks git .` (fresh history) | **no leaks found** |
| `trufflehog git file://.` | **0 findings** |
| `trufflehog filesystem .` | 0 verified, 0 unverified |
| `gitleaks detect --no-git` (working tree) | 3 hits, all inside gitignored regenerated caches (`.next/cache/.previewinfo`, `__pycache__/*.pyc`) — none tracked |
| Private-key headers | Only detector signatures in `scripts/audit-public-repository` and negative assertions in tests |
| `AKIA` / `ASIA` | Only the documented synthetic fixture; `ASIA` 0 |
| `Authorization: Bearer`, `bootstrap_token`, `enrollment_token` | Prose and parameter names only |
| `/Users/` | `C:/Users/Public/...` (Windows source constant) and redacted prose. The one real personal path in `GITHUB_READINESS_REPORT.md` was genericised to `/Users/<developer>` |
| `/home/` | All `/home/step` — the step-ca container's home |

No verified secrets, no real private key, no real environment file, no personal
absolute path, no generated development credentials.

## 14. Fresh commit SHA

A single commit on `main`,
632 tracked files, clean working tree, authored as
`294341038+RabbitEyesec@users.noreply.github.com`.

## 15. Git archive inspection

`git archive HEAD` → 774 entries / 631 files. Contained **none** of: `.git`,
`.env`, private keys, development key directories, `.venv`, `node_modules`,
`.next`, `.terraform`, build output, test traces, local runtime state, `.claude`,
`__MACOSX`, `.DS_Store`, or personal paths. Extracted and content-scanned to
confirm, then deleted.

## 16. Final status

**NOT_READY — blocked on one external action.**

Everything within this working tree is ready: all three CI jobs are fixed and
verified (two of them reproduced and re-verified on `linux/amd64`), the tree is
clean, credentials are rotated, and both secret scanners are clear on the fresh
history.

The single blocker is Phase 3. The old public repository still exists, and
deleting it needs a scope this token does not have:

```
gh auth refresh -h github.com -s delete_repo
```

Until the old repository is gone, `gh repo create RabbitEyesec/MiragebyAi`
cannot succeed, so **nothing has been pushed**. No code change is pending.
