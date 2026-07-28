# Repository Cleanup Report

Generated: 28 July 2026, on branch `remediation/github-readiness`
(HEAD `e27cc8638abf029552d3993079df9e9c1e89d2ac`, the repository's only commit;
`git remote -v` returns nothing — no remote is configured).

This report supersedes the version of this file produced earlier in the same
remediation effort. That earlier pass deliberately **preserved** `.env`,
`dashboard/.env.local`, `.broker-keys/`, `.dev-auth-keys/`,
`.dev-sandbox-keys/`, and `infra/step-ca/dev-provisioner-keys/` because the
Mirage dev Docker Compose stack was running at the time and deleting
live-in-use key/credential material out from under a running stack was
correctly treated as unsafe. This pass had **explicit operator authorization**
to stop the stack first, so it goes further: the stack was stopped (containers
only — no volumes, no prune), and all of those paths were then physically
deleted, with regeneration commands verified against the actual bootstrap
scripts/runbook. **No product/test/doc source content was deleted, and no
already-modified (`M`) engineering file was touched.**

---

## 0. Safety backups taken before any change

- `../mirage-before-cleanup.patch` — full `git diff` of the working tree at
  session start (5,078 lines).
- `../mirage-before-cleanup-staged.patch` — `git diff --cached` at session
  start (236 lines — the already-staged `git rm --cached` of
  `dashboard/test-results/.last-run.json` and the deletion of
  `infra/compose/docker-compose.yml`, both from prior work on this branch).
- `../mirage-before-cleanup-untracked.txt` — `git ls-files --others
  --exclude-standard` at session start (57 paths, all legitimate new
  engineering work — source, tests, docs, migrations, scaffolding).

None of these backups were needed for restoration (nothing was reverted), but
all three remain in the parent directory for reference.

---

## 1. Suspicious paths found (filesystem discovery)

| Path | Category | On disk at session start? |
|---|---|---|
| `.broker-keys/` (4 files: 2 private SSH keys + 2 `.pub`) | dev credential — bastion SSH keypairs | Yes |
| `.dev-auth-keys/dev-credentials.json` | dev credential — per-machine Keycloak password | Yes |
| `.dev-sandbox-keys/` (SSH keypair) | dev credential — sandbox target SSH keypair | Yes |
| `infra/step-ca/dev-provisioner-keys/` (11 files: 5 encrypted `.priv.json`, 5 `.pub.json`, 1 `root_ca.crt`) | dev credential — step-ca PKI provisioner material | Yes |
| `.env` | local secret env file (real-looking placeholder values only, e.g. `mirage_dev_local_only`) | Yes |
| `dashboard/.env.local` | local secret env file (6 vars, same placeholder convention) | Yes |
| `.venv/` | Python virtualenv (~339 MB) | Yes |
| `dashboard/node_modules/` | npm deps (~491 MB) | Yes |
| `contracts/typescript/node_modules/` | npm deps (~49 MB) | Yes |
| `contracts/typescript/dist/` | tsc build output | Yes |
| `dashboard/.next/` | Next.js build cache (empty `types/` stub, regenerated mid-session by an editor/TS-server process) | Appeared during session |
| `dashboard/tsconfig.tsbuildinfo` | tsc incremental build cache | Yes |
| `mirage.egg-info/` | Python editable-install metadata | Yes |
| `config/development.yaml` | local dev config copy (non-secret placeholders only) | Yes |
| `.claude/settings.local.json` | Claude Code local tool-permission allowlist | Yes |
| `.gitleaksignore` | fingerprint-scoped secret-scanner suppression file (legitimate, not cruft) | Yes (untracked) |
| `__pycache__`, `*.pyc`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.coverage`, `htmlcov`, `.tox`, `.nox` | Python caches | **None found anywhere in the tree** |
| `.next` build output beyond the one above, `test-results/`, `playwright-report/`, `*.trace.zip`, `npm-debug.log*` etc. | Node/dashboard generated data | **None found** |
| `build/`, `dist/` (other than `contracts/typescript/dist`), `target/`, `bin/`, `obj/`, `output/`, `release*`, `*.zip`, `*.msi`, `*.exe` | build/release output | **None found** |
| `.terraform/`, `*.tfstate*`, `*.tfplan`, `crash.log`, `packer_cache/`, `output-*/` | Terraform/Packer local state | **None found** |
| Postgres/ES/NATS/MinIO/step-ca runtime data dirs, Docker volume dirs, logs, PID/socket/lock files | local runtime state | **None found on the filesystem** (Docker-managed named volumes exist — see §5, not host-path clutter) |
| `.DS_Store`, `Thumbs.db`, `*.swp`/`*.swo`/`*~`, `.idea/` | editor/OS state | **None found anywhere in the tree** |

### 1a. Tracked-file safety check

```
git ls-files | grep -E '(^|/)(\.env|\.venv|venv|node_modules|\.next|\.terraform|
  __pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|build|dist|test-results|
  playwright-report|\.broker-keys|\.dev-auth-keys|\.dev-sandbox-keys)(/|$)'
```
**Result: 0 matches**, both before and after this pass. Also checked
separately for tracked `*.key`/`*.pem`/`*.p12`/`*.pfx`/`*.jks`,
`*.tfstate`/`*.tfplan`, `.DS_Store`, `*egg-info*`/`*tsbuildinfo*`, and
`*.zip`/`*.msi`/`*.exe` — **0 matches** for every pattern. Git tracking in
this repository was already clean of generated/sensitive content; no
`git rm`/`git rm --cached` was required by this pass.

One pre-existing drift from **before** this session (staged, not committed,
by prior work on this branch) remains correctly staged: `git rm --cached
dashboard/test-results/.last-run.json` (shown as `D ` in `git status`). This
is why `git archive HEAD` still contains that one file — `git archive` reads
the last real commit, and the removal is staged but not yet committed. No
action was needed from this pass beyond confirming it (see §7).

### 1b. Verified tracked-file count for every ignored path (must be 0)

```
$ for p in .broker-keys .dev-auth-keys .dev-sandbox-keys .venv .env \
  config/development.yaml contracts/typescript/dist contracts/typescript/node_modules \
  dashboard/.env.local dashboard/node_modules dashboard/tsconfig.tsbuildinfo \
  infra/step-ca/dev-provisioner-keys mirage.egg-info .claude; do
    git ls-files "$p" | wc -l
  done
```
All returned **0**. Confirmed via `git ls-files` (authoritative index state),
not inferred from `.gitignore` alone.

---

## 2. Paths physically deleted this pass

Stack was stopped first (§3), then:

```
.broker-keys/                                         (bastion SSH keypairs — regenerate: scripts/bootstrap-broker-keys)
.dev-auth-keys/                                        (Keycloak dev password — regenerate: scripts/bootstrap-keycloak-realm)
.dev-sandbox-keys/                                     (sandbox SSH keypair — regenerate: scripts/bootstrap-dev-sandbox-keys)
infra/step-ca/dev-provisioner-keys/                    (step-ca PKI material — regenerate: scripts/bootstrap-step-ca-provisioners)
.env                                                   (local secrets — regenerate: cp .env.example .env, then scripts/bootstrap-development backfills MIRAGE_STEP_CA_ROOT_FINGERPRINT)
dashboard/.env.local                                   (local secrets — regenerate: cp dashboard/.env.local.example dashboard/.env.local)
mirage.egg-info/                                       (regenerate: make setup / pip install -e ".[dev]")
dashboard/tsconfig.tsbuildinfo                         (regenerate: npx tsc, automatic)
contracts/typescript/dist/                             (regenerate: cd contracts/typescript && npm run build)
dashboard/.next/                                       (regenerate: cd dashboard && npm run build or npm run dev)
.venv/                                                 (~339 MB — regenerate: make setup)
dashboard/node_modules/                                (~491 MB — regenerate: cd dashboard && npm ci)
contracts/typescript/node_modules/                     (~49 MB — regenerate: cd contracts/typescript && npm ci)
```

`config/development.yaml` and `.claude/settings.local.json` were reviewed and
**not** deleted — see §4 for reasoning.

---

## 3. Dev stack shutdown (precondition for §2's key deletions)

Verified running (`docker ps`) before touching any key material: 12 Mirage
containers (`mirage-api`, `mirage-postgres`, `mirage-keycloak`,
`mirage-step-ca`, `mirage-nats`, `mirage-elasticsearch`, `mirage-minio`, etc.),
all `Up 3 hours`.

Command run (operator-specified, scoped to the Mirage compose project only):

```
docker compose --env-file .env -f infra/compose/docker-compose.development.yml down
```

- **No** `-v` (volumes preserved).
- **No** `docker system prune` / `docker volume prune`.
- Verified via `docker ps -a --filter name=mirage` afterward: **0 containers**.
- Verified via `docker volume ls | grep mirage`: all 7 named volumes
  (`mirage-dev_mirage-postgres-data`, `-elastic-data`, `-keycloak-data`,
  `-minio-data`, `-nats-data`, `-stepca-data`, `-artifact-quarantine`)
  **still present** — no data lost.
- Verified unrelated containers (`root-*`, `eye-*` — 15 containers from other
  projects on this machine) **untouched and still running**.
- Stack was **not** restarted after key deletion, per instructions.

---

## 4. Paths preserved and why

| Path | Why preserved |
|---|---|
| `config/development.yaml` | Non-secret local config (placeholder values only, per its own header comment); not in the operator's explicit deletion list; trivially reproducible (`cp config/development.example.yaml config/development.yaml`) if ever needed. Already gitignored — zero push risk either way. |
| `.claude/settings.local.json` | Local Claude Code tool-permission allowlist (~230 previously-approved Bash/Read patterns), no secrets, no `/Users/...` values beyond this machine's own already-known paths. Already gitignored (via this user's personal global `~/.config/git/ignore`, not the repo's `.gitignore` — see §6 for the repo-level rule added as defense-in-depth). Deleting it would only force re-approving ~230 command patterns with zero hygiene or GitHub-safety benefit, since it is unreachable by any `git add`/push regardless. |
| `.gitleaksignore` | Legitimate, narrowly fingerprint-scoped secret-scanner suppression (one exact commit+path+rule+line), not a wildcard. Reviewed in full — see §6. |
| All 74 already-modified (`M`) tracked source/test/doc/infra files | Engineering changes explicitly out of scope for this cleanup. |
| The staged deletions of `dashboard/test-results/.last-run.json` and `infra/compose/docker-compose.yml` | Pre-existing staged work from before this session; left as-is, not committed (per instructions). |
| All 57 untracked (`??`) new-feature-work paths (`ENGINEERING_REMEDIATION_STATUS.md`, `docs/architecture/`, `infra/broker/rdp/`, new tests, migrations, terraform `compute` module, etc.) | Legitimate engineering deliverables, not generated artefacts. Untouched. |
| Docker named volumes (`mirage-dev_*`) | Not filesystem clutter — Docker-managed state for a stack the operator may still want to bring back up with `docker compose ... up -d` (no `-v` was used specifically to preserve this option). |

---

## 5. Files removed from Git tracking

**None required by this pass** — §1a/§1b confirmed 0 tracked matches for every
generated/sensitive-file pattern before this pass began. The one pre-existing
`git rm --cached dashboard/test-results/.last-run.json` was already staged by
prior work on this branch (not committed, per instructions — left as-is).

---

## 6. Ignore rules added this pass

`.gitignore` and `.dockerignore` already had substantial coverage from prior
work on this branch. This pass closed the following specific gaps (each
verified against the current tree — nothing currently tracked or present on
disk matched any of these newly-added patterns before they were added, so
none of these changes could silently exclude real content):

**`.gitignore`:**
- `bin/`, `obj/`, `target/`, `output/` — generic build-output dirs for the
  untracked `infra/broker/rdp` C#/.NET plugin project (`.csproj` files
  present; building it would produce `bin/`/`obj/`, which had no rule yet).
- `coverage/` — generic JS/Node coverage-tool output directory (distinct
  from the Python `.coverage` file/`coverage.xml`, which were already
  covered).
- `!fixtures/**/*.pem` — symmetry with the existing `!fixtures/**/*.key`
  exception, so a future synthetic `.pem` test fixture isn't silently
  excluded by the blanket `*.pem` rule (no such file exists yet; this is
  forward-looking, matching the existing `.key` convention).
- `.claude/settings.local.json` — repo-level rule so this file is protected
  for **every** contributor regardless of their personal global
  `core.excludesFile` (it was previously only ignored via this operator's own
  machine-level git config, not the repo's own `.gitignore`).

**`.dockerignore`:** the same `bin`/`obj`/`target`/`coverage` additions
(with `**/` recursive variants matching the existing style in this file), plus
`.claude/settings.local.json`.

No wildcard/path-wide suppressions were added, and no source directory was
ignored to "silence" Git — every new rule targets a specific generated-file
class. Confirmed only one `.gitignore` exists in the whole tree (`find . -name
.gitignore`) — no nested ignore files to update.

---

## 7. Secret-scan results

| Scanner | Scope | Result |
|---|---|---|
| `gitleaks detect --source . --no-git` | Full working tree, ~3.08 MB scanned (post-cleanup — no more 224 MB of `node_modules`/`.venv`/key material to scan through) | 6 hits, **all** the same known synthetic fixture string `AKIAABCDEFGHIJKLMNOP` <!-- secret-scan: ignore (documentation reference to the known non-functional test fixture, not a live value) gitleaks:allow --> quoted as prose in `.gitleaksignore`, `REPOSITORY_CLEANUP_REPORT.md` (×3), `GITHUB_READINESS_REPORT.md`, `ENGINEERING_REMEDIATION_STATUS.md` — documentation references to a known non-functional test fixture, not a live value |
| `gitleaks git .` (full history) | 1 commit, ~2.76 MB | **0 leaks** (the one historical occurrence of the fixture is already suppressed via the fingerprint-scoped `.gitleaksignore` entry) |
| `trufflehog git file://.` | Full git history, verified-credential detector | **0 verified secrets, 0 unverified secrets** |
| Manual `git grep -I` across tracked files | `-----BEGIN (RSA\|EC)? PRIVATE KEY-----` | 0 matches |
| | `AKIA`, `ASIA` | `AKIA`: 2 files — `scripts/validate-config:52` (the detector's own regex definition) and the known suppressed test fixture in `tests/unit/test_config_schema.py:115`. `ASIA`: 0 matches. |
| | `client_secret` | 3 files — OAuth field-name usage in `dashboard/app/api/auth/callback/route.ts`, `dashboard/lib/session.ts` (both send `config.clientSecret`, a value read from env, never a literal), and a JSON-schema field description in `docs/runbooks/secrets.md`. No literal secret values. |
| | `password=`/`password:` (literal-value pattern, excluding placeholders) | Only `tests/integration/conftest.py` — ephemeral `testcontainers` Postgres credentials (`mirage_test`, `mirage_test_local_only`), ephemeral by construction, not real. |
| | `token=`/`token:`, `bootstrap_token`, `enrollment_token`, `Authorization: Bearer` | Field-name/identifier usage only (Fleet Server enrollment token config, OIDC token exchange code, etc.) — no literal token values embedded. |
| | `/Users/` | 1 match — `PureWindowsPath("C:/Users/Public/Documents/Mirage")` in `services/mirage-api/mirage_api/prompt2.py`, a synthetic Windows decoy-content path constant, not a personal path. |
| | `/home/` | 3 matches — all `/home/step/...` inside `docker exec` calls in `libs/mirage_common/step_ca_admin.py` against the step-ca **container's own** internal filesystem, not a host path. |

### Classification of all findings

- **Verified secret:** none.
- **Generated development secret:** none remaining on disk (the encrypted
  step-ca provisioner `.priv.json` files and SSH/Keycloak dev credentials
  that previously existed under this classification were physically deleted
  in §2).
- **Synthetic test fixture:** `AKIAABCDEFGHIJKLMNOP` <!-- secret-scan: ignore (documentation reference to the known non-functional test fixture, not a live value) gitleaks:allow --> (sequential-alphabet,
  never a real/activatable AWS key shape), used in
  `tests/unit/test_config_schema.py:115` to test the secret scanner itself,
  and referenced in prose in four documentation files. Narrowly suppressed
  via the existing fingerprint-scoped `.gitleaksignore` entry
  (`e27cc8638abf029552d3993079df9e9c1e89d2ac:tests/unit/test_config_schema.py:aws-access-token:115`)
  — exact commit+path+rule+line, not a wildcard.
- **False positive:** the `/Users/`, `/home/`, and `client_secret`
  field-name matches above.
- **Unresolved:** none.

### No real secret found in git history

Confirmed independently by two different tools (gitleaks, trufflehog)
against the repository's full history (1 commit). **No git-filter-repo
remediation plan is needed.**

---

## 8. Remaining ignored paths (post-cleanup)

```
$ git status --short --ignored | grep '^!!'
!! .claude/
!! config/development.yaml
```

Both reviewed and preserved with justification (§4). No key directory, no
`.env`/`.env.local`, no dependency tree, and no build cache remain anywhere
in the ignored list — they no longer exist on disk at all (§9 confirms).

## 9. Final filesystem verification

```
$ find . \( -name "__pycache__" -o -name "*.pyc" -o -name ".pytest_cache" -o \
    -name ".mypy_cache" -o -name ".ruff_cache" -o -name ".next" -o \
    -name "node_modules" -o -name ".terraform" -o -name ".broker-keys" -o \
    -name ".dev-auth-keys" -o -name ".dev-sandbox-keys" -o -name "build" \) -print
(no output)

$ find . \( -name "*.egg-info" -o -name "*.tsbuildinfo" -o -name ".venv" -o \
    -name ".env" -o -name "dev-provisioner-keys" -o -name "test-results" -o \
    -name "playwright-report" -o -name ".DS_Store" \) -not -path "*/node_modules/*" -print
(no output)
```

Both mandated checks returned **no paths** — cleanup is physically confirmed,
not merely claimed.

## 10. Final Git tracking verification

```
$ git ls-files | grep -E '(^|/)(\.env|\.venv|venv|node_modules|\.next|\.terraform|
  __pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|build|dist|test-results|
  playwright-report|\.broker-keys|\.dev-auth-keys|\.dev-sandbox-keys)(/|$)'
(no output — 0 matches)

$ git diff --check
(exit 0 — no whitespace/conflict-marker errors)
```

## 11. GitHub source archive verification

```
$ git archive --format=zip --output=../Mirage-source-verification.zip HEAD
$ unzip -l ../Mirage-source-verification.zip   # 710 files, 2,801,318 bytes uncompressed
```

Scanned the archive listing for every unsafe pattern (`.env`, `.venv/`,
`node_modules/`, `.next/`, `.terraform/`, caches, `.broker-keys/`,
`.dev-auth-keys/`, `.dev-sandbox-keys/`, `dev-provisioner-keys/`, private-key
extensions, `.DS_Store`, `tfstate`, `egg-info`, `tsbuildinfo`):

- **One expected hit:** `dashboard/test-results/.last-run.json` — present
  only because `git archive` exports the last real **commit** (HEAD), and
  its removal is staged (§1a) but not committed. This is not a new tracked
  file introduced by this pass; it will disappear from any future archive as
  soon as the already-staged removal is committed.
- No other unsafe pattern matched.

The verification archive was **deleted after inspection**
(`rm -f ../Mirage-source-verification.zip`), as instructed.

---

## 12. Dependency recreation commands

```
# Python virtualenv + editable install
python3.12 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
# or simply: make setup

# contracts/typescript
cd contracts/typescript && npm ci && npm run build

# dashboard
cd dashboard && npm ci
```

## 13. Development-key regeneration commands

```
# .env / dashboard/.env.local (non-secret placeholder templates)
cp .env.example .env
cp dashboard/.env.local.example dashboard/.env.local

# Full documented bootstrap order (docs/runbooks/bootstrap.md):
cp .env.example .env
cp config/development.example.yaml config/development.yaml   # already present, not deleted
scripts/check-prerequisites
scripts/validate-config config/development.yaml
scripts/bootstrap-development
  # ^ backfills MIRAGE_STEP_CA_ROOT_FINGERPRINT into .env, brings up the
  #   dev Compose stack, runs migrations + NATS stream provisioning

# Individual dev-credential directories (idempotent, safe to re-run):
scripts/bootstrap-step-ca-provisioners   # infra/step-ca/dev-provisioner-keys/
scripts/bootstrap-keycloak-realm         # .dev-auth-keys/dev-credentials.json
scripts/bootstrap-broker-keys            # .broker-keys/
scripts/bootstrap-dev-sandbox-keys       # .dev-sandbox-keys/

# Bring the stack back up (NOT run this session, per instructions):
docker compose --env-file .env -f infra/compose/docker-compose.development.yml up -d
```

All four bootstrap scripts were confirmed to exist in `scripts/` before
deletion (§1). None were re-run this session — the stack was left stopped,
as instructed.

---

## 14. Final status

```
CLEAN_AND_GITHUB_SAFE
```

**Basis for this determination:**
- No verified secret, private key, or credential exists in tracked content,
  untracked working-tree content, or git history (2 independent scanners +
  manual pattern review across every category the task specified, all
  clean).
- No generated dependency directory, build cache, dev-credential directory,
  or local `.env` file remains anywhere on the filesystem — confirmed by
  direct `find`/`git ls-files` checks (§9, §10), not assumed from
  `.gitignore` intent.
- No unsafe path is or was ever Git-tracked in this repository's one commit.
- Ignore rules now cover every category the task specified, including two
  gaps this pass identified and closed (`bin/`/`obj/`/`target/`/`output/`,
  `coverage/`, and a repo-level `.claude/settings.local.json` rule that
  previously relied only on this operator's personal global git config).
- The GitHub source archive (`git archive HEAD`) contains only legitimate
  repository content, plus the one already-staged-for-removal file that
  will drop out on the next commit.
- The Mirage dev Compose stack was stopped cleanly (containers only, no
  volumes, no prune) before any key material was deleted, per explicit
  operator instruction; all 7 named Docker volumes and all unrelated
  containers on this machine were verified untouched.
- Every deleted local artefact has a documented, verified-to-exist
  regeneration command (§12, §13).
- All 74 already-modified (`M`) engineering files and all 57 legitimate
  untracked new-feature-work paths remain completely untouched.

No commit was created. No push was performed. No git history was rewritten.
The dev stack was **not** restarted. Awaiting human review.
