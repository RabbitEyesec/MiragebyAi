# GitHub Readiness Report

Generated: 27 July 2026, on branch `remediation/github-readiness`
(created from `main` at commit `e27cc86`, the repository's only commit).

This report covers **engineering completion and GitHub-push safety**, not AWS
production deployment or Windows lab execution — those remain explicitly
`AWS_VERIFICATION_REQUIRED` / `WINDOWS_VERIFICATION_REQUIRED` as recorded
throughout `KNOWN_ISSUES.md` and are not claimed here.

## 1. Scope of this pass

Nearly all of the engineering-completion work this directive asks for
(event-loss defect, Packer/Fleet identity, controller Windows handlers, auth
hardening, standalone release packaging, RDP scaffold, signature trust,
production Compose, repo/secret hygiene tooling, test-honesty audit) was
**already implemented and documented in a prior session**, recorded as
findings F-01 through F-13 in `ENGINEERING_REMEDIATION_STATUS.md`, sitting
uncommitted in the working tree at session start. This pass did not redo that
engineering work. It:

1. Protected the pre-existing work (safety branch + two backups).
2. Independently re-ran every command those 13 findings cite as evidence,
   from a clean checkout of the working tree — not by re-reading the prior
   session's claims.
3. Ran the repo/secret/history hygiene audit this directive specifically
   requires (gitleaks, trufflehog, custom pattern scans, working-tree and
   history modes).
4. Found and fixed two real bugs surfaced specifically by testing the F-12
   hygiene tooling in the state it will actually run in once committed
   (documented as finding F-14).
5. Produced this report and the accompanying doc updates.

No product feature work was added or changed in this pass beyond the two
F-14 tooling fixes and a contract-regeneration/restaging correction.

## 2. Branch

`remediation/github-readiness` (local only — no remote is configured for
this repository; `git remote -v` returns nothing). Backups taken before any
change: `../mirage-working-tree-backup.patch` (tracked-file diff) and
`../mirage-untracked-backup.tar.gz` (new untracked files, listed in
`../mirage-untracked-paths.txt`).

## 3. Changed-file count

121 changed paths relative to the single existing commit:

- **42 new (untracked) files** — F-01..F-13's new source/tests/docs/scripts,
  plus this session's `.gitleaksignore`.
- **78 modified files** — F-01..F-13's edits to existing source/tests/docs,
  plus this session's two F-14 fixes
  (`scripts/audit-public-repository`, `infra/compose/docker-compose.production.yml`)
  and a contract regeneration (`schemas/events/spider.observation.v1.schema.json`
  and its four generated Python/TypeScript counterparts).
- **1 deleted (tracked) file** — `infra/compose/docker-compose.yml`, superseded
  by `infra/compose/docker-compose.development.yml` (content-identical rename
  per F-06; shows as a plain delete rather than a paired rename in `git
  status` right now because of an intermediate `git add`/`git reset` this
  session did to reproduce the F-14 self-match bug — git will still detect it
  as a rename in the eventual commit's diff, computed from content similarity,
  not from staging history).

## 4. Files removed

None of the working tree's actual product/test/doc content was removed by
this pass. The one deletion above is a rename, not a removal — its content
is fully present at the new path. No `.env`, private key, `node_modules`,
`.next`, `.terraform`, build cache, or release-output path was ever tracked
in this repository (confirmed by content-based and path-based scans below,
not assumed from `.gitignore` intent).

## 5. Secrets scan result — CLEAN

| Check | Result |
|---|---|
| `gitleaks detect` (git history, full) | **Clean** — 0 leaks, after adding `.gitleaksignore` for one pre-existing, documented, non-functional synthetic test fixture (see §6) |
| `gitleaks detect --no-git` (working tree, all files incl. gitignored) | 32 hits, **all** in confirmed-untracked, confirmed-gitignored local runtime paths (`.broker-keys/`, `.dev-auth-keys/`, `.dev-sandbox-keys/`, `infra/step-ca/dev-provisioner-keys/`, `dashboard/.next*` build cache) — none tracked, none committable, none reachable by `git archive`/`build-source-archive` |
| `trufflehog git file://.` | **0 findings** (its stricter verified-credential detector doesn't even flag the synthetic fixture) |
| Custom scanner (`scripts/validate-config --scan-secrets`) | **PASS** — clean |
| `scripts/audit-public-repository` (forbidden tracked paths + private-key content + custom scan + gitleaks, run with F-01..F-13's files staged as they'll actually be committed) | **PASS** — clean, after the F-14 fix |
| Private-key header grep (content-based, all tracked files) | Only match is a unit-test assertion that the string is *absent* (`test_prompt3_installers.py:147`) |
| Absolute local path grep (`/Users/<developer>`) | 0 matches in tracked files |
| Hardcoded password / bearer-token / client-secret grep | 0 matches in tracked files (outside documented, marked, non-functional test fixtures) |
| PEM/key/cert file extensions (`*.pem`, `*.key`, `*.p12`, `*.pfx`) | 0 tracked |

**No verified secret exists in git history or the working tree.** The one
finding gitleaks initially reported (`tests/unit/test_config_schema.py:115`,
rule `aws-access-token`) is a documented, non-functional synthetic fixture —
the literal string `AKIAABCDEFGHIJKLMNOP` <!-- secret-scan: ignore (documentation reference to the known non-functional test fixture, not a live value) gitleaks:allow --> (sequential alphabet, never a
real/activatable AWS key), written to a scratch file that is deleted in the
same test's `finally` block, used to prove the custom scanner itself catches
planted secrets. It is not a credential and never was one. Per this
directive's own instructions for "known synthetic secret-scanner fixtures,"
it is documented inline, isolated to a named test, and now suppressed only
through a narrow, fingerprint-scoped `.gitleaksignore` entry plus an inline
`gitleaks:allow` comment — not a wildcard or path-wide rule. **No history
rewrite was needed or performed**, and none is proposed.

## 6. Two real bugs found and fixed this pass (F-14)

Full detail in `ENGINEERING_REMEDIATION_STATUS.md` F-14. Summary:

1. `scripts/audit-public-repository`'s own private-key content scanner would
   have flagged **itself** permanently once committed (its detection-signature
   list literally contains the PEM header strings it searches for). Fixed by
   excluding the script's own path from that specific check.
2. `gitleaks:allow` inline suppressions do not retroactively clear a finding
   already recorded in an earlier historical commit (empirically verified in
   a disposable sandbox repo) — the prior session's F-12 note assumed
   otherwise. Fixed with a fingerprint-scoped root `.gitleaksignore` entry;
   no history rewrite.

Both were invisible until this pass actually staged F-12's own new files and
ran them in that state — while untracked, `git ls-files`/git-history-driven
logic never touched them.

## 7. Tests passed

19/19 commands run this pass returned PASS (full table in
`TEST_RESULTS.md`'s "GitHub-readiness verification pass" section). Headline
counts, all matching or reproducing F-01..F-13's documented evidence exactly:

- `make lint` / `make typecheck` — clean
- `make test` (unit + contract) — **435/435**
- `make test-integration` (real Postgres/NATS/Elasticsearch/Keycloak/step-ca) — **94/94**
- `make test-dashboard` — **27/27** unit, production build clean
- `make test-dashboard-e2e` (mocked-fixture Playwright) — **4/4**
- `make test-dashboard-auth-e2e` (real local Keycloak, no mocks) — **1/1**
- `make test-agent-delivery` — **26 unit + 6 integration**
- `make test-signature-trust` — **9/9**
- `make test-production-compose` — **10/10**
- `make test-rdp-contract` — **25 unit + 2 integration**
- `make test-release-clean-room` — **1/1**
- `make test-acceptance-local` — **9 integration + 6 package**
- `make test-prompt3-local` — **71/71**
- `make validate-contracts` — PASS (after regenerating + restaging; see note in `TEST_RESULTS.md`)
- `make scan-dependencies` (pip-audit) — no known vulnerabilities
- `terraform fmt -check -recursive` / `terraform validate` (dev + acceptance) — PASS
- `tfsec infra/terraform` — 310 passed, 89 ignored, 3 findings, all confirmed pre-existing and isolated to the untouched `modules/canary/main.tf`
- `git diff --check` — no whitespace errors

## 8. Tests failed

**None.** Every test and check run in this pass passed on the first or
corrected re-run (the two `validate-contracts`/`audit-public-repository`
apparent failures encountered mid-session were self-inflicted by this
session's own diagnostic staging/unstaging, or a real bug that was fixed —
neither reflects a defect in F-01..F-13's product code).

## 9. Tests not run (honestly recorded, not marked PASS)

Unchanged from `KNOWN_ISSUES.md`'s existing `P3-LAB-*` and `AWS_VERIFICATION_REQUIRED`/
`WINDOWS_VERIFICATION_REQUIRED` entries — this pass did not attempt lab
execution and does not change these:

- Windows: WiX/Burn MSI compilation and Authenticode signing; endpoint/sandbox
  install-upgrade-rollback-repair-uninstall lifecycle; real `win32serviceutil`/
  `win32file` Environment Controller calls; RD Gateway COM plugin compilation
  and RDP session steering; Packer `packer build` guest-side provisioning.
- AWS: `terraform apply`/`destroy`; Packer AMI build and KMS AMI signing; real
  S3 Object Lock/KMS/RFC3161; Secrets Manager `get_secret_value` against a
  real secret; public canary DNS/TLS/API Gateway/WAF/Lambda; AWS teardown.
- Profile B: 1,000 events/sec for 5 minutes, 5-minute outage simulation, and
  all other numeric/scenario acceptance rows — all still `NOT_RUN`.
- Hosted GitHub Actions has never executed this working tree in an actual
  runner (no remote exists yet to trigger it against).

## 10. Windows verification remaining

Every Windows-side capability required by this directive has real,
locally-verified, statically-typechecked code behind it (Phase 5's Packer/
Fleet-identity work, Phase 6's real controller handlers, Phase 9's RDP
scaffold) — none is a marker file, sleep, or fabricated success. What
remains is execution on an actual Windows host: see §9. No claim of Windows
execution is made anywhere in the updated docs.

## 11. AWS verification remaining

Same pattern: Terraform/Packer/Secrets-Manager code is real, unit-tested
(including against `botocore.stub.Stubber` for the AWS SDK calls), and
`terraform validate`/`terraform fmt`/`tfsec` all pass statically. Real
`apply`/`build`/live-account execution remains outstanding — see §9.

## 12. Public-repository risk assessment

**Low, with no blocking finding.**

- No verified secret, private key, or credential is tracked or reachable via
  `git archive` (what `scripts/build-source-archive` actually packages).
- No absolute local filesystem path, real personal email address (beyond the
  repo author's own GitHub noreply address, already visible in the existing
  commit), or other obvious PII was found in tracked content.
- This is a defensive-security / deception-platform (honeypot) codebase.
  Nothing scanned suggests offensive tooling, real target infrastructure, or
  operational deception details beyond the architecture itself, which the
  project's own docs already describe as intended for open engineering
  review.
- The repository has never had a remote configured, so nothing has been
  exposed publicly yet regardless of local commit state.

## 13. Recommended commit message

```
git add -A
git commit -m "$(cat <<'EOF'
Complete engineering remediation pass: event delivery, Fleet identity,
controller actions, auth hardening, release packaging, RDP scaffold,
signature trust, and repo/secret hygiene (F-01..F-14)

Implements the 13 findings tracked in ENGINEERING_REMEDIATION_STATUS.md
(F-01..F-13): signature trust anchor enforcement, per-machine dev
credentials, AWS Secrets Manager step-ca provisioner, Terraform compute
module + KMS key policies, Packer golden-image Fleet/Controller identity
and cleanliness gating, split dev/production/test Compose files, RDP
steering project scaffold, real Windows controller action handlers,
Windows-telemetry correlation gap closure, at-least-once agent
event-delivery with idempotent replay, standalone release packaging,
gitleaks/trufflehog-backed repo hygiene tooling, and a systematic
test-honesty audit.

Adds F-14: two bugs found while verifying F-01..F-13 are safe to commit
(a self-referential false positive in the new repo-hygiene audit script,
and a gitleaks history-immutability gap closed via a fingerprint-scoped
.gitleaksignore, no history rewrite).

Windows and AWS live execution remain explicitly out of scope per
KNOWN_ISSUES.md; nothing here claims lab or cloud verification that did
not happen.
EOF
)"
```

(Adjust attribution/co-author trailers to your own convention — none were
added automatically here.)

## 14. Exact push command

No GitHub remote is currently configured. Once you've created the target
repository and decided its visibility:

```
git remote add origin <your-github-repo-url>
git push -u origin remediation/github-readiness
```

Then open a pull request into `main` through GitHub's UI or `gh pr create`,
rather than pushing straight to `main` — this branch has not been merged
locally, and `main` in this local repo still points at the single original
commit.

## 15. Final status

```
READY_TO_COMMIT
```

Every locally-executable validation step in this directive's Phase 11
checklist passed. No secret, credential, or unsafe generated content is
tracked or would be archived. The working tree is safe to commit as-is.

This is **not** `READY_TO_PUSH` yet, for one reason unrelated to code safety:
no GitHub remote/repository has been created or chosen, and pushing to a
**public** repository is a one-way decision this report deliberately leaves
to you (§14) rather than assuming. Once a remote is configured and you've
confirmed the target repo's intended visibility, this branch is ready to
push exactly as-is — no further engineering work gates that step.

Commit and push were **not** performed by this pass, per this directive's
explicit instructions. Awaiting your approval.
