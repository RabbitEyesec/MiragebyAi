# Acceptance runbook

`scripts/acceptance-plan plan --profile PROFILE` prints the immutable 25
numeric targets, 36 live scenario steps, allowed result states, substitutions,
and twice-run rule. `PASS`, `FAIL`, `NOT_RUN`, and `BLOCKED` are the only
states; `NOT_RUN` is never promoted.

Local synthetic:

```sh
source .venv/bin/activate
make test-acceptance-local
./scripts/acceptance-run run --profile local \
  --output tests/acceptance/reports/local-latest
./scripts/acceptance-verify verify \
  tests/acceptance/reports/local-latest/acceptance-package.zip
```

The composite local command uses real PostgreSQL, NATS JetStream,
Elasticsearch, and MinIO through the selected integration scenarios. Windows,
AWS/KMS, public DNS, live AI, and Authenticode are named substitutions.

Profile B requires real AWS, Windows endpoint/sandbox, Kali, Fleet/Elastic,
S3 Object Lock, KMS, public canary infrastructure, configured AI where
enabled, and signed installers. Run the entire scenario twice with teardown and
clean reprovision between. Overall acceptance requires all 25 numeric targets,
all 36 steps, both runs, signed-package verification, and no blocking issue.
