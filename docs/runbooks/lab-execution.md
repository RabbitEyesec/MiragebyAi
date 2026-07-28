# Profile B lab execution

## Preconditions

Use an isolated AWS account with billing alarms, approved domains/TLS, an
approved Windows base AMI, Windows endpoint and sandbox hosts, Kali source,
Fleet/Elastic sized to Profile B, Object Lock evidence bucket, asymmetric KMS
key, public canary collector, trusted timestamp service, approved scanner
feeds, code-signing certificate, and optional approved AI provider.

Replace every `REPLACE_ME_` value and validate configuration. Build and
Authenticode-sign endpoint and sandbox packages on Windows. Build a signed
server release and verify it offline before installation.

## Exact sequence

```sh
source .venv/bin/activate
./scripts/acceptance-plan plan --profile profile-b > acceptance-plan.json
./scripts/acceptance-provision --profile profile-b --var-file \
  infra/terraform/environments/acceptance/terraform.tfvars \
  --execute --confirm 'PROVISION profile-b'
./scripts/acceptance-install --profile profile-b \
  --server-package dist/mirage-VERSION.zip \
  --config config/acceptance.yaml \
  --endpoint-msi dist/MirageEndpoint.msi \
  --sandbox-msi dist/MirageSandbox.msi \
  --execute --confirm 'INSTALL profile-b'
```

Run the 36-step operator scenario, the 13 failure injections, 31 security
checks, observability alert timing, and the deployed 1,000 events/second
five-minute load with outage. Populate one full result record per numeric
target and retain raw command logs and inventory.

Independently verify the signed package, then:

```sh
./scripts/acceptance-teardown --profile profile-b --region us-east-1 \
  --execute --confirm 'TEARDOWN profile-b'
./scripts/acceptance-provision --profile profile-b \
  --execute --confirm 'PROVISION profile-b'
./scripts/acceptance-repeat --run-command /opt/mirage-lab/profile-b-runner \
  --output acceptance-profile-b \
  --confirm 'REPEAT PROFILE_B TWICE'
```

Stop on evidence/export verification failure, containment breach, invalid
signature, temporary-resource residue, identity reconnect, any numeric
failure, or any `BLOCKED`/`NOT_RUN` row. Do not print an acceptance statement
unless both clean runs satisfy every gate.
