# step-ca secret loading

## What changed

`SecretsManagerProvisionerSource` (`services/mirage-agent-ingestion/mirage_agent_ingestion/provisioners.py`)
was a documented `NotImplementedError` stub. It now really implements
retrieval of `mirage/<environment>/step-ca` (the schema in
`docs/runbooks/secrets.md` is authoritative and unchanged) from AWS Secrets
Manager, with:

- Typed errors distinguishing IAM/access problems
  (`SecretAccessDeniedError`), a missing secret (`SecretNotFoundError`), and
  a malformed value (`SecretMalformedError` — lists missing field NAMES,
  never values) from a generic transport failure (`SecretRetrievalError`).
- Last-known-good caching: once a secret has been fetched successfully, a
  later transient AWS failure (throttling, a network blip, an IAM policy
  not yet propagated) falls back to the cached value with a logged warning
  instead of failing every enrollment request. The *first* fetch has no
  cache to fall back to, so it always raises on failure — "startup fails
  when a mandatory secret is unavailable" is not relaxed by this.
- `invalidate()` forces a fresh fetch immediately (call after a confirmed
  rotation, rather than waiting out `refresh_interval_seconds`).
- Secret values are never logged — only `secret_name` and AWS error codes
  ever appear in a log line or exception message.

`build_provisioner_source(environment, ...)` is the single place that
decides `DevFileProvisionerSource` vs. `SecretsManagerProvisionerSource`.
Production (`environment == "production"`) without a `secret_name` raises
immediately — it can never silently fall back to the development file
provider.

## What this does NOT prove

Every test in `tests/unit/test_secrets_manager_provisioner.py` uses
`botocore.stub.Stubber` — real boto3 client code, a real (stubbed)
`get_secret_value` call shape, but no network call and no AWS account. This
proves the retrieval/parsing/caching/error-handling logic is correct. It
does not prove:

- A real IAM role can actually reach a real Secrets Manager secret.
- Real AWS error codes/timing match what the stubs simulate exactly.
- Rotation against a real secret version actually completes within
  `refresh_interval_seconds`.

Those remain `AWS_VERIFICATION_REQUIRED` — see `EXTERNAL_DEPENDENCIES.md`.

## Rotation

Follow `docs/runbooks/secrets.md`'s rotation procedure (write a new secret
*version*, never a new name). Call `SecretsManagerProvisionerSource.invalidate()`
(or simply wait `refresh_interval_seconds`, default 300s) after confirming
the new version is live — no service restart or image rebuild required.

## Exact commands

```sh
.venv/bin/pytest tests/unit/test_secrets_manager_provisioner.py -v
```
