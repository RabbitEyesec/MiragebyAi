# Evidence storage

Mirage stores evidence bytes by exact S3 version and records their SHA-256, version ID, retention, provenance, and verification state in PostgreSQL.

## Configuration and readiness

Set `MIRAGE_EVIDENCE_BUCKET`, `MIRAGE_EVIDENCE_REGION`,
`MIRAGE_EVIDENCE_OBJECT_LOCK_MODE`, and `MIRAGE_EVIDENCE_RETENTION_DAYS`.
Production must omit `MIRAGE_EVIDENCE_ENDPOINT_URL` and use workload identity.
Confirm that the bucket was created with versioning and Object Lock enabled;
these properties cannot be retrofitted safely by the application.

Run `make test-evidence` before rollout. For local development, start the
Compose MinIO service and use the development values in `.env.example`.

## Failure and recovery

- Treat missing version IDs, a disabled versioning response, or a retention API
  failure as acquisition failure. Do not insert an evidence ledger row.
- A retry must preserve `(source_id, source_sequence)` and the original bytes.
  A different hash for the same sequence is a conflict, not a retry.
- Use the evidence verification endpoint after storage incidents. Never replace
  or delete a recorded object version.
- Escalate retention-policy or legal-hold changes to the evidence custodian and
  record the change outside the immutable evidence ledger.

Local MinIO validates the API flow only. AWS S3, AWS Object Lock, IAM, KMS, and
retention enforcement are `LAB_VERIFICATION_REQUIRED`.
