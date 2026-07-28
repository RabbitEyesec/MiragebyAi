# Reporting runbook

A report request is eligible only after the case has a `VERIFIED` canonical
evidence export, unless an authorised policy-backed gap override records every
missing item. The worker loads that exact manifest, renders PDF, DOCX, and JSON,
builds a canonical signed package, independently verifies it, then acquires the
package into the evidence ledger.

Each report statement is one of `OBSERVED_FACT`,
`DETERMINISTIC_CORRELATION`, `AI_INFERENCE`, or `ANALYST_NOTE` and retains
provenance. AI sections retain provider/model/schema/snapshot/uncertainty
metadata. Reports say evidence-ready, never court-admissible.

Use the Reporting workspace to queue, watch progress, cancel, verify, and mint
a two-minute single-use download. Download tokens are stored hashed and a
second use is rejected.

Offline verification:

```sh
./scripts/verify-report-package path/to/report-package.zip
make test-reports
```

Any missing, duplicate, unexpected, modified, signature-invalid, or
evidence-manifest-mismatched member fails verification.
