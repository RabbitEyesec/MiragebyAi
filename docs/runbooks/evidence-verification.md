# Evidence verification

Verification reads the exact recorded object version, recomputes SHA-256, and
appends a verification-history row. `MISSING`, `HASH_MISMATCH`, and required
unresolved collection gaps block export.

## Procedure

1. Request verification through `POST /api/v1/evidence/{evidence_id}/verify`
   as an investigator or platform administrator.
2. Inspect the evidence row and verification history through the evidence API.
3. For a case-wide check, request an export; the report worker re-verifies every
   required item immediately before packaging.
4. Run `make test-evidence` after any storage, hashing, or migration change.

## Incident handling

Do not overwrite a failed row or object. Preserve the exact bucket version and
collect S3 access logs, the verification reason, request identity, and failure
timestamp. For `MISSING`, determine whether the version was removed or access
was denied. For `HASH_MISMATCH`, quarantine the export path and investigate
both the ledger and object-store audit trails. Resolve collection gaps only with
an attributed explanation.
