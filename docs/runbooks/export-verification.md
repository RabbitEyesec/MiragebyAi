# Export verification

The report worker creates a deterministic ZIP containing exact evidence
versions, a canonical manifest, an RSA-PSS SHA-256 signature, verification
history, and optional RFC 3161 material.

## Generate and verify

Request `POST /api/v1/cases/{case_id}/exports`. The worker refuses the export
if pre-export verification or eligibility fails. Copy the resulting package and
public key to an isolated verifier, then run:

```text
scripts/verify-evidence-export PACKAGE.zip PUBLIC_KEY.pem
```

The command exits non-zero for duplicate ZIP members, malformed or unexpected
entries, missing evidence, hash disagreement, or signature failure. Preserve
the package unchanged and record the verifier version and command output.

`LOCAL_SELF_ASSERTED` timestamps establish deterministic local ordering only.
Independent time trust requires `MIRAGE_RFC3161_AUTHORITY_URL` and a trusted
`MIRAGE_RFC3161_CA_FILE`. A real RFC 3161 authority and AWS KMS signing are
`LAB_VERIFICATION_REQUIRED`.
