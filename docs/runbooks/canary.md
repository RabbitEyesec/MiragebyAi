# Canary callbacks

Canary URLs contain opaque stored-hash tokens. Ingestion verifies the forwarding
HMAC, expiry, revocation, one-time replay rules, and trusted-proxy source before
classification. Internal and scanner sources are never displayed as attacker
activity.

## Operations

Create and revoke tokens through the case artifact API. Rotate
`MIRAGE_CANARY_INGESTION_HMAC` together with the forwarding Lambda. Maintain
time-bounded `infrastructure_sources` records for internal/scanner/proxy CIDRs;
stale records classify as `UNKNOWN`.

For false attacker classification, revoke affected tokens, preserve callback
evidence, inspect the trusted proxy chain and source-record refresh time, and
correct the source inventory before re-enabling. Never accept caller-supplied
classification.

Terraform defines DNS/TLS, API Gateway, WAF, Lambda, DLQ, logs, and IAM, but
public DNS, certificates, Lambda forwarding, API Gateway, WAF behavior, and
external callbacks are `LAB_VERIFICATION_REQUIRED`.
